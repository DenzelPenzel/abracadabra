#![cfg(target_arch = "x86_64")]

use vmp_vm::bytecode::{Condition, Width};
use vmp_vm::bytecode_v2::{decode, encode, Instruction, Program};
use vmp_vm::host_v2::{Machine, Termination};
use vmp_vm::stack_v2::Instruction as Stack;

#[test]
fn add_all_widths_match_physical_cpu_arithmetic_flags() {
    use vmp_vm::bytecode::Register;
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        let mask = u64::MAX >> (64 - width as u32 * 8);
        let sign = (mask >> 1) + 1;
        let values = [0, 1, 2, 15, 16, 0x55, 0xaa, sign - 1, sign, mask];
        for lhs in values {
            for rhs in values {
                let (result, flags) = native_add(width, lhs, rhs);
                let p = Program::new(
                    0,
                    vec![
                        Instruction::Stack(Stack::PushImm { width, value: lhs }),
                        Instruction::Stack(Stack::PushImm { width, value: rhs }),
                        Instruction::Add { width },
                        Instruction::Stack(Stack::PopFlags),
                        Instruction::Stack(Stack::PopReg {
                            width,
                            register: Register::Rax,
                        }),
                        Instruction::Ret,
                    ],
                )
                .expect("program");
                let p = decode(&encode(&p).expect("encode")).expect("decode");
                for initial in [0, u64::MAX, !flags] {
                    let mut m = Machine::new(16);
                    m.set_flags_bits(initial);
                    assert_eq!(m.execute(&p, 6), Ok(Termination::Ret));
                    assert_eq!(
                        m.register(Register::Rax),
                        result & mask,
                        "{width:?} {lhs:#x}+{rhs:#x}"
                    );
                    assert_eq!(
                        m.flags_bits() & 0x8d5,
                        flags & 0x8d5,
                        "{width:?} {lhs:#x}+{rhs:#x}"
                    );
                    // Outside arithmetic bits this is logical transport policy, not CPU parity
                    assert_eq!(m.flags_bits() & !0x8d5, initial & !0x8d5);
                }
            }
        }
    }
}

#[allow(unsafe_code, reason = "isolated x86-64 ADD oracle")]
fn native_add(width: Width, lhs: u64, rhs: u64) -> (u64, u64) {
    let mut result = lhs;
    let flags: u64;
    macro_rules! run {
        ($op:literal) => {
            // SAFETY: Register-only ADD and balanced PUSHF/POP preserve control state
            // Early output prevents the flags register from aliasing live inputs
            unsafe { core::arch::asm!(
                "pushfq", $op, "pushfq", "pop {flags}", "popfq",
                inout("rax") result, in("rcx") rhs, flags = out(reg) flags,
            ); }
        };
    }
    match width {
        Width::Byte => run!("add al, cl"),
        Width::Word => run!("add ax, cx"),
        Width::Dword => run!("add eax, ecx"),
        Width::Qword => run!("add rax, rcx"),
    }
    (result, flags)
}

#[test]
fn shl_all_widths_and_raw_counts_match_physical_cpu_defined_flags() {
    use vmp_vm::bytecode::Register;
    const ARITHMETIC_BITS: u64 = 0x8d5;
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        let bits = width as u32 * 8;
        let mask = u64::MAX >> (64 - bits);
        let sign = (mask >> 1) + 1;
        let values = [
            0,
            1,
            2,
            15,
            16,
            0x55,
            0xaa,
            sign - 1,
            sign,
            sign + 1,
            mask - 1,
            mask,
        ];
        for raw_count in 0u16..=255 {
            let count = u32::from(raw_count) & if width == Width::Qword { 63 } else { 31 };
            let compared = if count == 0 {
                ARITHMETIC_BITS
            } else {
                0xc4 | if count < bits { 1 } else { 0 } | if count == 1 { 0x800 } else { 0 }
            };
            for value in values {
                let program = Program::new(
                    0,
                    vec![
                        Instruction::Stack(Stack::PushImm {
                            width: Width::Word,
                            value: 0xa500 | u64::from(raw_count),
                        }),
                        Instruction::Stack(Stack::PushImm { width, value }),
                        Instruction::Shl { width },
                        Instruction::Stack(Stack::PopFlags),
                        Instruction::Stack(Stack::PopReg {
                            width,
                            register: Register::Rax,
                        }),
                        Instruction::Ret,
                    ],
                )
                .expect("SHL program");
                let decoded = decode(&encode(&program).expect("encode SHL")).expect("decode SHL");
                for initial in [0, u64::MAX, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210] {
                    let (result, flags) = native_shl(width, value, raw_count as u8, initial);
                    let mut machine = Machine::new(16);
                    machine.set_flags_bits(initial);
                    assert_eq!(machine.execute(&decoded, 6), Ok(Termination::Ret));
                    assert_eq!(
                        machine.register(Register::Rax),
                        result & mask,
                        "{width:?} value={value:#x} raw_count={raw_count} initial={initial:#x}"
                    );
                    assert_eq!(
                        machine.flags_bits() & compared,
                        flags & compared,
                        "{width:?} value={value:#x} raw_count={raw_count} initial={initial:#x}"
                    );
                    // Undefined and nonarithmetic bits follow logical policy, not CPU parity
                    assert_eq!(
                        machine.flags_bits() & !compared, initial & !compared,
                        "preservation: {width:?} value={value:#x} raw_count={raw_count} initial={initial:#x}"
                    );
                    assert_eq!(machine.stack_bytes().len(), 0);
                }
            }
        }
    }
}

#[allow(unsafe_code, reason = "isolated x86-64 SHL oracle")]
fn native_shl(width: Width, value: u64, count: u8, initial: u64) -> (u64, u64) {
    let mut result = value;
    let flags: u64;
    macro_rules! run {
        ($op:literal) => {
            // SAFETY: Only six arithmetic bits are seeded, preserving all control bits
            // PUSH/POP pairs are balanced and original flags are restored before exit
            // Early outputs cannot alias live inputs, and nothing clobbers seeded flags
            // between POPFQ and SHL; no memory is accessed except the balanced stack
            unsafe { core::arch::asm!(
                "pushfq",
                "pop {saved}",
                "mov {seed}, {saved}",
                "and {seed}, {clear}",
                "or {seed}, {initial}",
                "push {seed}",
                "popfq",
                $op,
                "pushfq",
                "pop {flags}",
                "push {saved}",
                "popfq",
                saved = out(reg) _,
                seed = out(reg) _,
                flags = out(reg) flags,
                clear = in(reg) !0x8d5u64,
                initial = in(reg) (initial & 0x8d5),
                inout("rax") result,
                in("cl") count,
            ); }
        };
    }
    match width {
        Width::Byte => run!("shl al, cl"),
        Width::Word => run!("shl ax, cl"),
        Width::Dword => run!("shl eax, cl"),
        Width::Qword => run!("shl rax, cl"),
    }
    (result, flags)
}

const CONDITION_BITS: u64 = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11);

#[test]
fn all_raw_flag_conditions_match_physical_setcc() {
    let conditions = [
        Condition::O,
        Condition::No,
        Condition::B,
        Condition::Ae,
        Condition::E,
        Condition::Ne,
        Condition::Be,
        Condition::A,
        Condition::S,
        Condition::Ns,
        Condition::P,
        Condition::Np,
        Condition::L,
        Condition::Ge,
        Condition::Le,
        Condition::G,
    ];
    for assignment in 0..32 {
        let mut flags = 0;
        for (index, bit) in [0, 2, 6, 7, 11].into_iter().enumerate() {
            if assignment & (1 << index) != 0 {
                flags |= 1 << bit;
            }
        }
        let actual = native_conditions(flags);
        for (condition, taken) in conditions.into_iter().zip(actual) {
            assert!(taken <= 1);
            let program = Program::new(
                0,
                vec![
                    Instruction::Jcc {
                        condition,
                        target: 7,
                    },
                    Instruction::Ret,
                    Instruction::Ret,
                ],
            )
            .expect("valid branches");
            let decoded = decode(&encode(&program).expect("encode")).expect("decode");
            for noise in [0, !CONDITION_BITS] {
                let mut machine = Machine::new(0);
                machine.set_flags_bits(flags | noise);
                assert_eq!(machine.execute(&decoded, 2), Ok(Termination::Ret));
                assert_eq!(
                    machine.pc(),
                    if taken == 1 { 7 } else { 6 },
                    "condition={condition:?}, assignment={assignment}, noise={noise:#x}"
                );
                assert_eq!(machine.flags_bits(), flags | noise);

                let apply = Program::new(
                    0,
                    vec![
                        Instruction::Stack(Stack::PushImm {
                            width: Width::Qword,
                            value: flags | noise,
                        }),
                        Instruction::Stack(Stack::PopFlags),
                        Instruction::Jcc {
                            condition,
                            target: 18,
                        },
                        Instruction::Ret,
                        Instruction::Ret,
                    ],
                )
                .expect("flags then branch");
                let decoded = decode(&encode(&apply).expect("encode apply")).expect("decode apply");
                let mut applied = Machine::new(8);
                applied.set_flags_bits(!(flags | noise));
                assert_eq!(applied.execute(&decoded, 4), Ok(Termination::Ret));
                assert_eq!(applied.pc(), if taken == 1 { 18 } else { 17 });
                assert_eq!(applied.flags_bits(), flags | noise);
                assert_eq!(applied.stack_bytes().len(), 0);
            }
        }
    }
}

#[allow(unsafe_code, reason = "isolated x86-64 condition oracle")]
fn native_conditions(flags: u64) -> [u8; 16] {
    let mut result = [0; 16];
    // SAFETY: Only arithmetic condition bits are changed; control bits remain intact
    // The output pointer covers all sixteen stores and stack pushes are balanced
    // Original flags are restored and both scratch registers are declared early outputs
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {saved}",
            "mov {seed}, {saved}",
            "and {seed}, {clear}",
            "or {seed}, {flags}",
            "push {seed}",
            "popfq",
            "seto byte ptr [{output}]",
            "setno byte ptr [{output} + 1]",
            "setb byte ptr [{output} + 2]",
            "setae byte ptr [{output} + 3]",
            "sete byte ptr [{output} + 4]",
            "setne byte ptr [{output} + 5]",
            "setbe byte ptr [{output} + 6]",
            "seta byte ptr [{output} + 7]",
            "sets byte ptr [{output} + 8]",
            "setns byte ptr [{output} + 9]",
            "setp byte ptr [{output} + 10]",
            "setnp byte ptr [{output} + 11]",
            "setl byte ptr [{output} + 12]",
            "setge byte ptr [{output} + 13]",
            "setle byte ptr [{output} + 14]",
            "setg byte ptr [{output} + 15]",
            "push {saved}",
            "popfq",
            saved = out(reg) _,
            seed = out(reg) _,
            clear = in(reg) !CONDITION_BITS,
            flags = in(reg) (flags & CONDITION_BITS),
            output = in(reg) result.as_mut_ptr(),
        );
    }
    result
}
