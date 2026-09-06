#![cfg(target_arch = "x86_64")]

use vmp_vm::bytecode::{Condition, Width};
use vmp_vm::bytecode_v2::{decode, encode, Instruction, Program};
use vmp_vm::host_v2::{Machine, Termination};
use vmp_vm::stack_v2::Instruction as Stack;

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
