#![cfg(target_arch = "x86_64")]

use vmp_vm::operand::{Register, Width};
use vmp_vm::stack::{Instruction, Machine, Output};

fn push(machine: &mut Machine, width: Width, value: u64) {
    machine
        .step(Instruction::PushImm { width, value })
        .expect("push");
}

fn result(machine: &mut Machine, width: Width) -> (u64, u64) {
    let Output::FlagsWord(flags) = machine.step(Instruction::PopFlags).expect("flags") else {
        panic!("expected flags word");
    };
    machine
        .step(Instruction::PopReg {
            width,
            register: Register::Rax,
        })
        .expect("result");
    assert_eq!(machine.stack_bytes().len(), 0);
    (machine.register(Register::Rax), flags)
}

#[test]
fn add_all_widths_match_native_arithmetic_flags() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        let mask = u64::MAX >> (64 - width as u32 * 8);
        let sign = (mask >> 1) + 1;
        let values = [0, 1, 2, 15, 16, 0x55, 0xaa, sign - 1, sign, mask];
        for lhs in values {
            for rhs in values {
                let (expected, flags) = native_add(width, lhs, rhs);
                for initial in [0, u64::MAX, !flags] {
                    let mut machine = Machine::new(16);
                    push(&mut machine, width, lhs);
                    push(&mut machine, width, rhs);
                    machine.add(width, initial).expect("ADD");
                    let (value, actual) = result(&mut machine, width);
                    assert_eq!(value, expected & mask);
                    assert_eq!(actual & 0x8d5, flags & 0x8d5);
                    assert_eq!(actual & !0x8d5, initial & !0x8d5);
                }
            }
        }
    }
}

#[test]
fn shl_all_widths_and_counts_match_native_defined_flags() {
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
                0x8d5
            } else {
                0xc4 | if count < bits { 1 } else { 0 } | if count == 1 { 0x800 } else { 0 }
            };
            for value in values {
                for initial in [0, u64::MAX, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210] {
                    let (expected, flags) = native_shl(width, value, raw_count as u8, initial);
                    let mut machine = Machine::new(16);
                    push(&mut machine, Width::Word, 0xa500 | u64::from(raw_count));
                    push(&mut machine, width, value);
                    machine.shl(width, initial).expect("SHL");
                    let (actual, actual_flags) = result(&mut machine, width);
                    assert_eq!(actual, expected & mask);
                    assert_eq!(actual_flags & compared, flags & compared);
                    assert_eq!(actual_flags & !compared, initial & !compared);
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
