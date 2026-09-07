//! Production stack transport against source-derived C++ byte-layout pins

use vmp_vm::operand::{Register, Width};
use vmp_vm::stack::{Instruction, Machine, Output, StackError};

#[test]
fn shl_count_classes_padding_and_atomic_bounds() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        let bits = width as u32 * 8;
        let storage = (width as usize).max(2);
        for (count, value, result, changed, flags) in [
            (0, 0x81, 0x81u64, 0, 0),
            (1, 1, 2, 0x8c5, 0),
            (2, 1, 4, 0xc5, 0),
            (
                bits,
                1,
                if bits < 32 { 0 } else { 1 },
                if bits < 32 { 0xc4 } else { 0 },
                0x44,
            ),
            (
                255,
                1,
                if bits >= 32 { 1 << (bits - 1) } else { 0 },
                if bits < 32 { 0xc4 } else { 0xc5 },
                if bits >= 32 { 0x84 } else { 0x44 },
            ),
        ] {
            for initial in [0, u64::MAX] {
                let mut m = Machine::new(storage + 10);
                push(&mut m, Width::Word, 0xabcd);
                push(&mut m, Width::Word, 0xa500 | u64::from(count));
                push(&mut m, width, value);
                m.shl(width, initial).expect("shift");
                let raw = m.stack_bytes().collect::<Vec<_>>();
                let expected = (initial & !changed) | (flags & changed);
                assert_eq!(&raw[..8], expected.to_le_bytes(), "{width:?} count={count}");
                assert_eq!(&raw[8..8 + storage], &result.to_le_bytes()[..storage]);
                assert_eq!(&raw[8 + storage..], [0xcd, 0xab]);
            }
        }
        let mut m = Machine::new(storage + 9);
        push(&mut m, Width::Word, 0xabcd);
        push(&mut m, Width::Word, 0);
        push(&mut m, width, 1);
        let before = m.stack_bytes().collect::<Vec<_>>();
        assert_eq!(
            m.shl(width, 0),
            Err(StackError::Budget {
                required: storage + 10,
                limit: storage + 9
            })
        );
        assert_eq!(m.stack_bytes().collect::<Vec<_>>(), before);
        let mut short = Machine::new(32);
        push(&mut short, width, 1);
        let before = short.stack_bytes().collect::<Vec<_>>();
        assert_eq!(
            short.shl(width, 0),
            Err(StackError::Underflow {
                needed: storage + 2,
                available: storage
            })
        );
        assert_eq!(short.stack_bytes().collect::<Vec<_>>(), before);
    }
    let mut m = Machine::new(10);
    push(&mut m, Width::Dword, 0xa501_fe81);
    m.shl(Width::Byte, 0).expect("ignore both padding bytes");
    assert_eq!(
        m.stack_bytes().collect::<Vec<_>>(),
        [1, 8, 0, 0, 0, 0, 0, 0, 2, 0]
    );
}

#[test]
fn add_masks_padding_and_pins_arithmetic_goldens() {
    let mut m = Machine::new(12);
    push(&mut m, Width::Word, 0xabcd);
    push(&mut m, Width::Dword, 0xfe7f_ff01);
    m.add(Width::Byte, 0).expect("exact budget");
    assert_eq!(bytes(&m), [0x90, 8, 0, 0, 0, 0, 0, 0, 0x80, 0, 0xcd, 0xab]);
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        let mask = u64::MAX >> (64 - width as u32 * 8);
        let sign = (mask >> 1) + 1;
        for (lhs, rhs, result, flags) in [
            (0, 0, 0, 0x44),
            (15, 1, 16, 0x10),
            (1, 2, 3, 4),
            (
                sign - 1,
                1,
                sign,
                if width == Width::Byte { 0x890 } else { 0x894 },
            ),
            (sign, sign, 0, 0x845),
            (mask, 1, 0, 0x55),
        ] {
            let mut m =
                Machine::new((8 + (width as usize).max(2)).max(2 * (width as usize).max(2)));
            push(&mut m, width, lhs);
            push(&mut m, width, rhs);
            m.add(width, u64::MAX).expect("add");
            assert_eq!(
                m.step(Instruction::PopFlags),
                Ok(Output::FlagsWord((!0x8d5u64) | flags))
            );
            m.step(Instruction::PopReg {
                width,
                register: Register::Rax,
            })
            .expect("result");
            assert_eq!(m.register(Register::Rax), result);
        }
        let storage = (width as usize).max(2);
        for available in 0..2 * storage {
            if available % 2 != 0 {
                continue;
            }
            let mut m = Machine::new(32);
            for _ in 0..available / 2 {
                push(&mut m, Width::Word, 0xabcd);
            }
            let before = bytes(&m);
            assert_eq!(
                m.add(width, 0),
                Err(StackError::Underflow {
                    needed: 2 * storage,
                    available
                })
            );
            assert_eq!(bytes(&m), before);
        }
    }
}

fn push(machine: &mut Machine, width: Width, value: u64) {
    assert_eq!(
        machine.step(Instruction::PushImm { width, value }),
        Ok(Output::None)
    );
}

fn bytes(machine: &Machine) -> Vec<u8> {
    machine.stack_bytes().collect()
}

#[test]
fn byte_push_and_pop_use_word_storage() {
    let mut machine = Machine::new(4);
    push(&mut machine, Width::Dword, 0xddcc_5aa5);
    machine
        .step(Instruction::PopReg {
            width: Width::Byte,
            register: Register::Rax,
        })
        .expect("pop");
    assert_eq!(machine.register(Register::Rax), 0xa5);
    assert_eq!(bytes(&machine), [0xcc, 0xdd]);
    push(&mut machine, Width::Byte, 0x11);
    assert_eq!(bytes(&machine), [0x11, 0, 0xcc, 0xdd]);
}

#[test]
fn mixed_width_reads_cross_producing_pushes() {
    let mut machine = Machine::new(8);
    push(&mut machine, Width::Dword, 0x0403_0201);
    push(&mut machine, Width::Word, 0x0605);
    push(&mut machine, Width::Word, 0x0807);
    assert_eq!(bytes(&machine), [7, 8, 5, 6, 1, 2, 3, 4]);
    machine
        .step(Instruction::PopReg {
            width: Width::Qword,
            register: Register::R15,
        })
        .expect("mixed pop");
    assert_eq!(
        machine.register(Register::R15).to_le_bytes(),
        [7, 8, 5, 6, 1, 2, 3, 4]
    );
    assert!(bytes(&machine).is_empty());
}

#[test]
fn all_registers_obey_partial_write_semantics() {
    let registers = [
        Register::Rax,
        Register::Rcx,
        Register::Rdx,
        Register::Rbx,
        Register::Rbp,
        Register::Rsi,
        Register::Rdi,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    for register in registers {
        for (width, value, expected, stored) in [
            (Width::Byte, 0x12, 0xffff_ffff_ffff_ff12, &[0x12, 0][..]),
            (
                Width::Word,
                0x1234,
                0xffff_ffff_ffff_1234,
                &[0x34, 0x12][..],
            ),
            (
                Width::Dword,
                0x1234_5678,
                0x1234_5678,
                &[0x78, 0x56, 0x34, 0x12][..],
            ),
            (
                Width::Qword,
                0x1234_5678_9abc_def0,
                0x1234_5678_9abc_def0,
                &[0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12][..],
            ),
        ] {
            let mut machine = Machine::new(8);
            machine.set_register(register, u64::MAX);
            push(&mut machine, width, value);
            machine
                .step(Instruction::PopReg { width, register })
                .expect("write back");
            assert_eq!(
                machine.register(register),
                expected,
                "{register:?}/{width:?}"
            );
            machine
                .step(Instruction::PushReg { width, register })
                .expect("read low bits");
            assert_eq!(bytes(&machine), stored);
        }
    }
}

#[test]
fn flags_word_is_above_result_and_extracted_separately() {
    // intel.cc:29203-29212 emits flags at SP and the result at SP+8
    let mut machine = Machine::new(12);
    push(&mut machine, Width::Word, 0xddcc);
    push(&mut machine, Width::Word, 3);
    push(&mut machine, Width::Qword, 0x206);
    assert_eq!(bytes(&machine), [6, 2, 0, 0, 0, 0, 0, 0, 3, 0, 0xcc, 0xdd]);
    assert_eq!(
        machine.step(Instruction::PopFlags),
        Ok(Output::FlagsWord(0x206))
    );
    assert_eq!(bytes(&machine), [3, 0, 0xcc, 0xdd]);
    machine
        .step(Instruction::PopReg {
            width: Width::Word,
            register: Register::Rax,
        })
        .expect("result");
    assert_eq!(machine.register(Register::Rax), 3);
}

#[test]
fn discarded_flags_produce_no_apply_output() {
    let mut machine = Machine::new(10);
    push(&mut machine, Width::Byte, 3);
    push(&mut machine, Width::Qword, 0x206);
    assert_eq!(
        machine.step(Instruction::Drop {
            width: Width::Qword
        }),
        Ok(Output::None)
    );
    assert_eq!(bytes(&machine), [3, 0]);
}

#[test]
fn underflow_does_not_change_stack_or_register() {
    let mut machine = Machine::new(8);
    machine.set_register(Register::Rax, 0x55);
    push(&mut machine, Width::Word, 0x0201);
    assert!(matches!(
        machine.step(Instruction::PopReg {
            width: Width::Dword,
            register: Register::Rax
        }),
        Err(StackError::Underflow { .. })
    ));
    assert!(matches!(
        machine.step(Instruction::PopFlags),
        Err(StackError::Underflow { .. })
    ));
    assert!(matches!(
        machine.step(Instruction::Drop {
            width: Width::Qword
        }),
        Err(StackError::Underflow { .. })
    ));
    assert_eq!(machine.register(Register::Rax), 0x55);
    assert_eq!(bytes(&machine), [1, 2]);
}

#[test]
fn budget_applies_to_promoted_bytes_without_partial_mutation() {
    for budget in [0, 1] {
        let mut machine = Machine::new(budget);
        assert!(matches!(
            machine.step(Instruction::PushImm {
                width: Width::Byte,
                value: 1
            }),
            Err(StackError::Budget { .. })
        ));
        assert!(bytes(&machine).is_empty());
    }
    let mut machine = Machine::new(2);
    push(&mut machine, Width::Byte, 1);
    assert!(matches!(
        machine.step(Instruction::PushImm {
            width: Width::Byte,
            value: 2
        }),
        Err(StackError::Budget { .. })
    ));
    assert_eq!(bytes(&machine), [1, 0]);
}

#[test]
fn oversized_immediate_is_rejected_before_mutation() {
    let mut machine = Machine::new(8);
    assert!(matches!(
        machine.step(Instruction::PushImm {
            width: Width::Byte,
            value: 0x100
        }),
        Err(StackError::ImmediateTooWide { .. })
    ));
    assert!(bytes(&machine).is_empty());
}

#[test]
fn byte_budget_replaces_the_old_slot_count_limit() {
    let mut machine = Machine::new(10_000);
    for _ in 0..5_000 {
        push(&mut machine, Width::Byte, 0xa5);
    }
    assert_eq!(machine.stack_bytes().len(), 10_000);
    for _ in 0..5_000 {
        machine
            .step(Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            })
            .expect("pop");
        assert_eq!(machine.register(Register::Rax), 0xa5);
    }
    assert!(bytes(&machine).is_empty());
}
