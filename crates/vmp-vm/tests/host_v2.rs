use vmp_vm::bytecode::{self, Condition, Register, Width};
use vmp_vm::bytecode_v2::{decode, Instruction as I, Program};
use vmp_vm::host_v2::{ExecutionError as E, Machine, Termination};
use vmp_vm::stack_v2::{Instruction as S, StackError};
#[test]
fn shl_flags_are_separate_and_count_is_a_word() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for count in [0, 1, 2, 32, 64, 255] {
            for apply in [false, true] {
                let mut m = Machine::new(16);
                m.set_flags_bits(u64::MAX);
                let p = program(vec![
                    push(Width::Word, count),
                    push(width, 1),
                    I::Shl { width },
                ]);
                assert!(matches!(m.execute(&p, 3), Err(E::Fallthrough { .. })));
                assert_eq!(m.flags_bits(), u64::MAX);
                let raw = m.stack_bytes().collect::<Vec<_>>();
                let flags = u64::from_le_bytes(raw[..8].try_into().expect("flags"));
                let end = program(vec![
                    I::Stack(if apply {
                        S::PopFlags
                    } else {
                        S::Drop {
                            width: Width::Qword,
                        }
                    }),
                    I::Stack(S::Drop { width }),
                    I::Ret,
                ]);
                assert_eq!(m.execute(&end, 6), Ok(Termination::Ret));
                assert_eq!(m.flags_bits(), if apply { flags } else { u64::MAX });
            }
        }
    }
}

#[test]
fn add_flags_are_physical_until_applied_or_discarded() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for initial in [0, u64::MAX, 0xdead_beef_0005_0202] {
            for apply in [false, true] {
                let mut m = Machine::new(16);
                m.set_flags_bits(initial);
                let mask = u64::MAX >> (64 - width as u32 * 8);
                let p = program(vec![push(width, mask), push(width, 1), I::Add { width }]);
                assert!(matches!(m.execute(&p, 3), Err(E::Fallthrough { .. })));
                assert_eq!(m.flags_bits(), initial);
                let flags = (initial & !0x8d5) | 0x55;
                let bytes = m.stack_bytes().collect::<Vec<_>>();
                assert_eq!(&bytes[..8], &flags.to_le_bytes());
                assert_eq!(&bytes[8..], vec![0; (width as usize).max(2)]);
                let end = program(vec![
                    I::Stack(if apply {
                        S::PopFlags
                    } else {
                        S::Drop {
                            width: Width::Qword,
                        }
                    }),
                    I::Stack(S::PopReg {
                        width,
                        register: Register::Rax,
                    }),
                    I::Ret,
                ]);
                assert_eq!(m.execute(&end, 6), Ok(Termination::Ret));
                assert_eq!(m.flags_bits(), if apply { flags } else { initial });
                assert_eq!(m.register(Register::Rax), 0);
            }
        }
    }
}

#[test]
fn add_failure_preserves_data_state_and_counts_dispatch() {
    let mut m = Machine::new(11);
    m.set_flags_bits(u64::MAX);
    m.set_register(Register::Rax, 42);
    let p = program(vec![
        push(Width::Word, 0xabcd),
        push(Width::Word, 1),
        push(Width::Word, 2),
        I::Add { width: Width::Word },
    ]);
    assert_eq!(
        m.execute(&p, 4),
        Err(E::Stack(StackError::Budget {
            required: 12,
            limit: 11
        }))
    );
    assert_eq!(
        m.stack_bytes().collect::<Vec<_>>(),
        [2, 0, 1, 0, 0xcd, 0xab]
    );
    assert_eq!(m.flags_bits(), u64::MAX);
    assert_eq!(m.register(Register::Rax), 42);
    assert_eq!(m.pc(), 12);
    assert_eq!(m.steps(), 4);
}

fn program(instructions: Vec<I>) -> Program {
    Program::new(0, instructions).expect("valid")
}
fn push(width: Width, value: u64) -> I {
    I::Stack(S::PushImm { width, value })
}

#[test]
fn literal_mixed_width_executes_only_in_v2() {
    let mut bytes = [
        86, 77, 80, 66, 2, 0, 16, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0x10, 1, 0xa5, 0x12, 2, 0, 1,
    ];
    let mut machine = Machine::new(2);
    machine.set_register(Register::Rax, 0x1122_3344_5566_ffff);
    assert_eq!(
        machine.execute(&decode(&bytes).expect("v2"), 3),
        Ok(Termination::Ret)
    );
    assert_eq!(machine.register(Register::Rax), 0x1122_3344_5566_00a5);
    assert_eq!(machine.steps(), 3);
    bytes[4] = 1;
    let old = bytecode::decode(&bytes).expect("v1 structural");
    assert!(matches!(
        vmp_vm::host::execute(&old, Default::default()),
        Err(vmp_vm::host::ExecutionError::PopWidthMismatch { .. })
    ));
}

#[test]
fn raw_flags_apply_discard_and_mixed_width_qword() {
    for (last, expected) in [
        (S::PopFlags, 0x8877_6655_4433_2211),
        (
            S::Drop {
                width: Width::Qword,
            },
            0xdead,
        ),
    ] {
        let p = program(vec![
            push(Width::Dword, 0x8877_6655),
            push(Width::Word, 0x4433),
            push(Width::Word, 0x2211),
            I::Stack(last),
            I::Ret,
        ]);
        let mut m = Machine::new(8);
        m.set_flags_bits(0xdead);
        assert_eq!(m.execute(&p, 5), Ok(Termination::Ret));
        assert_eq!(m.flags_bits(), expected);
        assert_eq!(m.stack_bytes().len(), 0);
    }
    for bits in [0, u64::MAX, 1 << 18] {
        let mut m = Machine::new(8);
        m.execute(
            &program(vec![
                push(Width::Qword, bits),
                I::Stack(S::PopFlags),
                I::Ret,
            ]),
            3,
        )
        .expect("raw");
        assert_eq!(m.flags_bits(), bits);
    }
}

#[test]
fn underflow_preserves_stack_registers_and_flags() {
    for op in [
        S::PopFlags,
        S::PopReg {
            width: Width::Qword,
            register: Register::Rax,
        },
        S::Drop {
            width: Width::Qword,
        },
    ] {
        let mut m = Machine::new(8);
        m.set_flags_bits(u64::MAX);
        m.set_register(Register::Rax, 42);
        let p = program(vec![push(Width::Word, 0x2211), I::Stack(op), I::Ret]);
        assert_eq!(
            m.execute(&p, 3),
            Err(E::Stack(StackError::Underflow {
                needed: 8,
                available: 2
            }))
        );
        assert_eq!(m.stack_bytes().collect::<Vec<_>>(), [0x11, 0x22]);
        assert_eq!(m.register(Register::Rax), 42);
        assert_eq!(m.flags_bits(), u64::MAX);
        assert_eq!(m.pc(), 4);
        assert_eq!(m.steps(), 2);
    }
}

#[test]
fn all_conditions_against_literal_truth_masks() {
    // Assignment index bits are CF, PF, ZF, SF, OF, in that order
    let masks: [u32; 16] = [
        0xffff0000, 0x0000ffff, 0xaaaaaaaa, 0x55555555, 0xf0f0f0f0, 0x0f0f0f0f, 0xfafafafa,
        0x05050505, 0xff00ff00, 0x00ff00ff, 0xcccccccc, 0x33333333, 0x00ffff00, 0xff0000ff,
        0xf0fffff0, 0x0f00000f,
    ];
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
    for (condition, mask) in conditions.into_iter().zip(masks) {
        // Taken returns at byte 7; untaken returns at byte 6
        let p = program(vec![
            I::Jcc {
                condition,
                target: 7,
            },
            I::Ret,
            I::Ret,
        ]);
        for assignment in 0..32 {
            let mut bits = 0;
            for (index, position) in [0, 2, 6, 7, 11].into_iter().enumerate() {
                if assignment & (1 << index) != 0 {
                    bits |= 1 << position;
                }
            }
            let mut m = Machine::new(0);
            m.set_flags_bits(bits | (1 << 63));
            assert_eq!(m.execute(&p, 2), Ok(Termination::Ret));
            assert_eq!(
                m.pc(),
                if mask & (1 << assignment) != 0 { 7 } else { 6 },
                "{condition:?} {assignment}"
            );
            assert_eq!(m.flags_bits(), bits | (1 << 63));
        }
    }
}

#[test]
fn limits_ret_boundary_loop_fallthrough_and_nonzero_entry() {
    let ret = program(vec![I::Ret]);
    let mut m = Machine::new(0);
    assert_eq!(m.execute(&ret, 0), Err(E::StepLimit { maximum: 0 }));
    assert_eq!(m.execute(&ret, 1), Ok(Termination::Ret));
    assert_eq!(m.execute(&ret, 1), Err(E::StepLimit { maximum: 1 }));
    let mut m = Machine::new(0);
    assert_eq!(
        m.execute(&program(vec![I::Jmp { target: 0 }]), 7),
        Err(E::StepLimit { maximum: 7 })
    );
    assert_eq!(m.steps(), 7);
    let mut m = Machine::new(2);
    assert_eq!(
        m.execute(&program(vec![push(Width::Byte, 1)]), 1),
        Err(E::Fallthrough { pc: 0 })
    );
    let mut m = Machine::new(2);
    assert_eq!(
        m.execute(&program(vec![push(Width::Byte, 1), I::Ret]), 2),
        Err(E::NonEmptyStackAtRet { bytes: 2 })
    );
    let mut m = Machine::new(1);
    assert_eq!(
        m.execute(&program(vec![push(Width::Byte, 1), I::Ret]), 2),
        Err(E::Stack(StackError::Budget {
            required: 2,
            limit: 1
        }))
    );
    assert_eq!(m.stack_bytes().len(), 0);
    let mut m = Machine::new(0);
    assert_eq!(
        m.execute(
            &Program::new(1, vec![I::Stack(S::PopFlags), I::Ret]).expect("entry"),
            1
        ),
        Ok(Termination::Ret)
    );
    assert_eq!(m.pc(), 1);
}
