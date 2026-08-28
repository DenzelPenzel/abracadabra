use vmp_vm::{
    bytecode::{Condition, Instruction, Program, Register, Width},
    host::{execute, ExecutionError, MachineState},
};

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const MODELED: u64 = CF | PF | AF | ZF | SF | OF;

fn execute_binary(operation: Instruction, width: Width, lhs: u64, rhs: u64) -> MachineState {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm { width, value: lhs },
            Instruction::PushImm { width, value: rhs },
            operation,
            Instruction::PopReg {
                width,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );
    execute(&program, MachineState::default())
        .expect("fixed arithmetic vector must execute")
        .state()
        .clone()
}

#[test]
fn arithmetic_edge_classes_are_pinned_at_every_width() {
    let widths = [
        (Width::Byte, u8::MAX.into(), 1u64 << 7, 0),
        (Width::Word, u16::MAX.into(), 1u64 << 15, PF),
        (Width::Dword, u32::MAX.into(), 1u64 << 31, PF),
        (Width::Qword, u64::MAX, 1u64 << 63, PF),
    ];

    for (width, maximum, sign_only, sign_parity) in widths {
        let add_carry = execute_binary(Instruction::Add(width), width, maximum, 1);
        assert_eq!(add_carry.register(Register::Rax), 0);
        assert_eq!(add_carry.flags_defined(), MODELED);
        assert_eq!(
            add_carry.flags_bits() & MODELED,
            CF | PF | AF | ZF,
            "add carry/zero edge at {width:?}"
        );

        let sub_borrow = execute_binary(Instruction::Sub(width), width, 0, 1);
        assert_eq!(sub_borrow.register(Register::Rax), maximum);
        assert_eq!(sub_borrow.flags_defined(), MODELED);
        assert_eq!(
            sub_borrow.flags_bits() & MODELED,
            CF | PF | AF | SF,
            "sub borrow/sign edge at {width:?}"
        );

        let sign_without_overflow = execute_binary(Instruction::Add(width), width, sign_only, 0);
        assert_eq!(sign_without_overflow.register(Register::Rax), sign_only);
        assert_eq!(
            sign_without_overflow.flags_bits() & MODELED,
            SF | sign_parity,
            "sign without overflow at {width:?}"
        );

        let odd_parity = execute_binary(Instruction::Sub(width), width, 2, 1);
        assert_eq!(odd_parity.register(Register::Rax), 1);
        assert_eq!(odd_parity.flags_bits() & MODELED, 0);

        let even_parity_zero = execute_binary(Instruction::Sub(width), width, maximum, maximum);
        assert_eq!(even_parity_zero.register(Register::Rax), 0);
        assert_eq!(even_parity_zero.flags_bits() & MODELED, PF | ZF);
    }
}

fn branch_program(condition: Condition) -> Program {
    Program::new(
        0,
        vec![
            Instruction::Jcc {
                condition,
                target: 14,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 0x11,
            },
            Instruction::Jmp { target: 17 },
            Instruction::PushImm {
                width: Width::Byte,
                value: 0x22,
            },
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    )
}

#[test]
fn every_jcc_truth_assignment_and_missing_required_flag_is_pinned() {
    let tables = [
        (Condition::O, OF, vec![OF]),
        (Condition::No, OF, vec![0]),
        (Condition::B, CF, vec![CF]),
        (Condition::Ae, CF, vec![0]),
        (Condition::E, ZF, vec![ZF]),
        (Condition::Ne, ZF, vec![0]),
        (Condition::Be, CF | ZF, vec![CF, ZF, CF | ZF]),
        (Condition::A, CF | ZF, vec![0]),
        (Condition::S, SF, vec![SF]),
        (Condition::Ns, SF, vec![0]),
        (Condition::P, PF, vec![PF]),
        (Condition::Np, PF, vec![0]),
        (Condition::L, SF | OF, vec![SF, OF]),
        (Condition::Ge, SF | OF, vec![0, SF | OF]),
        (
            Condition::Le,
            ZF | SF | OF,
            vec![ZF, SF, OF, ZF | SF, ZF | OF, ZF | SF | OF],
        ),
        (Condition::G, ZF | SF | OF, vec![0, SF | OF]),
    ];

    for (condition, required, true_assignments) in tables {
        let relevant: Vec<u64> = [CF, PF, ZF, SF, OF]
            .into_iter()
            .filter(|flag| required & flag != 0)
            .collect();
        for assignment in 0..(1usize << relevant.len()) {
            let bits = relevant
                .iter()
                .enumerate()
                .filter(|(index, _)| assignment & (1 << index) != 0)
                .map(|(_, flag)| *flag)
                .fold(0, |bits, flag| bits | flag);
            let mut state = MachineState::default();
            state.set_flags(bits, required);
            let execution = execute(&branch_program(condition), state)
                .expect("complete flag assignment must execute");
            let expected = if true_assignments.contains(&bits) {
                0x22
            } else {
                0x11
            };
            assert_eq!(
                execution.state().register(Register::Rax),
                expected,
                "condition {condition:?}, flags 0x{bits:x}"
            );
        }

        for missing in relevant {
            let defined = required & !missing;
            let mut state = MachineState::default();
            state.set_flags(required, defined);
            assert_eq!(
                execute(&branch_program(condition), state),
                Err(ExecutionError::UndefinedConditionFlags {
                    condition,
                    required,
                    defined,
                }),
                "condition {condition:?} accepted missing flag 0x{missing:x}"
            );
        }
    }
}

#[test]
fn nonzero_entry_and_terminal_untaken_fallthrough_follow_byte_offsets() {
    let nonzero_entry = Program::new(
        3,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 1,
            },
            Instruction::Ret,
        ],
    );
    let execution = execute(&nonzero_entry, MachineState::default())
        .expect("valid nonzero entry must execute from its boundary");
    assert_eq!(execution.state().pc(), 3);
    assert_eq!(execution.state().steps(), 1);

    let terminal_untaken = Program::new(
        0,
        vec![Instruction::Jcc {
            condition: Condition::E,
            target: 0,
        }],
    );
    let mut state = MachineState::default();
    state.set_flags(0, ZF);
    assert_eq!(
        execute(&terminal_untaken, state),
        Err(ExecutionError::Fallthrough { pc: 0 })
    );
}
