use vmp_vm::{
    bytecode::{
        decode, encode, Condition, Instruction, Program, Register, Width, MAX_INSTRUCTIONS,
    },
    host::{execute, ExecutionError, MachineState, Termination},
};

#[test]
fn byte_add_uses_stack_order_updates_low_register_byte_and_defines_exact_flags() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 1,
            },
            Instruction::Add(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rbx,
            },
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, 0xff);
    initial.set_register(Register::Rbx, 0x1122_3344_5566_7788);

    let execution = execute(&program, initial).expect("valid program must terminate");
    let state = execution.state();

    assert_eq!(execution.termination(), Termination::Ret);
    assert_eq!(state.register(Register::Rbx), 0x1122_3344_5566_7700);
    assert_eq!(state.stack_len(), 0);
    assert_eq!(state.steps(), 5);
    assert_eq!(
        state.flags_defined(),
        (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11)
    );
    assert_eq!(
        state.flags_bits() & state.flags_defined(),
        (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6)
    );
}

#[test]
fn byte_sub_pops_rhs_then_lhs_and_sets_borrow_flags() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 1,
            },
            Instruction::Sub(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );

    let execution = execute(&program, MachineState::default()).expect("sub must execute");
    let state = execution.state();

    assert_eq!(state.register(Register::Rax), 0xff);
    assert_eq!(
        state.flags_defined(),
        (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11)
    );
    assert_eq!(
        state.flags_bits() & state.flags_defined(),
        (1 << 0) | (1 << 2) | (1 << 4) | (1 << 7)
    );
}

#[test]
fn drop_discards_a_typed_slot_without_changing_registers_or_flags() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Word,
                value: 0x1234,
            },
            Instruction::Drop(Width::Word),
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, 0x1122_3344_5566_7788);
    initial.set_flags(0x805, 0x8d5);

    let execution = execute(&program, initial).expect("typed drop must execute");
    let state = execution.state();

    assert_eq!(execution.termination(), Termination::Ret);
    assert_eq!(state.register(Register::Rax), 0x1122_3344_5566_7788);
    assert_eq!(state.flags_bits(), 0x805);
    assert_eq!(state.flags_defined(), 0x8d5);
    assert_eq!(state.stack_len(), 0);
    assert_eq!(state.steps(), 3);
}

#[test]
fn drop_rejects_underflow_and_a_mismatched_slot_width() {
    assert_eq!(
        execute(
            &Program::new(0, vec![Instruction::Drop(Width::Byte)]),
            MachineState::default(),
        ),
        Err(ExecutionError::StackUnderflow)
    );

    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PushImm {
                        width: Width::Word,
                        value: 1,
                    },
                    Instruction::Drop(Width::Byte),
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::PopWidthMismatch {
            expected: Width::Byte,
            actual: Width::Word,
        })
    );
}

#[test]
fn byte_xor_clears_carry_overflow_and_makes_auxiliary_undefined() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xff,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xff,
            },
            Instruction::Xor(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_flags(u64::MAX, u64::MAX);

    let execution = execute(&program, initial).expect("xor must execute");
    let state = execution.state();
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

    assert_eq!(state.register(Register::Rax), 0);
    assert_eq!(state.flags_defined(), !(1 << 4));
    assert_eq!(
        state.flags_bits() & state.flags_defined(),
        !modeled | (1 << 2) | (1 << 6)
    );
}

#[test]
fn byte_and_clears_carry_overflow_and_makes_auxiliary_undefined() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xf0,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 0x0f,
            },
            Instruction::And(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_flags(u64::MAX, u64::MAX);

    let execution = execute(&program, initial).expect("and must execute");
    let state = execution.state();
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

    assert_eq!(state.register(Register::Rax), 0);
    assert_eq!(state.flags_defined(), !(1 << 4));
    assert_eq!(
        state.flags_bits() & state.flags_defined(),
        !modeled | (1 << 2) | (1 << 6)
    );
}

#[test]
fn and_rejects_underflow_and_mismatched_operand_widths() {
    assert_eq!(
        execute(
            &Program::new(0, vec![Instruction::And(Width::Byte)]),
            MachineState::default(),
        ),
        Err(ExecutionError::StackUnderflow)
    );
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PushImm {
                        width: Width::Byte,
                        value: 1,
                    },
                    Instruction::PushImm {
                        width: Width::Word,
                        value: 1,
                    },
                    Instruction::And(Width::Byte),
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::WidthMismatch {
            instruction: Width::Byte,
            lhs: Width::Byte,
            rhs: Width::Word,
        })
    );
}

#[test]
fn byte_or_clears_carry_overflow_and_makes_auxiliary_undefined() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xf0,
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 0x0f,
            },
            Instruction::Or(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_flags(u64::MAX, u64::MAX);

    let execution = execute(&program, initial).expect("or must execute");
    let state = execution.state();
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

    assert_eq!(state.register(Register::Rax), 0xff);
    assert_eq!(state.flags_defined(), !(1 << 4));
    assert_eq!(
        state.flags_bits() & state.flags_defined(),
        !modeled | (1 << 2) | (1 << 7)
    );
}

#[test]
fn or_rejects_underflow_and_mismatched_operand_widths() {
    assert_eq!(
        execute(
            &Program::new(0, vec![Instruction::Or(Width::Byte)]),
            MachineState::default(),
        ),
        Err(ExecutionError::StackUnderflow)
    );
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PushImm {
                        width: Width::Byte,
                        value: 1,
                    },
                    Instruction::PushImm {
                        width: Width::Word,
                        value: 1,
                    },
                    Instruction::Or(Width::Byte),
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::WidthMismatch {
            instruction: Width::Byte,
            lhs: Width::Byte,
            rhs: Width::Word,
        })
    );
}

#[test]
fn conditional_and_unconditional_branches_select_exact_boundaries() {
    let program = Program::new(
        0,
        vec![
            Instruction::Jcc {
                condition: Condition::E,
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
    );

    let mut taken = MachineState::default();
    taken.set_flags(1 << 6, 1 << 6);
    let taken = execute(&program, taken).expect("defined true ZF must take E");
    assert_eq!(taken.state().register(Register::Rax), 0x22);
    assert_eq!(taken.state().steps(), 4);

    let mut untaken = MachineState::default();
    untaken.set_flags(0, 1 << 6);
    let untaken = execute(&program, untaken).expect("defined false ZF must not take E");
    assert_eq!(untaken.state().register(Register::Rax), 0x11);
    assert_eq!(untaken.state().steps(), 5);
}

#[test]
fn all_conditions_require_complete_flags_and_choose_canonical_result() {
    let cf = 1 << 0;
    let pf = 1 << 2;
    let zf = 1 << 6;
    let sf = 1 << 7;
    let of = 1 << 11;
    let cases = [
        (Condition::O, of, of, 0),
        (Condition::No, of, 0, of),
        (Condition::B, cf, cf, 0),
        (Condition::Ae, cf, 0, cf),
        (Condition::E, zf, zf, 0),
        (Condition::Ne, zf, 0, zf),
        (Condition::Be, cf | zf, cf, 0),
        (Condition::A, cf | zf, 0, cf),
        (Condition::S, sf, sf, 0),
        (Condition::Ns, sf, 0, sf),
        (Condition::P, pf, pf, 0),
        (Condition::Np, pf, 0, pf),
        (Condition::L, sf | of, sf, 0),
        (Condition::Ge, sf | of, 0, sf),
        (Condition::Le, zf | sf | of, zf, 0),
        (Condition::G, zf | sf | of, 0, zf),
    ];

    for (condition, required, true_bits, false_bits) in cases {
        let program = Program::new(
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
        );

        let mut true_state = MachineState::default();
        true_state.set_flags(true_bits, required);
        let true_execution = execute(&program, true_state).expect("true condition must execute");
        assert_eq!(true_execution.state().register(Register::Rax), 0x22);

        let mut false_state = MachineState::default();
        false_state.set_flags(false_bits, required);
        let false_execution = execute(&program, false_state).expect("false condition must execute");
        assert_eq!(false_execution.state().register(Register::Rax), 0x11);

        for missing in [1 << 0, 1 << 2, 1 << 6, 1 << 7, 1 << 11] {
            if required & missing == 0 {
                continue;
            }
            let defined = required & !missing;
            let mut incomplete = MachineState::default();
            incomplete.set_flags(true_bits, defined);
            assert_eq!(
                execute(&program, incomplete),
                Err(ExecutionError::UndefinedConditionFlags {
                    condition,
                    required,
                    defined,
                })
            );
        }
    }
}

#[test]
fn one_millionth_ret_succeeds_but_the_next_fetch_traps() {
    let mut before_last_ret = MachineState::default();
    before_last_ret.set_steps(999_999);
    let terminal = execute(&Program::new(0, vec![Instruction::Ret]), before_last_ret)
        .expect("ret may be the one-millionth dispatch");
    assert_eq!(terminal.state().steps(), 1_000_000);

    let mut before_last_nonterminal = MachineState::default();
    before_last_nonterminal.set_steps(999_999);
    assert_eq!(
        execute(
            &Program::new(0, vec![Instruction::Jmp { target: 0 }]),
            before_last_nonterminal,
        ),
        Err(ExecutionError::StepLimit { maximum: 1_000_000 })
    );
}

#[test]
fn an_initial_step_count_over_the_limit_traps_before_dispatch() {
    let mut invalid = MachineState::default();
    invalid.set_steps(1_000_001);

    assert_eq!(
        execute(&Program::new(0, vec![Instruction::Ret]), invalid),
        Err(ExecutionError::StepLimit { maximum: 1_000_000 })
    );
}

#[test]
fn an_initial_step_count_at_the_limit_traps_before_dispatch() {
    let mut exhausted = MachineState::default();
    exhausted.set_steps(1_000_000);

    assert_eq!(
        execute(&Program::new(0, vec![Instruction::Ret]), exhausted),
        Err(ExecutionError::StepLimit { maximum: 1_000_000 })
    );
}

#[test]
fn stack_limit_accepts_exact_and_rejects_one_over() {
    let push = Instruction::PushImm {
        width: Width::Byte,
        value: 1,
    };
    let pop = Instruction::PopReg {
        width: Width::Byte,
        register: Register::Rax,
    };
    let mut exact = Vec::new();
    exact.extend(std::iter::repeat_n(push.clone(), 4_096));
    exact.extend(std::iter::repeat_n(pop, 4_096));
    exact.push(Instruction::Ret);
    assert!(execute(&Program::new(0, exact), MachineState::default()).is_ok());

    let one_over = std::iter::repeat_n(push, 4_097).collect();
    assert_eq!(
        execute(&Program::new(0, one_over), MachineState::default()),
        Err(ExecutionError::StackOverflow { maximum: 4_096 })
    );
}

#[test]
fn malformed_execution_state_transitions_return_typed_traps() {
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PopReg {
                        width: Width::Byte,
                        register: Register::Rax,
                    },
                    Instruction::Ret,
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::StackUnderflow)
    );
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PushImm {
                        width: Width::Byte,
                        value: 1,
                    },
                    Instruction::PushImm {
                        width: Width::Word,
                        value: 2,
                    },
                    Instruction::Add(Width::Word),
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::WidthMismatch {
            instruction: Width::Word,
            lhs: Width::Byte,
            rhs: Width::Word,
        })
    );
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![
                    Instruction::PushImm {
                        width: Width::Byte,
                        value: 1,
                    },
                    Instruction::Ret,
                ],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::NonEmptyStackAtRet { depth: 1 })
    );
    assert_eq!(
        execute(
            &Program::new(
                0,
                vec![Instruction::PushImm {
                    width: Width::Byte,
                    value: 1,
                }],
            ),
            MachineState::default(),
        ),
        Err(ExecutionError::Fallthrough { pc: 0 })
    );
    assert_eq!(
        execute(
            &Program::new(1, vec![Instruction::Ret]),
            MachineState::default(),
        ),
        Err(ExecutionError::InvalidPc { pc: 1 })
    );
    assert_eq!(
        execute(
            &Program::new(0, vec![Instruction::Jmp { target: 1 }]),
            MachineState::default(),
        ),
        Err(ExecutionError::InvalidBranchTarget {
            code_offset: 0,
            target: 1,
        })
    );
}

#[test]
fn pop_register_follows_x64_partial_and_zero_extending_writes() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xaa,
            },
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::PushImm {
                width: Width::Word,
                value: 0xbbcc,
            },
            Instruction::PopReg {
                width: Width::Word,
                register: Register::Rbx,
            },
            Instruction::PushImm {
                width: Width::Dword,
                value: 0xdead_beef,
            },
            Instruction::PopReg {
                width: Width::Dword,
                register: Register::Rcx,
            },
            Instruction::PushImm {
                width: Width::Qword,
                value: 0xfedc_ba98_7654_3210,
            },
            Instruction::PopReg {
                width: Width::Qword,
                register: Register::Rdx,
            },
            Instruction::Ret,
        ],
    );
    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, 0x1122_3344_5566_7788);
    initial.set_register(Register::Rbx, 0x1122_3344_5566_7788);
    initial.set_register(Register::Rcx, u64::MAX);
    initial.set_register(Register::Rdx, u64::MAX);

    let execution = execute(&program, initial).expect("all register widths must execute");
    assert_eq!(
        execution.state().register(Register::Rax),
        0x1122_3344_5566_77aa
    );
    assert_eq!(
        execution.state().register(Register::Rbx),
        0x1122_3344_5566_bbcc
    );
    assert_eq!(execution.state().register(Register::Rcx), 0xdead_beef);
    assert_eq!(
        execution.state().register(Register::Rdx),
        0xfedc_ba98_7654_3210
    );
}

#[test]
fn signed_add_and_sub_overflow_vectors_are_pinned_at_every_width() {
    let cases = [
        (
            Width::Byte,
            0x7f,
            0x80,
            (1 << 4) | (1 << 7) | (1 << 11),
            (1 << 4) | (1 << 11),
        ),
        (
            Width::Word,
            0x7fff,
            0x8000,
            (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11),
            (1 << 2) | (1 << 4) | (1 << 11),
        ),
        (
            Width::Dword,
            0x7fff_ffff,
            0x8000_0000,
            (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11),
            (1 << 2) | (1 << 4) | (1 << 11),
        ),
        (
            Width::Qword,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11),
            (1 << 2) | (1 << 4) | (1 << 11),
        ),
    ];
    for (width, max_positive, min_negative, add_flags, sub_flags) in cases {
        let add = Program::new(
            0,
            vec![
                Instruction::PushImm {
                    width,
                    value: max_positive,
                },
                Instruction::PushImm { width, value: 1 },
                Instruction::Add(width),
                Instruction::PopReg {
                    width,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let add = execute(&add, MachineState::default()).expect("signed add edge must execute");
        assert_eq!(add.state().register(Register::Rax), min_negative);
        assert_eq!(
            add.state().flags_bits() & add.state().flags_defined(),
            add_flags
        );

        let sub = Program::new(
            0,
            vec![
                Instruction::PushImm {
                    width,
                    value: min_negative,
                },
                Instruction::PushImm { width, value: 1 },
                Instruction::Sub(width),
                Instruction::PopReg {
                    width,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let sub = execute(&sub, MachineState::default()).expect("signed sub edge must execute");
        assert_eq!(sub.state().register(Register::Rax), max_positive);
        assert_eq!(
            sub.state().flags_bits() & sub.state().flags_defined(),
            sub_flags
        );
    }
}

#[test]
fn freshly_decoded_program_has_the_same_host_semantics() {
    let source = Program::new(
        0,
        vec![
            Instruction::PushReg {
                width: Width::Dword,
                register: Register::Rax,
            },
            Instruction::PushImm {
                width: Width::Dword,
                value: 7,
            },
            Instruction::Add(Width::Dword),
            Instruction::PopReg {
                width: Width::Dword,
                register: Register::Rbx,
            },
            Instruction::Ret,
        ],
    );
    let bytes = encode(&source).expect("source program must encode");
    let decoded = decode(&bytes).expect("encoded program must decode fresh");
    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, 5);

    let execution = execute(&decoded, initial).expect("fresh decoded program must execute");
    assert_eq!(execution.state().register(Register::Rbx), 12);
    assert_eq!(execution.termination(), Termination::Ret);
}

#[test]
fn invalid_branch_targets_are_rejected_before_dispatch_even_when_unreached() {
    let program = Program::new(
        0,
        vec![
            Instruction::Jcc {
                condition: Condition::E,
                target: 1,
            },
            Instruction::Ret,
        ],
    );
    let mut state = MachineState::default();
    state.set_flags(0, 1 << 6);

    assert_eq!(
        execute(&program, state),
        Err(ExecutionError::InvalidBranchTarget {
            code_offset: 0,
            target: 1,
        })
    );

    let unreachable = Program::new(0, vec![Instruction::Ret, Instruction::Jmp { target: 2 }]);
    assert_eq!(
        execute(&unreachable, MachineState::default()),
        Err(ExecutionError::InvalidBranchTarget {
            code_offset: 1,
            target: 2,
        })
    );
}

#[test]
fn a_manual_program_one_over_the_instruction_limit_is_rejected_before_allocation() {
    let program = Program::new(0, vec![Instruction::Ret; MAX_INSTRUCTIONS + 1]);

    assert_eq!(
        execute(&program, MachineState::default()),
        Err(ExecutionError::TooManyInstructions {
            count: MAX_INSTRUCTIONS + 1,
            maximum: MAX_INSTRUCTIONS,
        })
    );
}

#[test]
fn a_manual_out_of_range_immediate_is_rejected_instead_of_masked() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 0x100,
            },
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );

    assert_eq!(
        execute(&program, MachineState::default()),
        Err(ExecutionError::ImmediateOutOfRange {
            width: Width::Byte,
            value: 0x100,
        })
    );
}

#[test]
fn pop_width_mismatch_reports_expected_and_actual_slot_widths() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushImm {
                width: Width::Byte,
                value: 1,
            },
            Instruction::PopReg {
                width: Width::Word,
                register: Register::Rax,
            },
            Instruction::Ret,
        ],
    );

    assert_eq!(
        execute(&program, MachineState::default()),
        Err(ExecutionError::PopWidthMismatch {
            expected: Width::Word,
            actual: Width::Byte,
        })
    );
}

#[test]
fn nonzero_xor_vectors_are_pinned_at_every_width() {
    let cases = [
        (Width::Byte, 0xaa, 0x0f, 0xa5),
        (Width::Word, 0xaa55, 0x0ff0, 0xa5a5),
        (Width::Dword, 0xaa55_aa55, 0x0ff0_0ff0, 0xa5a5_a5a5),
        (
            Width::Qword,
            0xaa55_aa55_aa55_aa55,
            0x0ff0_0ff0_0ff0_0ff0,
            0xa5a5_a5a5_a5a5_a5a5,
        ),
    ];
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    for (width, lhs, rhs, expected) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::PushImm { width, value: lhs },
                Instruction::PushImm { width, value: rhs },
                Instruction::Xor(width),
                Instruction::PopReg {
                    width,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let mut initial = MachineState::default();
        initial.set_flags(u64::MAX, u64::MAX);

        let execution = execute(&program, initial).expect("nonzero xor vector must execute");
        assert_eq!(execution.state().register(Register::Rax), expected);
        assert_eq!(execution.state().flags_defined(), !(1 << 4));
        assert_eq!(
            execution.state().flags_bits() & execution.state().flags_defined(),
            !modeled | (1 << 2) | (1 << 7)
        );
    }
}

#[test]
fn nonzero_and_vectors_are_pinned_at_every_width() {
    let cases = [
        (Width::Byte, 0xf3, 0x3f, 0x33),
        (Width::Word, 0xf0f3, 0x3ff0, 0x30f0),
        (Width::Dword, 0xf0f0_f0f3, 0x3f3f_3ff0, 0x3030_30f0),
        (
            Width::Qword,
            0xf0f0_f0f0_f0f0_f0f3,
            0x3f3f_3f3f_3f3f_3ff0,
            0x3030_3030_3030_30f0,
        ),
    ];
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    for (width, lhs, rhs, expected) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::PushImm { width, value: lhs },
                Instruction::PushImm { width, value: rhs },
                Instruction::And(width),
                Instruction::PopReg {
                    width,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let mut initial = MachineState::default();
        initial.set_flags(u64::MAX, u64::MAX);

        let execution = execute(&program, initial).expect("nonzero and vector must execute");
        assert_eq!(execution.state().register(Register::Rax), expected);
        assert_eq!(execution.state().flags_defined(), !(1 << 4));
        assert_eq!(
            execution.state().flags_bits() & execution.state().flags_defined(),
            !modeled | (1 << 2)
        );
    }
}

#[test]
fn and_sets_sign_clears_odd_parity_and_preserves_outside_flags_at_every_width() {
    let cases = [
        (Width::Byte, 0x80, u64::from(u8::MAX)),
        (Width::Word, 0x8001, u64::from(u16::MAX)),
        (Width::Dword, 0x8000_0001, u64::from(u32::MAX)),
        (Width::Qword, 0x8000_0000_0000_0001, u64::MAX),
    ];
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    let logical_defined = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11);
    let initial_bits = modeled | (1 << 9) | (1 << 10);
    let initial_defined = modeled | (1 << 9) | (1 << 12);

    for (width, expected, rhs) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::PushImm {
                    width,
                    value: expected,
                },
                Instruction::PushImm { width, value: rhs },
                Instruction::And(width),
                Instruction::PopReg {
                    width,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let mut initial = MachineState::default();
        initial.set_flags(initial_bits, initial_defined);

        let execution = execute(&program, initial).expect("signed and vector must execute");
        assert_eq!(execution.state().register(Register::Rax), expected);
        assert_eq!(
            execution.state().flags_bits(),
            (1 << 7) | (1 << 9) | (1 << 10)
        );
        assert_eq!(
            execution.state().flags_defined(),
            logical_defined | (1 << 9) | (1 << 12)
        );
    }
}

#[test]
fn add_and_sub_preserve_flags_outside_the_modeled_set() {
    let cases = [
        (Instruction::Add(Width::Byte), 1),
        (Instruction::Sub(Width::Byte), 2),
    ];
    let modeled = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    for (operation, lhs) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::PushImm {
                    width: Width::Byte,
                    value: lhs,
                },
                Instruction::PushImm {
                    width: Width::Byte,
                    value: 1,
                },
                operation,
                Instruction::PopReg {
                    width: Width::Byte,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        );
        let mut initial = MachineState::default();
        initial.set_flags(1 << 9, 1 << 9);

        let execution = execute(&program, initial).expect("arithmetic vector must execute");
        assert_eq!(execution.state().flags_defined(), modeled | (1 << 9));
        assert_eq!(
            execution.state().flags_bits() & execution.state().flags_defined(),
            1 << 9
        );
    }
}
