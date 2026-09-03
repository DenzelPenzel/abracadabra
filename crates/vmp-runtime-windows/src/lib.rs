//! Embedded Windows x64 VM runtime.

#[cfg(target_arch = "x86_64")]
mod runtime_x64;

#[cfg(target_arch = "x86_64")]
pub use runtime_x64::{
    execute_validated_gate, RuntimeError, RuntimeExecution, RuntimeTrap, MAX_RUNTIME_CODE_SIZE,
};

#[cfg(all(test, target_arch = "x86_64"))]
use runtime_x64::execute_raw_gate;

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use vmp_vm::bytecode::{decode, encode, DecodeError, Instruction, Program, Register, Width};
    use vmp_vm::host::{execute, MachineState, Termination};

    #[test]
    fn validated_gate_rejects_a_later_unknown_opcode_before_execution() {
        let mut container = encode(&Program::new(
            0,
            vec![Instruction::Add(Width::Qword), Instruction::Ret],
        ))
        .expect("fixture must encode");
        container[18] = 0xff;

        assert!(matches!(
            execute_validated_gate(&container, 1, 2),
            Err(RuntimeError::Decode(DecodeError::UnknownOpcode {
                code_offset: 2,
                opcode: 0xff,
            }))
        ));
    }

    #[test]
    fn validated_gate_matches_host_for_qword_add_corpus() {
        let container = encode(&Program::new(
            1,
            vec![
                Instruction::Ret,
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rcx,
                },
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rdx,
                },
                Instruction::Add(Width::Qword),
                Instruction::PopReg {
                    width: Width::Qword,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        ))
        .expect("fixture must encode");
        let code = &container[16..];
        assert_eq!(
            code,
            [0x01, 0x11, 8, 1, 0x11, 8, 2, 0x20, 8, 0x12, 8, 0, 0x01]
        );
        let program = decode(&container).expect("fixture must validate");

        for (lhs, rhs) in [
            (0, 0),
            (1, 2),
            (u64::MAX, 1),
            (i64::MAX as u64, 1),
            (0xffff_ffff_ffff_fffe, 5),
            (0x0f, 1),
        ] {
            let mut initial = MachineState::default();
            initial.set_register(Register::Rax, 0xfeed_face_cafe_beef);
            initial.set_register(Register::Rcx, lhs);
            initial.set_register(Register::Rdx, rhs);
            let host = execute(&program, initial).expect("host must execute validated fixture");
            let native = execute_validated_gate(&container, lhs, rhs)
                .expect("native runtime must execute validated fixture");
            let defined = host.state().flags_defined();

            assert_eq!(host.termination(), Termination::Ret);
            assert_eq!(defined, 0x8d5);
            assert_eq!(native.rax, host.state().register(Register::Rax));
            assert_eq!(native.rcx, host.state().register(Register::Rcx));
            assert_eq!(native.rdx, host.state().register(Register::Rdx));
            assert_eq!(native.rflags & defined, host.state().flags_bits() & defined);
        }
    }

    #[test]
    fn raw_gate_rejects_malformed_bytecode_without_reading_past_end() {
        assert_eq!(
            execute_raw_gate(&[], 1, 2),
            Err(RuntimeTrap::TruncatedBytecode)
        );
        assert_eq!(
            execute_raw_gate(&[0x11, 8], 1, 2),
            Err(RuntimeTrap::TruncatedBytecode)
        );
        assert_eq!(
            execute_raw_gate(&[0xff], 1, 2),
            Err(RuntimeTrap::UnsupportedOpcode)
        );
        assert_eq!(
            execute_raw_gate(&[0x11, 8, 3], 1, 2),
            Err(RuntimeTrap::InvalidOperand)
        );
    }

    #[test]
    fn raw_gate_enforces_operand_stack_contract() {
        assert_eq!(
            execute_raw_gate(&[0x20, 8], 1, 2),
            Err(RuntimeTrap::StackUnderflow)
        );
        assert_eq!(
            execute_raw_gate(&[0x11, 8, 1, 0x01], 1, 2),
            Err(RuntimeTrap::NonEmptyStack)
        );

        let seventeen_pushes = [0x11, 8, 1].repeat(17);
        assert_eq!(
            execute_raw_gate(&seventeen_pushes, 1, 2),
            Err(RuntimeTrap::StackOverflow)
        );
    }

    #[test]
    fn raw_gate_rejects_bytecode_over_the_v1_code_limit_before_dispatch() {
        let oversized = vec![0x01; MAX_RUNTIME_CODE_SIZE + 1];

        assert_eq!(
            execute_raw_gate(&oversized, 1, 2),
            Err(RuntimeTrap::BytecodeTooLarge {
                size: MAX_RUNTIME_CODE_SIZE + 1,
                maximum: MAX_RUNTIME_CODE_SIZE,
            })
        );
    }

    #[test]
    fn runtime_traps_implement_the_workspace_error_contract() {
        let trap = RuntimeTrap::BytecodeTooLarge {
            size: MAX_RUNTIME_CODE_SIZE + 1,
            maximum: MAX_RUNTIME_CODE_SIZE,
        };
        let error: &dyn std::error::Error = &trap;

        assert_eq!(
            error.to_string(),
            format!(
                "runtime bytecode size {} exceeds {}",
                MAX_RUNTIME_CODE_SIZE + 1,
                MAX_RUNTIME_CODE_SIZE
            )
        );
        assert_eq!(
            RuntimeTrap::FlagRestoreMismatch.to_string(),
            "runtime RFLAGS restoration mismatch"
        );
    }
}
