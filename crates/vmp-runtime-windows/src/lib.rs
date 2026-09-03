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
    use vmp_vm::bytecode::{encode, Instruction, Program, Register, Width};

    #[test]
    fn raw_gate_executes_qword_add_and_returns_to_native_caller() {
        let container = encode(&Program::new(
            0,
            vec![
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
        assert_eq!(code, [0x11, 8, 1, 0x11, 8, 2, 0x20, 8, 0x12, 8, 0, 0x01]);

        let execution = execute_raw_gate(code, 0xffff_ffff_ffff_fffe, 5)
            .expect("valid bytecode must return to the native caller");

        assert_eq!(execution.rax, 3);
        assert_eq!(execution.rflags & 0x8d5, 0x15);
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
