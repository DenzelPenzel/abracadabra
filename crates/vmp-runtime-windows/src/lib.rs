//! Embedded Windows x64 VM runtime.

#[cfg(target_arch = "x86_64")]
mod runtime_x64;

#[cfg(target_arch = "x86_64")]
pub use runtime_x64::{execute_raw_gate, RuntimeExecution, RuntimeTrap, MAX_RUNTIME_CODE_SIZE};

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
}
