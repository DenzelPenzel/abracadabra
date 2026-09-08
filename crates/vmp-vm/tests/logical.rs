use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::{BranchKind, FieldSpan, Instruction, OperandRef};
use vmp_types::{Architecture, Rva};
use vmp_vm::{
    logical::{lower_instruction, Command, LogicalError},
    operand::{Register, Width},
    stack::{Instruction as Stack, Machine, Output},
};

const REGISTERS: [(u8, Register); 15] = [
    (0, Register::Rax),
    (1, Register::Rcx),
    (2, Register::Rdx),
    (3, Register::Rbx),
    (5, Register::Rbp),
    (6, Register::Rsi),
    (7, Register::Rdi),
    (8, Register::R8),
    (9, Register::R9),
    (10, Register::R10),
    (11, Register::R11),
    (12, Register::R12),
    (13, Register::R13),
    (14, Register::R14),
    (15, Register::R15),
];

fn decoded(bytes: &[u8]) -> Instruction {
    let raw = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE).decode();
    Instruction::decoded(Rva(0x1000), raw, &bytes[..raw.len()])
}

fn push(register: Register) -> Command {
    Command::Stack(Stack::PushReg {
        width: Width::Qword,
        register,
    })
}

fn pop(register: Register) -> Command {
    Command::Stack(Stack::PopReg {
        width: Width::Qword,
        register,
    })
}

// These are C++ logical field tuples, not a wire encoding
// core/intel.cc:9958-9961,9993-10010 and classic_logical.txt:41-49
fn fixture_tuple(command: Command) -> [u8; 6] {
    let id = |register| {
        REGISTERS
            .iter()
            .find(|(_, r)| *r == register)
            .expect("GPR")
            .0
    };
    match command {
        Command::Stack(Stack::PushReg {
            width: Width::Qword,
            register,
        }) => [1, 2, 3, id(register), 0, 0],
        Command::Stack(Stack::PopReg {
            width: Width::Qword,
            register,
        }) => [2, 2, 3, id(register), 0, 0],
        Command::Stack(Stack::PopFlags) => [2, 2, 3, 16, 0, 0],
        Command::Add {
            width: Width::Qword,
        } => [4, 0, 3, 0, 0, 0],
        other => panic!("outside fixture: {other:?}"),
    }
}

#[test]
fn exact_cpp_fixtures_retain_single_source_ownership() {
    for (bytes, expected) in [
        (
            &[0x48, 0x89, 0xc8][..],
            &[[1, 2, 3, 1, 0, 0], [2, 2, 3, 0, 0, 0]][..],
        ),
        (
            &[0x48, 0x01, 0xd0][..],
            &[
                [1, 2, 3, 2, 0, 0],
                [1, 2, 3, 0, 0, 0],
                [4, 0, 3, 0, 0, 0],
                [2, 2, 3, 16, 0, 0],
                [2, 2, 3, 0, 0, 0],
            ][..],
        ),
    ] {
        let source = decoded(bytes);
        let logical = lower_instruction(Architecture::X64, &source).expect("supported fixture");
        assert!(std::ptr::eq(logical.source(), &source));
        assert_eq!(logical.source().rva(), Some(Rva(0x1000)));
        assert_eq!(
            logical
                .commands()
                .iter()
                .copied()
                .map(fixture_tuple)
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn all_gpr_pairs_and_both_native_opcode_directions() {
    // CompileOperand's ordinary GPR path is core/intel.cc:9674-9687
    // This tests body commands only, without frame-register shadow bookkeeping
    for (destination_id, destination) in REGISTERS {
        for (source_id, source) in REGISTERS {
            for (opcode, reverse, add) in [
                (0x89, false, false),
                (0x8b, true, false),
                (0x01, false, true),
                (0x03, true, true),
            ] {
                let (reg, rm) = if reverse {
                    (destination_id, source_id)
                } else {
                    (source_id, destination_id)
                };
                let bytes = [
                    0x48 | ((reg >> 3) << 2) | (rm >> 3),
                    opcode,
                    0xc0 | ((reg & 7) << 3) | (rm & 7),
                ];
                let native = decoded(&bytes);
                let logical = lower_instruction(Architecture::X64, &native).expect("GPR pair");
                let expected = if add {
                    vec![
                        push(source),
                        push(destination),
                        Command::Add {
                            width: Width::Qword,
                        },
                        Command::Stack(Stack::PopFlags),
                        pop(destination),
                    ]
                } else {
                    vec![push(source), pop(destination)]
                };
                assert_eq!(logical.commands(), expected, "{bytes:02x?}");
            }
        }
    }
}

// Caller-driven test harness only: there is no production command execution loop
fn apply(commands: &[Command], machine: &mut Machine, flags: &mut u64) {
    for command in commands {
        match *command {
            Command::Stack(instruction) => {
                match machine.step(instruction).expect("stack operation") {
                    Output::None => {}
                    Output::FlagsWord(word) => *flags = word,
                }
            }
            Command::Add { width } => machine.add(width, *flags).expect("ADD"),
        }
    }
}

#[test]
fn fixture_sequence_matches_literal_results_flags_and_preserves_older_bytes() {
    let mov = decoded(&[0x48, 0x89, 0xc8]);
    let add = decoded(&[0x48, 0x01, 0xd0]);
    // Independently pinned x64 arithmetic cases, not producer/consumer round trips
    // High/reserved bits deliberately remain raw logical data, never architectural POPF
    for (lhs, rhs, result, expected_flags) in [
        (0, 0, 0, 0x8000_0000_0000_0246),
        (1, 2, 3, 0x8000_0000_0000_0206),
        (u64::MAX, 1, 0, 0x8000_0000_0000_0257),
        (
            0x7fff_ffff_ffff_ffff,
            1,
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0a96,
        ),
        (0xf, 1, 0x10, 0x8000_0000_0000_0212),
        (
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0000,
            0,
            0x8000_0000_0000_0a47,
        ),
        (
            0x1234_5678_9abc_def0,
            0xfedc_ba98_7654_3210,
            0x1111_1111_1111_1100,
            0x8000_0000_0000_0207,
        ),
    ] {
        let mut machine = Machine::new(24);
        for (id, register) in REGISTERS {
            machine.set_register(register, 0xabc0 + u64::from(id));
        }
        machine.set_register(Register::Rcx, lhs);
        machine.set_register(Register::Rdx, rhs);
        let before = REGISTERS.map(|(_, register)| machine.register(register));
        let sentinel = 0x1234_5678_9abc_def0u64;
        machine
            .step(Stack::PushImm {
                width: Width::Qword,
                value: sentinel,
            })
            .expect("return address");
        let mut flags = 0x8000_0000_0000_0202;
        apply(
            lower_instruction(Architecture::X64, &mov)
                .expect("MOV")
                .commands(),
            &mut machine,
            &mut flags,
        );
        assert_eq!(machine.register(Register::Rax), lhs);
        assert_eq!(flags, 0x8000_0000_0000_0202);
        apply(
            lower_instruction(Architecture::X64, &add)
                .expect("ADD")
                .commands(),
            &mut machine,
            &mut flags,
        );
        assert_eq!(machine.register(Register::Rax), result);
        assert_eq!(flags, expected_flags);
        assert_eq!(
            machine.stack_bytes().collect::<Vec<_>>(),
            sentinel.to_le_bytes()
        );
        for (index, (_, register)) in REGISTERS.iter().enumerate().skip(1) {
            assert_eq!(machine.register(*register), before[index]);
        }
    }
}

#[test]
fn unsupported_boundaries_fail_closed() {
    let valid = decoded(&[0x48, 0x89, 0xc8]);
    assert_eq!(
        lower_instruction(Architecture::X86, &valid).expect_err("architecture"),
        LogicalError::UnsupportedArchitecture {
            architecture: Architecture::X86
        }
    );
    for bytes in [
        &[0x89, 0xc8][..],
        &[0x66, 0x89, 0xc8],
        &[0x88, 0xc8],
        &[0x01, 0xd0],
        &[0x66, 0x01, 0xd0],
        &[0x00, 0xd0],
        &[0x48, 0x89, 0xe0],
        &[0x48, 0x89, 0xc4],
        &[0x48, 0x01, 0xe0],
        &[0x48, 0x01, 0xc4],
        &[0x48, 0x8b, 0x00],
        &[0x48, 0x89, 0x00],
        &[0x48, 0x03, 0x00],
        &[0x48, 0x01, 0x00],
        &[0x48, 0xc7, 0xc0, 1, 0, 0, 0],
        &[0x48, 0x83, 0xc0, 1],
        &[0xf3, 0x48, 0x89, 0xc8],
        &[0xf2, 0x48, 0x01, 0xd0],
        &[0x66, 0x48, 0x89, 0xc8],
        &[0x67, 0x48, 0x01, 0xd0],
        &[0x64, 0x48, 0x89, 0xc8],
        &[0xf0, 0x48, 0x01, 0xd0],
        &[0x48, 0x48, 0x89, 0xc8],
        &[0xc3],
        &[0xeb, 0],
        &[0x74, 0],
        &[0x90],
        &[0x0f, 0x0b],
    ] {
        let source = decoded(bytes);
        assert!(
            matches!(
                lower_instruction(Architecture::X64, &source),
                Err(LogicalError::UnsupportedInstruction)
            ),
            "{bytes:02x?}"
        );
    }
    let mut linked = valid.clone();
    linked.push_ref(OperandRef::Branch {
        target: Rva(0x2000),
        kind: BranchKind::Jump,
        field: FieldSpan::new(1, 1),
    });
    assert_eq!(
        lower_instruction(Architecture::X64, &linked).expect_err("link metadata"),
        LogicalError::UnsupportedInstruction
    );
}
