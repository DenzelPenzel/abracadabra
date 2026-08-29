use vmp_vm::bytecode::{
    decode, encode, Condition, DecodeError, EncodeError, Instruction, Program, Register, Width,
    MAX_CONTAINER_SIZE, MAX_INSTRUCTIONS,
};

fn container(code: &[u8], entry_offset: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + code.len());
    bytes.extend_from_slice(b"VMPB");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&16u16.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(code.len())
            .expect("test code size fits the header")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&entry_offset.to_le_bytes());
    bytes.extend_from_slice(code);
    bytes
}

#[test]
fn v1_golden_program_is_byte_exact_and_decodes() {
    let program = Program::new(
        0,
        vec![
            Instruction::PushReg {
                width: Width::Dword,
                register: Register::Rcx,
            },
            Instruction::PushImm {
                width: Width::Dword,
                value: 7,
            },
            Instruction::Add(Width::Dword),
            Instruction::PushImm {
                width: Width::Dword,
                value: 3,
            },
            Instruction::Sub(Width::Dword),
            Instruction::PushImm {
                width: Width::Dword,
                value: 0xff,
            },
            Instruction::Xor(Width::Dword),
            Instruction::PopReg {
                width: Width::Dword,
                register: Register::Rax,
            },
            Instruction::Jcc {
                condition: Condition::Ne,
                target: 41,
            },
            Instruction::Jmp { target: 41 },
            Instruction::Ret,
        ],
    );
    let expected = [
        0x56, 0x4d, 0x50, 0x42, 0x01, 0x00, 0x10, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x11, 0x04, 0x01, 0x10, 0x04, 0x07, 0x00, 0x00, 0x00, 0x20, 0x04, 0x10, 0x04, 0x03,
        0x00, 0x00, 0x00, 0x21, 0x04, 0x10, 0x04, 0xff, 0x00, 0x00, 0x00, 0x22, 0x04, 0x12, 0x04,
        0x00, 0x31, 0x05, 0x29, 0x00, 0x00, 0x00, 0x30, 0x29, 0x00, 0x00, 0x00, 0x01,
    ];

    assert_eq!(
        encode(&program).expect("golden program must encode"),
        expected
    );
    assert_eq!(
        decode(&expected).expect("golden bytes must decode"),
        program
    );
}

#[test]
fn drop_has_an_independently_pinned_wire_encoding() {
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
    let expected = [
        0x56, 0x4d, 0x50, 0x42, 0x01, 0x00, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x02, 0x34, 0x12, 0x13, 0x02, 0x01,
    ];

    assert_eq!(encode(&program).expect("drop must encode"), expected);
    assert_eq!(
        decode(&expected).expect("physical drop must decode"),
        program
    );
}

#[test]
fn declared_container_limit_rejects_one_over_before_length_mismatch() {
    let mut input = [0u8; 16];
    input[0..4].copy_from_slice(b"VMPB");
    input[4..6].copy_from_slice(&1u16.to_le_bytes());
    input[6..8].copy_from_slice(&16u16.to_le_bytes());
    let code_size =
        u32::try_from(MAX_CONTAINER_SIZE - 16 + 1).expect("the v1 limit fits the u32 header field");
    input[8..12].copy_from_slice(&code_size.to_le_bytes());

    assert_eq!(
        decode(&input),
        Err(DecodeError::ContainerTooLarge {
            size: MAX_CONTAINER_SIZE + 1,
            maximum: MAX_CONTAINER_SIZE,
        })
    );
}

#[test]
fn every_typed_width_register_and_condition_round_trips() {
    let widths = [Width::Byte, Width::Word, Width::Dword, Width::Qword];
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
    let mut instructions = Vec::new();
    for width in widths {
        instructions.push(Instruction::PushImm { width, value: 1 });
        instructions.push(Instruction::Drop(width));
        instructions.push(Instruction::Add(width));
        instructions.push(Instruction::Sub(width));
        instructions.push(Instruction::Xor(width));
        for register in registers {
            instructions.push(Instruction::PushReg { width, register });
            instructions.push(Instruction::PopReg { width, register });
        }
    }
    for condition in conditions {
        instructions.push(Instruction::Jcc {
            condition,
            target: 0,
        });
    }
    instructions.push(Instruction::Jmp { target: 0 });
    instructions.push(Instruction::Ret);
    let program = Program::new(0, instructions);

    let encoded = encode(&program).expect("every typed v1 form must encode");
    assert_eq!(
        decode(&encoded).expect("every emitted v1 form must decode"),
        program
    );
}

#[test]
fn malformed_instruction_fields_are_typed_and_fail_closed() {
    assert!(matches!(
        decode(&container(&[0xff], 0)),
        Err(DecodeError::UnknownOpcode {
            code_offset: 0,
            opcode: 0xff
        })
    ));
    assert!(matches!(
        decode(&container(&[0x20, 3], 0)),
        Err(DecodeError::InvalidWidth {
            code_offset: 0,
            value: 3
        })
    ));
    assert_eq!(
        decode(&container(&[0x13, 3], 0)),
        Err(DecodeError::InvalidWidth {
            code_offset: 0,
            value: 3,
        })
    );
    assert_eq!(
        decode(&container(&[0x13], 0)),
        Err(DecodeError::TruncatedInstruction {
            code_offset: 0,
            needed: 2,
            remaining: 1,
        })
    );
    assert!(matches!(
        decode(&container(&[0x11, 4, 4], 0)),
        Err(DecodeError::InvalidRegister {
            code_offset: 0,
            value: 4
        })
    ));
    assert!(matches!(
        decode(&container(&[0x31, 16, 0, 0, 0, 0], 0)),
        Err(DecodeError::InvalidCondition {
            code_offset: 0,
            value: 16
        })
    ));
    assert_eq!(
        decode(&container(&[0x10, 8], 0)),
        Err(DecodeError::TruncatedInstruction {
            code_offset: 0,
            needed: 10,
            remaining: 2,
        })
    );
}

#[test]
fn entry_and_branch_targets_must_be_instruction_boundaries() {
    assert_eq!(
        decode(&container(&[0x10, 1, 7, 0x01], 1)),
        Err(DecodeError::EntryNotBoundary { entry_offset: 1 })
    );
    assert_eq!(
        decode(&container(&[0x30, 1, 0, 0, 0, 0x01], 0)),
        Err(DecodeError::BranchTargetNotBoundary {
            code_offset: 0,
            target: 1,
        })
    );

    assert_eq!(
        encode(&Program::new(1, vec![Instruction::Ret])),
        Err(EncodeError::EntryNotBoundary { entry_offset: 1 })
    );
    assert_eq!(
        encode(&Program::new(
            0,
            vec![Instruction::Jmp { target: 1 }, Instruction::Ret],
        )),
        Err(EncodeError::BranchTargetNotBoundary {
            code_offset: 0,
            target: 1,
        })
    );
    assert_eq!(
        encode(&Program::new(
            0,
            vec![Instruction::PushImm {
                width: Width::Byte,
                value: 0x100,
            }],
        )),
        Err(EncodeError::ImmediateOutOfRange {
            width: Width::Byte,
            value: 0x100,
        })
    );
}

#[test]
fn instruction_limit_accepts_exact_and_rejects_one_over() {
    let exact = vec![Instruction::Ret; MAX_INSTRUCTIONS];
    let encoded = encode(&Program::new(0, exact)).expect("exact instruction limit must encode");
    assert_eq!(
        decode(&encoded)
            .expect("exact instruction limit must decode")
            .instructions()
            .len(),
        MAX_INSTRUCTIONS
    );

    let one_over = vec![Instruction::Ret; MAX_INSTRUCTIONS + 1];
    assert_eq!(
        encode(&Program::new(0, one_over)),
        Err(EncodeError::TooManyInstructions {
            count: MAX_INSTRUCTIONS + 1,
            maximum: MAX_INSTRUCTIONS,
        })
    );

    let one_over_code = vec![0x01; MAX_INSTRUCTIONS + 1];
    assert_eq!(
        decode(&container(&one_over_code, 0)),
        Err(DecodeError::TooManyInstructions {
            maximum: MAX_INSTRUCTIONS,
        })
    );
}

#[test]
fn malformed_headers_and_empty_program_are_rejected_exactly() {
    assert_eq!(
        decode(&[]),
        Err(DecodeError::TruncatedHeader {
            needed: 16,
            actual: 0,
        })
    );

    let mut bad_magic = container(&[0x01], 0);
    bad_magic[0] = b'X';
    assert_eq!(decode(&bad_magic), Err(DecodeError::BadMagic));

    let mut bad_version = container(&[0x01], 0);
    bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        decode(&bad_version),
        Err(DecodeError::UnsupportedVersion { version: 2 })
    );

    let mut bad_header_size = container(&[0x01], 0);
    bad_header_size[6..8].copy_from_slice(&17u16.to_le_bytes());
    assert_eq!(
        decode(&bad_header_size),
        Err(DecodeError::UnsupportedHeaderSize { size: 17 })
    );

    let mut trailing = container(&[0x01], 0);
    trailing.push(0);
    assert_eq!(
        decode(&trailing),
        Err(DecodeError::LengthMismatch {
            declared: 17,
            actual: 18,
        })
    );

    assert_eq!(
        encode(&Program::new(0, Vec::new())),
        Err(EncodeError::EntryNotBoundary { entry_offset: 0 })
    );
    assert_eq!(
        decode(&container(&[], 0)),
        Err(DecodeError::EntryNotBoundary { entry_offset: 0 })
    );
}

#[test]
fn every_width_has_an_independently_pinned_wire_value() {
    let cases = [
        (Width::Byte, 1u8, 1usize),
        (Width::Word, 2, 2),
        (Width::Dword, 4, 4),
        (Width::Qword, 8, 8),
    ];
    for (width, wire_value, immediate_len) in cases {
        let program = Program::new(
            0,
            vec![Instruction::PushImm { width, value: 0 }, Instruction::Ret],
        );
        let mut expected_code = vec![0x10, wire_value];
        expected_code.extend(std::iter::repeat_n(0, immediate_len));
        expected_code.push(0x01);

        let encoded = encode(&program).expect("typed width must encode");
        assert_eq!(encoded.get(16..), Some(expected_code.as_slice()));
        assert_eq!(
            decode(&container(&expected_code, 0)).expect("pinned width bytes must decode"),
            program
        );
    }
}

#[test]
fn every_non_rsp_register_has_an_independently_pinned_wire_id() {
    let cases = [
        (Register::Rax, 0u8),
        (Register::Rcx, 1),
        (Register::Rdx, 2),
        (Register::Rbx, 3),
        (Register::Rbp, 5),
        (Register::Rsi, 6),
        (Register::Rdi, 7),
        (Register::R8, 8),
        (Register::R9, 9),
        (Register::R10, 10),
        (Register::R11, 11),
        (Register::R12, 12),
        (Register::R13, 13),
        (Register::R14, 14),
        (Register::R15, 15),
    ];
    for (register, wire_id) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::PushReg {
                    width: Width::Byte,
                    register,
                },
                Instruction::Ret,
            ],
        );
        let expected_code = [0x11, 1, wire_id, 0x01];

        let encoded = encode(&program).expect("typed register must encode");
        assert_eq!(encoded.get(16..), Some(expected_code.as_slice()));
        assert_eq!(
            decode(&container(&expected_code, 0)).expect("pinned register bytes must decode"),
            program
        );
    }
}

#[test]
fn every_condition_has_an_independently_pinned_wire_value() {
    let cases = [
        (Condition::O, 0u8),
        (Condition::No, 1),
        (Condition::B, 2),
        (Condition::Ae, 3),
        (Condition::E, 4),
        (Condition::Ne, 5),
        (Condition::Be, 6),
        (Condition::A, 7),
        (Condition::S, 8),
        (Condition::Ns, 9),
        (Condition::P, 10),
        (Condition::Np, 11),
        (Condition::L, 12),
        (Condition::Ge, 13),
        (Condition::Le, 14),
        (Condition::G, 15),
    ];
    for (condition, wire_value) in cases {
        let program = Program::new(
            0,
            vec![
                Instruction::Jcc {
                    condition,
                    target: 6,
                },
                Instruction::Ret,
            ],
        );
        let expected_code = [0x31, wire_value, 6, 0, 0, 0, 0x01];

        let encoded = encode(&program).expect("typed condition must encode");
        assert_eq!(encoded.get(16..), Some(expected_code.as_slice()));
        assert_eq!(
            decode(&container(&expected_code, 0)).expect("pinned condition bytes must decode"),
            program
        );
    }
}

#[test]
fn physical_container_limit_accepts_exact_and_rejects_one_over() {
    let exact = vec![0u8; MAX_CONTAINER_SIZE];
    assert_eq!(decode(&exact), Err(DecodeError::BadMagic));

    let one_over = vec![0u8; MAX_CONTAINER_SIZE + 1];
    assert_eq!(
        decode(&one_over),
        Err(DecodeError::ContainerTooLarge {
            size: MAX_CONTAINER_SIZE + 1,
            maximum: MAX_CONTAINER_SIZE,
        })
    );
}
