use vmp_vm::bytecode::{self, Condition, Register, Width, MAX_CONTAINER_SIZE, MAX_INSTRUCTIONS};
use vmp_vm::bytecode_v2::{decode, encode, Error, Instruction as I, Program};
use vmp_vm::stack_v2::Instruction as S;

fn wire(code: &[u8], entry: u32) -> Vec<u8> {
    let mut bytes = b"VMPB\x02\x00\x10\x00".to_vec();
    bytes.extend_from_slice(&(code.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&entry.to_le_bytes());
    bytes.extend_from_slice(code);
    bytes
}

#[test]
fn literal_wire_all_opcodes_and_version_separation() {
    let literal = [
        86, 77, 80, 66, 2, 0, 16, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0x10, 1, 0xa5, 0x11, 2, 15, 0x12, 4,
        0, 0x13, 8, 0x14, 0x30, 23, 0, 0, 0, 0x31, 15, 23, 0, 0, 0, 1,
    ];
    let expected = Program::new(
        0,
        vec![
            I::Stack(S::PushImm {
                width: Width::Byte,
                value: 0xa5,
            }),
            I::Stack(S::PushReg {
                width: Width::Word,
                register: Register::R15,
            }),
            I::Stack(S::PopReg {
                width: Width::Dword,
                register: Register::Rax,
            }),
            I::Stack(S::Drop {
                width: Width::Qword,
            }),
            I::Stack(S::PopFlags),
            I::Jmp { target: 23 },
            I::Jcc {
                condition: Condition::G,
                target: 23,
            },
            I::Ret,
        ],
    )
    .expect("valid");
    assert_eq!(decode(&literal).expect("decode"), expected);
    assert_eq!(encode(&expected).expect("encode"), literal);
    assert!(matches!(
        bytecode::decode(&literal),
        Err(bytecode::DecodeError::UnsupportedVersion { version: 2 })
    ));
    let mut v1 = literal;
    v1[4] = 1;
    assert!(matches!(
        decode(&v1),
        Err(Error::UnsupportedVersion { version: 1 })
    ));
}

#[test]
fn truncation_every_container_and_instruction_prefix() {
    let code = [
        0x10, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 8, 0, 0x12, 8, 1, 0x13, 8, 0x14, 0x30, 0, 0, 0, 0,
        0x31, 0, 0, 0, 0, 0, 1,
    ];
    let full = wire(&code, 0);
    for end in 0..full.len() {
        assert!(decode(&full[..end]).is_err(), "{end}");
    }
    for instruction in [
        &code[0..10],
        &code[10..13],
        &code[13..16],
        &code[16..18],
        &code[19..24],
        &code[24..30],
    ] {
        for end in 1..instruction.len() {
            assert!(matches!(
                decode(&wire(&instruction[..end], 0)),
                Err(Error::TruncatedInstruction { .. })
            ));
        }
    }
}

#[test]
fn invalid_fields_are_typed() {
    for code in [[0x11, 3, 0], [0x12, 0, 0], [0x13, 16, 0]] {
        assert!(matches!(
            decode(&wire(&code, 0)),
            Err(Error::InvalidWidth { .. })
        ));
    }
    for id in [4, 16, 255] {
        assert!(matches!(
            decode(&wire(&[0x11, 8, id], 0)),
            Err(Error::InvalidRegister { .. })
        ));
    }
    assert!(matches!(
        decode(&wire(&[0x31, 16, 0, 0, 0, 0], 0)),
        Err(Error::InvalidCondition { .. })
    ));
    for opcode in [0, 0x21, 0x22, 0x23, 0x24, 255] {
        assert!(matches!(
            decode(&wire(&[opcode], 0)),
            Err(Error::UnknownOpcode { .. })
        ));
    }
    let mut bytes = wire(&[1], 0);
    bytes[0] = 0;
    assert!(matches!(decode(&bytes), Err(Error::BadMagic)));
    bytes = wire(&[1], 0);
    bytes[6] = 17;
    assert!(matches!(
        decode(&bytes),
        Err(Error::UnsupportedHeaderSize { .. })
    ));
}

#[test]
fn length_and_count_bounds() {
    assert!(matches!(
        decode(&vec![0; MAX_CONTAINER_SIZE + 1]),
        Err(Error::ContainerTooLarge)
    ));
    let mut bytes = wire(&[1], 0);
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(decode(&bytes), Err(Error::ContainerTooLarge)));
    bytes = wire(&[1], 0);
    bytes.push(1);
    assert!(matches!(decode(&bytes), Err(Error::LengthMismatch)));
    assert!(decode(&wire(&vec![1; MAX_INSTRUCTIONS], 0)).is_ok());
    assert!(matches!(
        decode(&wire(&vec![1; MAX_INSTRUCTIONS + 1], 0)),
        Err(Error::TooManyInstructions)
    ));
    assert!(matches!(
        Program::new(0, vec![I::Ret; MAX_INSTRUCTIONS + 1]),
        Err(Error::TooManyInstructions)
    ));
}

#[test]
fn all_targets_and_manual_construction_are_validated() {
    for entry in [1, 5, u32::MAX] {
        assert!(matches!(
            decode(&wire(&[0x30, 0, 0, 0, 0], entry)),
            Err(Error::EntryNotBoundary { .. })
        ));
    }
    assert!(Program::new(0, vec![]).is_err());
    assert!(matches!(
        Program::new(
            0,
            vec![
                I::Ret,
                I::Stack(S::PushImm {
                    width: Width::Byte,
                    value: 256
                })
            ]
        ),
        Err(Error::ImmediateOutOfRange { .. })
    ));
    for branch in [
        I::Jmp { target: 2 },
        I::Jcc {
            condition: Condition::E,
            target: 2,
        },
    ] {
        assert!(matches!(
            Program::new(0, vec![I::Ret, branch]),
            Err(Error::BranchTargetNotBoundary { .. })
        ));
    }
    assert!(matches!(
        decode(&wire(&[1, 0x30, 2, 0, 0, 0], 0)),
        Err(Error::BranchTargetNotBoundary { .. })
    ));
    assert!(matches!(
        decode(&wire(&[0x31, 4, 2, 0, 0, 0, 1], 0)),
        Err(Error::BranchTargetNotBoundary { .. })
    ));
    assert!(Program::new(1, vec![I::Ret, I::Ret]).is_ok());
}
