//! Versioned VM bytecode model and deterministic v1 codec.

use thiserror::Error;

const MAGIC: &[u8; 4] = b"VMPB";
const VERSION: u16 = 1;
pub(crate) const HEADER_SIZE: usize = 16;

/// Maximum accepted or emitted v1 container size.
pub const MAX_CONTAINER_SIZE: usize = 1024 * 1024;
/// Maximum number of decoded v1 instructions.
pub const MAX_INSTRUCTIONS: usize = 65_536;

/// Operand width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Width {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

impl Width {
    fn from_byte(value: u8, code_offset: u32) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Byte),
            2 => Ok(Self::Word),
            4 => Ok(Self::Dword),
            8 => Ok(Self::Qword),
            _ => Err(DecodeError::InvalidWidth { code_offset, value }),
        }
    }

    pub(crate) fn byte_len(self) -> usize {
        self as usize
    }

    pub(crate) fn mask(self) -> u64 {
        match self {
            Self::Byte => u64::from(u8::MAX),
            Self::Word => u64::from(u16::MAX),
            Self::Dword => u64::from(u32::MAX),
            Self::Qword => u64::MAX,
        }
    }
}

/// Stable logical x64 GPR IDs. Native RSP (ID 4) is deliberately absent in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    pub(crate) fn id(self) -> u8 {
        match self {
            Self::Rax => 0,
            Self::Rcx => 1,
            Self::Rdx => 2,
            Self::Rbx => 3,
            Self::Rbp => 5,
            Self::Rsi => 6,
            Self::Rdi => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
            Self::R11 => 11,
            Self::R12 => 12,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
        }
    }

    fn from_id(value: u8, code_offset: u32) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Rax),
            1 => Ok(Self::Rcx),
            2 => Ok(Self::Rdx),
            3 => Ok(Self::Rbx),
            5 => Ok(Self::Rbp),
            6 => Ok(Self::Rsi),
            7 => Ok(Self::Rdi),
            8 => Ok(Self::R8),
            9 => Ok(Self::R9),
            10 => Ok(Self::R10),
            11 => Ok(Self::R11),
            12 => Ok(Self::R12),
            13 => Ok(Self::R13),
            14 => Ok(Self::R14),
            15 => Ok(Self::R15),
            _ => Err(DecodeError::InvalidRegister { code_offset, value }),
        }
    }
}

/// Canonical x86 condition-code nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Condition {
    O = 0,
    No = 1,
    B = 2,
    Ae = 3,
    E = 4,
    Ne = 5,
    Be = 6,
    A = 7,
    S = 8,
    Ns = 9,
    P = 10,
    Np = 11,
    L = 12,
    Ge = 13,
    Le = 14,
    G = 15,
}

impl Condition {
    fn from_byte(value: u8, code_offset: u32) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::O),
            1 => Ok(Self::No),
            2 => Ok(Self::B),
            3 => Ok(Self::Ae),
            4 => Ok(Self::E),
            5 => Ok(Self::Ne),
            6 => Ok(Self::Be),
            7 => Ok(Self::A),
            8 => Ok(Self::S),
            9 => Ok(Self::Ns),
            10 => Ok(Self::P),
            11 => Ok(Self::Np),
            12 => Ok(Self::L),
            13 => Ok(Self::Ge),
            14 => Ok(Self::Le),
            15 => Ok(Self::G),
            _ => Err(DecodeError::InvalidCondition { code_offset, value }),
        }
    }
}

/// One logical v1 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Ret,
    PushImm { width: Width, value: u64 },
    PushReg { width: Width, register: Register },
    PopReg { width: Width, register: Register },
    Drop(Width),
    Add(Width),
    Sub(Width),
    Xor(Width),
    And(Width),
    Jmp { target: u32 },
    Jcc { condition: Condition, target: u32 },
}

impl Instruction {
    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            Self::Ret => 1,
            Self::PushImm { width, .. } => 2 + width.byte_len(),
            Self::PushReg { .. } | Self::PopReg { .. } => 3,
            Self::Drop(_) | Self::Add(_) | Self::Sub(_) | Self::Xor(_) | Self::And(_) => 2,
            Self::Jmp { .. } => 5,
            Self::Jcc { .. } => 6,
        }
    }

    pub(crate) fn branch_target(&self) -> Option<u32> {
        match self {
            Self::Jmp { target } | Self::Jcc { target, .. } => Some(*target),
            _ => None,
        }
    }
}

/// Fully decoded v1 program. Branches and entry use code-relative byte offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    entry_offset: u32,
    instructions: Vec<Instruction>,
}

impl Program {
    pub fn new(entry_offset: u32, instructions: Vec<Instruction>) -> Self {
        Self {
            entry_offset,
            instructions,
        }
    }

    pub fn entry_offset(&self) -> u32 {
        self.entry_offset
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
}

/// Deterministic v1 encoding failure.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("v1 instruction count {count} exceeds {maximum}")]
    TooManyInstructions { count: usize, maximum: usize },
    #[error("v1 container size {size} exceeds {maximum}")]
    ContainerTooLarge { size: usize, maximum: usize },
    #[error("v1 code size arithmetic overflow")]
    SizeOverflow,
    #[error("immediate 0x{value:x} does not fit width {width:?}")]
    ImmediateOutOfRange { width: Width, value: u64 },
    #[error("entry offset 0x{entry_offset:08x} is not an instruction boundary")]
    EntryNotBoundary { entry_offset: u32 },
    #[error("branch at code offset 0x{code_offset:08x} targets non-boundary 0x{target:08x}")]
    BranchTargetNotBoundary { code_offset: u32, target: u32 },
    #[error("allocation failed while {context}")]
    Allocation { context: &'static str },
}

/// Fail-closed v1 decoding failure.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    #[error("v1 container size {size} exceeds {maximum}")]
    ContainerTooLarge { size: usize, maximum: usize },
    #[error("truncated v1 header: need {needed} bytes, have {actual}")]
    TruncatedHeader { needed: usize, actual: usize },
    #[error("invalid v1 magic")]
    BadMagic,
    #[error("unsupported bytecode version {version}")]
    UnsupportedVersion { version: u16 },
    #[error("unsupported v1 header size {size}")]
    UnsupportedHeaderSize { size: u16 },
    #[error("v1 declared-size arithmetic overflow")]
    SizeOverflow,
    #[error("v1 container length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error(
        "truncated instruction at code offset 0x{code_offset:08x}: need {needed} bytes, have {remaining}"
    )]
    TruncatedInstruction {
        code_offset: u32,
        needed: usize,
        remaining: usize,
    },
    #[error("unknown opcode 0x{opcode:02x} at code offset 0x{code_offset:08x}")]
    UnknownOpcode { code_offset: u32, opcode: u8 },
    #[error("invalid width {value} at code offset 0x{code_offset:08x}")]
    InvalidWidth { code_offset: u32, value: u8 },
    #[error("invalid register ID {value} at code offset 0x{code_offset:08x}")]
    InvalidRegister { code_offset: u32, value: u8 },
    #[error("invalid condition {value} at code offset 0x{code_offset:08x}")]
    InvalidCondition { code_offset: u32, value: u8 },
    #[error("v1 instruction count exceeds {maximum}")]
    TooManyInstructions { maximum: usize },
    #[error("entry offset 0x{entry_offset:08x} is not an instruction boundary")]
    EntryNotBoundary { entry_offset: u32 },
    #[error("branch at code offset 0x{code_offset:08x} targets non-boundary 0x{target:08x}")]
    BranchTargetNotBoundary { code_offset: u32, target: u32 },
    #[error("allocation failed while {context}")]
    Allocation { context: &'static str },
}

pub fn encode(program: &Program) -> Result<Vec<u8>, EncodeError> {
    if program.instructions.len() > MAX_INSTRUCTIONS {
        return Err(EncodeError::TooManyInstructions {
            count: program.instructions.len(),
            maximum: MAX_INSTRUCTIONS,
        });
    }

    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(program.instructions.len())
        .map_err(|_| EncodeError::Allocation {
            context: "retaining instruction boundaries",
        })?;
    let mut code_size = 0usize;
    for instruction in &program.instructions {
        offsets.push(u32::try_from(code_size).map_err(|_| EncodeError::SizeOverflow)?);
        code_size = code_size
            .checked_add(instruction.encoded_len())
            .ok_or(EncodeError::SizeOverflow)?;
        if let Instruction::PushImm { width, value } = instruction {
            if value & !width.mask() != 0 {
                return Err(EncodeError::ImmediateOutOfRange {
                    width: *width,
                    value: *value,
                });
            }
        }
    }
    let total_size = HEADER_SIZE
        .checked_add(code_size)
        .ok_or(EncodeError::SizeOverflow)?;
    if total_size > MAX_CONTAINER_SIZE {
        return Err(EncodeError::ContainerTooLarge {
            size: total_size,
            maximum: MAX_CONTAINER_SIZE,
        });
    }
    let code_size_u32 = u32::try_from(code_size).map_err(|_| EncodeError::SizeOverflow)?;
    validate_targets_for_encode(program, &offsets)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(total_size)
        .map_err(|_| EncodeError::Allocation {
            context: "retaining encoded bytecode",
        })?;
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    output.extend_from_slice(&code_size_u32.to_le_bytes());
    output.extend_from_slice(&program.entry_offset.to_le_bytes());
    for instruction in &program.instructions {
        encode_instruction(instruction, &mut output);
    }

    Ok(output)
}

fn validate_targets_for_encode(program: &Program, offsets: &[u32]) -> Result<(), EncodeError> {
    if offsets.binary_search(&program.entry_offset).is_err() {
        return Err(EncodeError::EntryNotBoundary {
            entry_offset: program.entry_offset,
        });
    }
    for (index, instruction) in program.instructions.iter().enumerate() {
        let Some(target) = instruction.branch_target() else {
            continue;
        };
        if offsets.binary_search(&target).is_err() {
            return Err(EncodeError::BranchTargetNotBoundary {
                code_offset: offsets[index],
                target,
            });
        }
    }
    Ok(())
}

fn encode_instruction(instruction: &Instruction, output: &mut Vec<u8>) {
    match instruction {
        Instruction::Ret => output.push(0x01),
        Instruction::PushImm { width, value } => {
            output.push(0x10);
            output.push(*width as u8);
            output.extend(value.to_le_bytes().into_iter().take(width.byte_len()));
        }
        Instruction::PushReg { width, register } => {
            output.extend_from_slice(&[0x11, *width as u8, register.id()]);
        }
        Instruction::PopReg { width, register } => {
            output.extend_from_slice(&[0x12, *width as u8, register.id()]);
        }
        Instruction::Drop(width) => output.extend_from_slice(&[0x13, *width as u8]),
        Instruction::Add(width) => output.extend_from_slice(&[0x20, *width as u8]),
        Instruction::Sub(width) => output.extend_from_slice(&[0x21, *width as u8]),
        Instruction::Xor(width) => output.extend_from_slice(&[0x22, *width as u8]),
        Instruction::And(width) => output.extend_from_slice(&[0x23, *width as u8]),
        Instruction::Jmp { target } => {
            output.push(0x30);
            output.extend_from_slice(&target.to_le_bytes());
        }
        Instruction::Jcc { condition, target } => {
            output.extend_from_slice(&[0x31, *condition as u8]);
            output.extend_from_slice(&target.to_le_bytes());
        }
    }
}

pub fn decode(input: &[u8]) -> Result<Program, DecodeError> {
    if input.len() > MAX_CONTAINER_SIZE {
        return Err(DecodeError::ContainerTooLarge {
            size: input.len(),
            maximum: MAX_CONTAINER_SIZE,
        });
    }
    if input.len() < HEADER_SIZE {
        return Err(DecodeError::TruncatedHeader {
            needed: HEADER_SIZE,
            actual: input.len(),
        });
    }
    if input.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(DecodeError::BadMagic);
    }
    let version = read_header_u16(input, 4)?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { version });
    }
    let header_size = read_header_u16(input, 6)?;
    if usize::from(header_size) != HEADER_SIZE {
        return Err(DecodeError::UnsupportedHeaderSize { size: header_size });
    }
    let code_size =
        usize::try_from(read_header_u32(input, 8)?).map_err(|_| DecodeError::SizeOverflow)?;
    let entry_offset = read_header_u32(input, 12)?;
    let declared = HEADER_SIZE
        .checked_add(code_size)
        .ok_or(DecodeError::SizeOverflow)?;
    if declared > MAX_CONTAINER_SIZE {
        return Err(DecodeError::ContainerTooLarge {
            size: declared,
            maximum: MAX_CONTAINER_SIZE,
        });
    }
    if declared != input.len() {
        return Err(DecodeError::LengthMismatch {
            declared,
            actual: input.len(),
        });
    }
    let code = input
        .get(HEADER_SIZE..declared)
        .ok_or(DecodeError::LengthMismatch {
            declared,
            actual: input.len(),
        })?;

    let mut cursor = 0usize;
    let mut offsets = Vec::new();
    let mut instructions = Vec::new();
    while cursor < code.len() {
        if instructions.len() == MAX_INSTRUCTIONS {
            return Err(DecodeError::TooManyInstructions {
                maximum: MAX_INSTRUCTIONS,
            });
        }
        offsets
            .try_reserve(1)
            .map_err(|_| DecodeError::Allocation {
                context: "retaining instruction boundaries",
            })?;
        instructions
            .try_reserve(1)
            .map_err(|_| DecodeError::Allocation {
                context: "retaining decoded instructions",
            })?;
        let instruction_offset = cursor;
        offsets.push(u32::try_from(cursor).map_err(|_| DecodeError::SizeOverflow)?);
        instructions.push(decode_instruction(code, &mut cursor, instruction_offset)?);
    }
    validate_targets_for_decode(entry_offset, &instructions, &offsets)?;
    Ok(Program::new(entry_offset, instructions))
}

fn decode_instruction(
    code: &[u8],
    cursor: &mut usize,
    instruction_offset: usize,
) -> Result<Instruction, DecodeError> {
    let opcode = take_byte(code, cursor, instruction_offset)?;
    let code_offset = u32::try_from(instruction_offset).map_err(|_| DecodeError::SizeOverflow)?;
    match opcode {
        0x01 => Ok(Instruction::Ret),
        0x10 => {
            let width = decode_width(code, cursor, instruction_offset, code_offset)?;
            let bytes = take(code, cursor, width.byte_len(), instruction_offset)?;
            let value = bytes.iter().enumerate().fold(0u64, |value, (shift, byte)| {
                value | (u64::from(*byte) << (shift * 8))
            });
            Ok(Instruction::PushImm { width, value })
        }
        0x11 | 0x12 => {
            let width = decode_width(code, cursor, instruction_offset, code_offset)?;
            let register =
                Register::from_id(take_byte(code, cursor, instruction_offset)?, code_offset)?;
            if opcode == 0x11 {
                Ok(Instruction::PushReg { width, register })
            } else {
                Ok(Instruction::PopReg { width, register })
            }
        }
        0x13 => Ok(Instruction::Drop(decode_width(
            code,
            cursor,
            instruction_offset,
            code_offset,
        )?)),
        0x20..=0x23 => {
            let width = decode_width(code, cursor, instruction_offset, code_offset)?;
            match opcode {
                0x20 => Ok(Instruction::Add(width)),
                0x21 => Ok(Instruction::Sub(width)),
                0x22 => Ok(Instruction::Xor(width)),
                _ => Ok(Instruction::And(width)),
            }
        }
        0x30 => Ok(Instruction::Jmp {
            target: decode_u32(code, cursor, instruction_offset)?,
        }),
        0x31 => {
            let condition =
                Condition::from_byte(take_byte(code, cursor, instruction_offset)?, code_offset)?;
            let target = decode_u32(code, cursor, instruction_offset)?;
            Ok(Instruction::Jcc { condition, target })
        }
        _ => Err(DecodeError::UnknownOpcode {
            code_offset,
            opcode,
        }),
    }
}

fn decode_width(
    code: &[u8],
    cursor: &mut usize,
    instruction_offset: usize,
    code_offset: u32,
) -> Result<Width, DecodeError> {
    Width::from_byte(take_byte(code, cursor, instruction_offset)?, code_offset)
}

fn take_byte(
    code: &[u8],
    cursor: &mut usize,
    instruction_offset: usize,
) -> Result<u8, DecodeError> {
    let bytes = take(code, cursor, 1, instruction_offset)?;
    let [value] = bytes else {
        return Err(DecodeError::TruncatedInstruction {
            code_offset: u32::try_from(instruction_offset)
                .map_err(|_| DecodeError::SizeOverflow)?,
            needed: 1,
            remaining: bytes.len(),
        });
    };
    Ok(*value)
}

fn decode_u32(
    code: &[u8],
    cursor: &mut usize,
    instruction_offset: usize,
) -> Result<u32, DecodeError> {
    let bytes = take(code, cursor, 4, instruction_offset)?;
    let [a, b, c, d] = bytes else {
        return Err(DecodeError::TruncatedInstruction {
            code_offset: u32::try_from(instruction_offset)
                .map_err(|_| DecodeError::SizeOverflow)?,
            needed: 4,
            remaining: bytes.len(),
        });
    };
    Ok(u32::from_le_bytes([*a, *b, *c, *d]))
}

fn take<'a>(
    code: &'a [u8],
    cursor: &mut usize,
    length: usize,
    instruction_offset: usize,
) -> Result<&'a [u8], DecodeError> {
    let remaining = code.len().saturating_sub(*cursor);
    let end = cursor
        .checked_add(length)
        .ok_or(DecodeError::SizeOverflow)?;
    let Some(bytes) = code.get(*cursor..end) else {
        return Err(DecodeError::TruncatedInstruction {
            code_offset: u32::try_from(instruction_offset)
                .map_err(|_| DecodeError::SizeOverflow)?,
            needed: end.saturating_sub(instruction_offset),
            remaining: code.len().saturating_sub(instruction_offset),
        });
    };
    *cursor = end;
    debug_assert!(bytes.len() <= remaining);
    Ok(bytes)
}

fn read_header_u16(input: &[u8], offset: usize) -> Result<u16, DecodeError> {
    let end = offset.checked_add(2).ok_or(DecodeError::SizeOverflow)?;
    let bytes = input.get(offset..end).ok_or(DecodeError::TruncatedHeader {
        needed: end,
        actual: input.len(),
    })?;
    let [a, b] = bytes else {
        return Err(DecodeError::TruncatedHeader {
            needed: end,
            actual: input.len(),
        });
    };
    Ok(u16::from_le_bytes([*a, *b]))
}

fn read_header_u32(input: &[u8], offset: usize) -> Result<u32, DecodeError> {
    let end = offset.checked_add(4).ok_or(DecodeError::SizeOverflow)?;
    let bytes = input.get(offset..end).ok_or(DecodeError::TruncatedHeader {
        needed: end,
        actual: input.len(),
    })?;
    let [a, b, c, d] = bytes else {
        return Err(DecodeError::TruncatedHeader {
            needed: end,
            actual: input.len(),
        });
    };
    Ok(u32::from_le_bytes([*a, *b, *c, *d]))
}

fn validate_targets_for_decode(
    entry_offset: u32,
    instructions: &[Instruction],
    offsets: &[u32],
) -> Result<(), DecodeError> {
    if offsets.binary_search(&entry_offset).is_err() {
        return Err(DecodeError::EntryNotBoundary { entry_offset });
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let Some(target) = instruction.branch_target() else {
            continue;
        };
        if offsets.binary_search(&target).is_err() {
            return Err(DecodeError::BranchTargetNotBoundary {
                code_offset: offsets[index],
                target,
            });
        }
    }
    Ok(())
}
