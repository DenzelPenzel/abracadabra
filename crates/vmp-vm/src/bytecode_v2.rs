//! Explicit v2 wire codec with immutable, fully validated programs

use crate::bytecode::{Condition, Register, Width, MAX_CONTAINER_SIZE, MAX_INSTRUCTIONS};
use crate::stack_v2::Instruction as Stack;
use thiserror::Error;

pub const V2_HEADER_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Stack(Stack),
    Ret,
    Jmp { target: u32 },
    Jcc { condition: Condition, target: u32 },
}

impl Instruction {
    fn encoded_len(self) -> usize {
        match self {
            Self::Ret | Self::Stack(Stack::PopFlags) => 1,
            Self::Stack(Stack::PushImm { width, .. }) => 2 + width.byte_len(),
            Self::Stack(Stack::PushReg { .. } | Stack::PopReg { .. }) => 3,
            Self::Stack(Stack::Drop { .. }) => 2,
            Self::Jmp { .. } => 5,
            Self::Jcc { .. } => 6,
        }
    }
}

/// Constructed only through complete validation; no mutable instruction access
#[derive(Debug, PartialEq, Eq)]
pub struct Program {
    entry_offset: u32,
    instructions: Vec<Instruction>,
    offsets: Vec<u32>,
    code_size: u32,
}

impl Program {
    pub fn new(entry_offset: u32, instructions: Vec<Instruction>) -> Result<Self, Error> {
        if instructions.len() > MAX_INSTRUCTIONS {
            return Err(Error::TooManyInstructions);
        }
        let mut size = 0usize;
        for instruction in &instructions {
            if let Instruction::Stack(Stack::PushImm { width, value }) = instruction {
                if value & !width.mask() != 0 {
                    return Err(Error::ImmediateOutOfRange {
                        width: *width,
                        value: *value,
                    });
                }
            }
            size = size
                .checked_add(instruction.encoded_len())
                .ok_or(Error::SizeOverflow)?;
        }
        if size
            .checked_add(V2_HEADER_SIZE)
            .ok_or(Error::SizeOverflow)?
            > MAX_CONTAINER_SIZE
        {
            return Err(Error::ContainerTooLarge);
        }
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(instructions.len())
            .map_err(|_| Error::Allocation)?;
        let mut offset = 0u32;
        for instruction in &instructions {
            offsets.push(offset);
            offset = offset
                .checked_add(
                    u32::try_from(instruction.encoded_len()).map_err(|_| Error::SizeOverflow)?,
                )
                .ok_or(Error::SizeOverflow)?;
        }
        if offsets.binary_search(&entry_offset).is_err() {
            return Err(Error::EntryNotBoundary { entry_offset });
        }
        for (instruction, code_offset) in instructions.iter().zip(&offsets) {
            match instruction {
                Instruction::Jmp { target } | Instruction::Jcc { target, .. } => {
                    if offsets.binary_search(target).is_err() {
                        return Err(Error::BranchTargetNotBoundary {
                            code_offset: *code_offset,
                            target: *target,
                        });
                    }
                }
                Instruction::Ret | Instruction::Stack(_) => {}
            }
        }
        Ok(Self {
            entry_offset,
            instructions,
            offsets,
            code_size: offset,
        })
    }
    pub fn entry_offset(&self) -> u32 {
        self.entry_offset
    }
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
    pub(crate) fn offsets(&self) -> &[u32] {
        &self.offsets
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("v2 container exceeds 1 MiB")]
    ContainerTooLarge,
    #[error("v2 instruction count exceeds 65536")]
    TooManyInstructions,
    #[error("v2 size arithmetic overflow")]
    SizeOverflow,
    #[error("v2 allocation failed")]
    Allocation,
    #[error("truncated v2 header")]
    TruncatedHeader,
    #[error("invalid v2 magic")]
    BadMagic,
    #[error("unsupported bytecode version {version}")]
    UnsupportedVersion { version: u16 },
    #[error("unsupported v2 header size {size}")]
    UnsupportedHeaderSize { size: u16 },
    #[error("v2 declared length differs from actual length")]
    LengthMismatch,
    #[error("truncated instruction at {code_offset}")]
    TruncatedInstruction { code_offset: u32 },
    #[error("unknown opcode {opcode:#x} at {code_offset}")]
    UnknownOpcode { code_offset: u32, opcode: u8 },
    #[error("invalid width {value} at {code_offset}")]
    InvalidWidth { code_offset: u32, value: u8 },
    #[error("invalid register {value} at {code_offset}")]
    InvalidRegister { code_offset: u32, value: u8 },
    #[error("invalid condition {value} at {code_offset}")]
    InvalidCondition { code_offset: u32, value: u8 },
    #[error("immediate {value:#x} exceeds {width:?}")]
    ImmediateOutOfRange { width: Width, value: u64 },
    #[error("entry {entry_offset} is not an instruction boundary")]
    EntryNotBoundary { entry_offset: u32 },
    #[error("branch at {code_offset} targets non-boundary {target}")]
    BranchTargetNotBoundary { code_offset: u32, target: u32 },
}

pub fn encode(program: &Program) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(V2_HEADER_SIZE + program.code_size as usize)
        .map_err(|_| Error::Allocation)?;
    out.extend_from_slice(b"VMPB\x02\x00\x10\x00");
    out.extend_from_slice(&program.code_size.to_le_bytes());
    out.extend_from_slice(&program.entry_offset.to_le_bytes());
    for instruction in &program.instructions {
        match *instruction {
            Instruction::Ret => out.push(1),
            Instruction::Stack(stack) => match stack {
                Stack::PushImm { width, value } => {
                    out.extend_from_slice(&[0x10, width as u8]);
                    out.extend_from_slice(&value.to_le_bytes()[..width.byte_len()]);
                }
                Stack::PushReg { width, register } => {
                    out.extend_from_slice(&[0x11, width as u8, register.id()])
                }
                Stack::PopReg { width, register } => {
                    out.extend_from_slice(&[0x12, width as u8, register.id()])
                }
                Stack::Drop { width } => out.extend_from_slice(&[0x13, width as u8]),
                Stack::PopFlags => out.push(0x14),
            },
            Instruction::Jmp { target } => {
                out.push(0x30);
                out.extend_from_slice(&target.to_le_bytes());
            }
            Instruction::Jcc { condition, target } => {
                out.extend_from_slice(&[0x31, condition as u8]);
                out.extend_from_slice(&target.to_le_bytes());
            }
        }
    }
    Ok(out)
}

pub fn decode(input: &[u8]) -> Result<Program, Error> {
    if input.len() > MAX_CONTAINER_SIZE {
        return Err(Error::ContainerTooLarge);
    }
    if input.len() < V2_HEADER_SIZE {
        return Err(Error::TruncatedHeader);
    }
    if &input[..4] != b"VMPB" {
        return Err(Error::BadMagic);
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != 2 {
        return Err(Error::UnsupportedVersion { version });
    }
    let size = u16::from_le_bytes([input[6], input[7]]);
    if size != 16 {
        return Err(Error::UnsupportedHeaderSize { size });
    }
    let code_size = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let declared = usize::try_from(code_size)
        .map_err(|_| Error::SizeOverflow)?
        .checked_add(V2_HEADER_SIZE)
        .ok_or(Error::SizeOverflow)?;
    if declared > MAX_CONTAINER_SIZE {
        return Err(Error::ContainerTooLarge);
    }
    if declared != input.len() {
        return Err(Error::LengthMismatch);
    }
    let entry = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);
    let mut reader = Reader {
        code: &input[V2_HEADER_SIZE..],
        cursor: 0,
        start: 0,
    };
    let mut instructions = Vec::new();
    while reader.cursor < reader.code.len() {
        if instructions.len() == MAX_INSTRUCTIONS {
            return Err(Error::TooManyInstructions);
        }
        reader.start = reader.cursor as u32;
        let opcode = reader.byte()?;
        let instruction = match opcode {
            1 => Instruction::Ret,
            0x10 => {
                let width = reader.width()?;
                let bytes = reader.take(width.byte_len())?;
                let mut raw = [0; 8];
                raw[..bytes.len()].copy_from_slice(bytes);
                Instruction::Stack(Stack::PushImm {
                    width,
                    value: u64::from_le_bytes(raw),
                })
            }
            0x11 | 0x12 => {
                let width = reader.width()?;
                let register = reader.register()?;
                Instruction::Stack(if opcode == 0x11 {
                    Stack::PushReg { width, register }
                } else {
                    Stack::PopReg { width, register }
                })
            }
            0x13 => Instruction::Stack(Stack::Drop {
                width: reader.width()?,
            }),
            0x14 => Instruction::Stack(Stack::PopFlags),
            0x30 => Instruction::Jmp {
                target: reader.u32()?,
            },
            0x31 => {
                let condition = reader.condition()?;
                Instruction::Jcc {
                    condition,
                    target: reader.u32()?,
                }
            }
            _ => {
                return Err(Error::UnknownOpcode {
                    code_offset: reader.start,
                    opcode,
                })
            }
        };
        instructions.try_reserve(1).map_err(|_| Error::Allocation)?;
        instructions.push(instruction);
    }
    Program::new(entry, instructions)
}

struct Reader<'a> {
    code: &'a [u8],
    cursor: usize,
    start: u32,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.cursor.checked_add(count).ok_or(Error::SizeOverflow)?;
        let bytes = self
            .code
            .get(self.cursor..end)
            .ok_or(Error::TruncatedInstruction {
                code_offset: self.start,
            })?;
        self.cursor = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn width(&mut self) -> Result<Width, Error> {
        let value = self.byte()?;
        Width::from_byte(value, self.start).map_err(|_| Error::InvalidWidth {
            code_offset: self.start,
            value,
        })
    }
    fn register(&mut self) -> Result<Register, Error> {
        let value = self.byte()?;
        Register::from_id(value, self.start).map_err(|_| Error::InvalidRegister {
            code_offset: self.start,
            value,
        })
    }
    fn condition(&mut self) -> Result<Condition, Error> {
        let value = self.byte()?;
        Condition::from_byte(value, self.start).map_err(|_| Error::InvalidCondition {
            code_offset: self.start,
            value,
        })
    }
}
