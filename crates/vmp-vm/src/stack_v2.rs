//! Stack-only host execution over raw bytes, without a wire decoder or native execution
//!
//! Flags are transported as raw words, not applied to architectural flags or definedness

use crate::bytecode::{Register, Width};
use thiserror::Error;

/// Logical stack operations independent of their wire encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    PushImm {
        width: Width,
        value: u64,
    },
    PushReg {
        width: Width,
        register: Register,
    },
    PopReg {
        width: Width,
        register: Register,
    },
    Drop {
        width: Width,
    },
    /// Consumes a qword and returns it without POPF normalization or definedness claims
    PopFlags,
}

/// Output of one stack operation, separate from register and stack state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    None,
    FlagsWord(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackError {
    #[error("stack underflow: need {needed} bytes, have {available}")]
    Underflow { needed: usize, available: usize },
    #[error("stack byte budget exceeded: need {required}, limit {limit}")]
    Budget { required: usize, limit: usize },
    #[error("stack size overflow")]
    SizeOverflow,
    #[error("stack allocation failed")]
    Allocation,
    #[error("immediate {value:#x} exceeds {width:?} width")]
    ImmediateTooWide { width: Width, value: u64 },
}

/// Caller-driven stack execution with an explicit live-byte budget and no implicit flags state
///
/// This is not a complete program executor: there is no PC, branch, RET or arithmetic
/// Each call executes one bounded primitive; no v1 program is accepted or converted
#[derive(Debug)]
pub struct Machine {
    registers: [u64; 16],
    stack: ByteStack,
}

impl Machine {
    /// Starts with zeroed registers and an empty stack, without preallocating the budget
    pub fn new(max_stack_bytes: usize) -> Self {
        Self {
            registers: [0; 16],
            stack: ByteStack {
                bytes: Vec::new(),
                budget: max_stack_bytes,
            },
        }
    }

    pub fn register(&self, register: Register) -> u64 {
        self.registers[usize::from(register.id())]
    }

    pub fn set_register(&mut self, register: Register, value: u64) {
        self.registers[usize::from(register.id())] = value;
    }

    /// Live bytes in increasing logical address order, starting at the downward-growing SP
    pub fn stack_bytes(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.stack.bytes.iter().rev().copied()
    }

    /// Executes one primitive; any error preserves live bytes and all registers
    pub fn step(&mut self, instruction: Instruction) -> Result<Output, StackError> {
        match instruction {
            Instruction::PushImm { width, value } => {
                if value & !width.mask() != 0 {
                    return Err(StackError::ImmediateTooWide { width, value });
                }
                self.stack.push(width, value)?;
            }
            Instruction::PushReg { width, register } => {
                self.stack
                    .push(width, self.register(register) & width.mask())?;
            }
            Instruction::PopReg { width, register } => {
                let value = self.stack.pop(width)?;
                let updated = match width {
                    Width::Byte | Width::Word => (self.register(register) & !width.mask()) | value,
                    Width::Dword | Width::Qword => value,
                };
                self.set_register(register, updated);
            }
            Instruction::Drop { width } => {
                self.stack.pop(width)?;
            }
            Instruction::PopFlags => return self.stack.pop(Width::Qword).map(Output::FlagsWord),
        }
        Ok(Output::None)
    }
}

// Reverse address order keeps the logical SP at the vector end across reallocations
#[derive(Debug)]
struct ByteStack {
    bytes: Vec<u8>,
    budget: usize,
}

impl ByteStack {
    fn push(&mut self, width: Width, value: u64) -> Result<(), StackError> {
        self.push_with_reserve(width, value, |bytes, additional| {
            bytes
                .try_reserve(additional)
                .map_err(|_| StackError::Allocation)
        })
    }

    fn push_with_reserve(
        &mut self,
        width: Width,
        value: u64,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), StackError>,
    ) -> Result<(), StackError> {
        let storage = width.byte_len().max(2);
        required_len(self.bytes.len(), storage, self.budget)?;
        reserve(&mut self.bytes, storage)?;
        let raw = (value & width.mask()).to_le_bytes();
        self.bytes.extend(raw[..storage].iter().rev().copied());
        Ok(())
    }

    fn pop(&mut self, width: Width) -> Result<u64, StackError> {
        let storage = width.byte_len().max(2);
        let available = self.bytes.len();
        let remaining = available
            .checked_sub(storage)
            .ok_or(StackError::Underflow {
                needed: storage,
                available,
            })?;
        let mut raw = [0; 8];
        for (destination, source) in raw[..width.byte_len()]
            .iter_mut()
            .zip(self.bytes[remaining..].iter().rev())
        {
            *destination = *source;
        }
        self.bytes.truncate(remaining);
        Ok(u64::from_le_bytes(raw))
    }
}

fn required_len(live: usize, additional: usize, budget: usize) -> Result<usize, StackError> {
    let required = live
        .checked_add(additional)
        .ok_or(StackError::SizeOverflow)?;
    if required > budget {
        return Err(StackError::Budget {
            required,
            limit: budget,
        });
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_overflow_is_typed_before_allocation() {
        assert_eq!(
            required_len(usize::MAX, 2, usize::MAX),
            Err(StackError::SizeOverflow)
        );
    }

    #[test]
    fn failed_reservation_preserves_live_bytes() {
        let mut stack = ByteStack {
            bytes: vec![0x22, 0x11],
            budget: 8,
        };
        let result =
            stack.push_with_reserve(Width::Word, 0x4433, |_, _| Err(StackError::Allocation));
        assert_eq!(result, Err(StackError::Allocation));
        assert_eq!(stack.bytes, [0x22, 0x11]);
    }
}
