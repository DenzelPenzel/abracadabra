//! Stack-only host execution over raw bytes, without a wire decoder or native execution
//!
//! Flags are transported as raw words, not applied to architectural flags or definedness

use crate::operand::{Register, Width};
use thiserror::Error;

/// Binary ALU operations sharing the two-operand, flags-above-result stack shape
///
/// Both operations consume the top two values and leave raw flags above the result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Nor,
}

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
    /// Pushes the pre-push SP in the host stack's budget-relative address space
    PushStackPointer,
    /// Replaces a qword address with a promoted value read from live stack bytes
    LoadStack {
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
    #[error("stack address {address:#x} does not cover a live {width:?} value")]
    StackAddress { address: u64, width: Width },
}

/// Caller-driven stack execution with an explicit live-byte budget and no implicit flags state
///
/// This is not a complete program executor: there is no PC, branch or RET
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

    /// Replaces rhs then lhs with a promoted result below a qword flags word
    ///
    /// Replaces CF/PF/AF/ZF/SF/OF and preserves other input bits as logical data
    /// Any error preserves live bytes and registers; no flags are applied here
    pub fn add(&mut self, width: Width, flags_bits: u64) -> Result<(), StackError> {
        self.binary(BinaryOp::Add, width, flags_bits)
    }

    /// NOR takes flags from AND of the inverted operands; its undefined AF is retained
    pub fn binary(
        &mut self,
        op: BinaryOp,
        width: Width,
        flags_bits: u64,
    ) -> Result<(), StackError> {
        self.stack
            .binary_with_reserve(op, width, flags_bits, |bytes, additional| {
                bytes
                    .try_reserve(additional)
                    .map_err(|_| StackError::Allocation)
            })
    }

    /// Replaces value then word-sized count with flags above the promoted result
    /// Undefined flag bits retain their input value; no flags are applied here
    pub fn shl(&mut self, width: Width, flags_bits: u64) -> Result<(), StackError> {
        self.stack
            .shl_with_reserve(width, flags_bits, |bytes, additional| {
                bytes
                    .try_reserve(additional)
                    .map_err(|_| StackError::Allocation)
            })
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
            Instruction::PushStackPointer => {
                let address = u64::try_from(self.stack.budget - self.stack.bytes.len())
                    .map_err(|_| StackError::SizeOverflow)?;
                self.stack.push(Width::Qword, address)?;
            }
            Instruction::LoadStack { width } => self.stack.load(width)?,
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
    fn load(&mut self, width: Width) -> Result<(), StackError> {
        let available = self.bytes.len();
        let remaining = available.checked_sub(8).ok_or(StackError::Underflow {
            needed: 8,
            available,
        })?;
        let address = self.bytes[remaining..]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let error = || StackError::StackAddress { address, width };
        let end = usize::try_from(address)
            .ok()
            .and_then(|address| self.budget.checked_sub(address))
            .filter(|&end| end <= available)
            .ok_or_else(error)?;
        let start = end.checked_sub(width.byte_len()).ok_or_else(error)?;
        let value = self.bytes[start..end]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        // The replacement is never larger than the consumed qword, so no allocation follows
        self.bytes.truncate(remaining);
        self.bytes.extend(
            value.to_le_bytes()[..width.byte_len().max(2)]
                .iter()
                .rev()
                .copied(),
        );
        Ok(())
    }

    fn shl_with_reserve(
        &mut self,
        width: Width,
        flags_bits: u64,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), StackError>,
    ) -> Result<(), StackError> {
        let storage = width.byte_len().max(2);
        let available = self.bytes.len();
        let remaining = available
            .checked_sub(storage + 2)
            .ok_or(StackError::Underflow {
                needed: storage + 2,
                available,
            })?;
        let required = required_len(remaining, storage + 8, self.budget)?;
        reserve(&mut self.bytes, required - available)?;
        let count =
            u32::from(self.bytes[remaining + 1]) & if width == Width::Qword { 63 } else { 31 };
        let value = self.bytes[remaining + 2..]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
            & width.mask();
        let result = (value << count) & width.mask();
        let bits = width.byte_len() as u32 * 8;
        let sign = 1u64 << (bits - 1);
        let mut flags = flags_bits;
        if count != 0 {
            flags = (flags & !0xc4)
                | (u64::from((result as u8).count_ones().is_multiple_of(2)) << 2)
                | (u64::from(result == 0) << 6)
                | (u64::from(result & sign != 0) << 7);
            if count < bits {
                flags = (flags & !1) | ((value >> (bits - count)) & 1);
            }
            if count == 1 {
                flags =
                    (flags & !0x800) | (u64::from((result & sign != 0) ^ (flags & 1 != 0)) << 11);
            }
        }
        self.bytes.truncate(remaining);
        self.bytes
            .extend(result.to_le_bytes()[..storage].iter().rev().copied());
        self.bytes.extend(flags.to_le_bytes().iter().rev().copied());
        Ok(())
    }

    fn binary_with_reserve(
        &mut self,
        op: BinaryOp,
        width: Width,
        flags_bits: u64,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), StackError>,
    ) -> Result<(), StackError> {
        let storage = width.byte_len().max(2);
        let available = self.bytes.len();
        let remaining = available
            .checked_sub(2 * storage)
            .ok_or(StackError::Underflow {
                needed: 2 * storage,
                available,
            })?;
        let required = required_len(remaining, storage + 8, self.budget)?;
        reserve(&mut self.bytes, required - available)?;
        let operands = &self.bytes[remaining..];
        let read = |bytes: &[u8]| {
            bytes
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
                & width.mask()
        };
        let deeper = read(&operands[..storage]);
        let top = read(&operands[storage..]);
        let sign = 1u64 << (width.byte_len() * 8 - 1);
        let (result, carry, overflow, auxiliary, changed) = match op {
            BinaryOp::Add => {
                let result = deeper.wrapping_add(top) & width.mask();
                let overflow = (!(deeper ^ top) & (deeper ^ result)) & sign != 0;
                (
                    result,
                    top > width.mask() - deeper,
                    overflow,
                    (deeper ^ top ^ result) & 0x10,
                    0x8d5,
                )
            }
            BinaryOp::Nor => (!(deeper | top) & width.mask(), false, false, 0, 0x8c5),
        };
        let flags = (flags_bits & !changed)
            | u64::from(carry)
            | (u64::from((result as u8).count_ones().is_multiple_of(2)) << 2)
            | auxiliary
            | (u64::from(result == 0) << 6)
            | (u64::from(result & sign != 0) << 7)
            | (u64::from(overflow) << 11);
        self.bytes.truncate(remaining);
        self.bytes
            .extend(result.to_le_bytes()[..storage].iter().rev().copied());
        self.bytes.extend(flags.to_le_bytes().iter().rev().copied());
        Ok(())
    }

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
    fn shl_failed_reservation_preserves_operands_and_lower_bytes() {
        for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
            let storage = width.byte_len().max(2);
            let mut stack = ByteStack {
                bytes: vec![0xa5; storage + 4],
                budget: 32,
            };
            let before = stack.bytes.clone();
            assert_eq!(
                stack.shl_with_reserve(width, u64::MAX, |bytes, growth| {
                    assert_eq!(*bytes, before);
                    assert_eq!(growth, 6);
                    Err(StackError::Allocation)
                }),
                Err(StackError::Allocation)
            );
            assert_eq!(stack.bytes, before);
        }
    }

    #[test]
    fn binary_failed_reservation_preserves_both_operands_and_lower_bytes() {
        for op in [BinaryOp::Add, BinaryOp::Nor] {
            for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
                let storage = width.byte_len().max(2);
                let mut stack = ByteStack {
                    bytes: vec![0xa5; 2 + 2 * storage],
                    budget: 32,
                };
                let before = stack.bytes.clone();
                let result = stack.binary_with_reserve(op, width, u64::MAX, |bytes, growth| {
                    assert_eq!(*bytes, before);
                    assert_eq!(growth, 8 - storage);
                    Err(StackError::Allocation)
                });
                assert_eq!(result, Err(StackError::Allocation));
                assert_eq!(stack.bytes, before);
            }
        }
    }

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
