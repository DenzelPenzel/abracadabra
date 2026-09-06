//! Bounded v2 host execution with a raw byte stack and logical flags word

use crate::bytecode::{Condition, Register};
use crate::bytecode_v2::{Instruction, Program};
use crate::stack_v2::{self, Output, StackError};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Ret,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecutionError {
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error("v2 dispatch limit {maximum} reached")]
    StepLimit { maximum: u64 },
    #[error("v2 ret reached with {bytes} stack bytes")]
    NonEmptyStackAtRet { bytes: usize },
    #[error("v2 execution fell through after {pc}")]
    Fallthrough { pc: u32 },
    #[error("invalid v2 PC {pc}")]
    InvalidPc { pc: u32 },
}

/// Reusable logical state; failures leave the attempted dispatch observable
#[derive(Debug)]
pub struct Machine {
    stack: stack_v2::Machine,
    flags_bits: u64,
    pc: u32,
    steps: u64,
}

impl Machine {
    pub fn new(max_stack_bytes: usize) -> Self {
        Self {
            stack: stack_v2::Machine::new(max_stack_bytes),
            flags_bits: 0,
            pc: 0,
            steps: 0,
        }
    }
    pub fn register(&self, register: Register) -> u64 {
        self.stack.register(register)
    }
    pub fn set_register(&mut self, register: Register, value: u64) {
        self.stack.set_register(register, value);
    }
    pub fn flags_bits(&self) -> u64 {
        self.flags_bits
    }
    /// Sets the raw logical word, without physical POPF or reserved-bit normalization
    pub fn set_flags_bits(&mut self, bits: u64) {
        self.flags_bits = bits;
    }
    pub fn stack_bytes(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.stack.stack_bytes()
    }
    pub fn pc(&self) -> u32 {
        self.pc
    }
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Starts at program entry, retaining data state and cumulative dispatch count
    pub fn execute(
        &mut self,
        program: &Program,
        max_steps: u64,
    ) -> Result<Termination, ExecutionError> {
        self.pc = program.entry_offset();
        loop {
            if self.steps >= max_steps {
                return Err(ExecutionError::StepLimit { maximum: max_steps });
            }
            let index = program
                .offsets()
                .binary_search(&self.pc)
                .map_err(|_| ExecutionError::InvalidPc { pc: self.pc })?;
            let instruction = program
                .instructions()
                .get(index)
                .ok_or(ExecutionError::InvalidPc { pc: self.pc })?;
            self.steps += 1;
            match *instruction {
                Instruction::Add { width } => self.stack.add(width, self.flags_bits)?,
                Instruction::Shl { width } => self.stack.shl(width, self.flags_bits)?,
                Instruction::Stack(instruction) => match self.stack.step(instruction)? {
                    Output::None => {}
                    Output::FlagsWord(bits) => self.flags_bits = bits,
                },
                Instruction::Ret => {
                    let bytes = self.stack.stack_bytes().len();
                    if bytes != 0 {
                        return Err(ExecutionError::NonEmptyStackAtRet { bytes });
                    }
                    return Ok(Termination::Ret);
                }
                Instruction::Jmp { target } => {
                    self.pc = target;
                    continue;
                }
                Instruction::Jcc { condition, target } => {
                    if evaluate_condition(self.flags_bits, condition) {
                        self.pc = target;
                        continue;
                    }
                }
            }
            self.pc = *program
                .offsets()
                .get(index + 1)
                .ok_or(ExecutionError::Fallthrough { pc: self.pc })?;
        }
    }
}

fn evaluate_condition(bits: u64, condition: Condition) -> bool {
    let cf = bits & 1 != 0;
    let pf = bits & (1 << 2) != 0;
    let zf = bits & (1 << 6) != 0;
    let sf = bits & (1 << 7) != 0;
    let of = bits & (1 << 11) != 0;
    match condition {
        Condition::O => of,
        Condition::No => !of,
        Condition::B => cf,
        Condition::Ae => !cf,
        Condition::E => zf,
        Condition::Ne => !zf,
        Condition::Be => cf || zf,
        Condition::A => !cf && !zf,
        Condition::S => sf,
        Condition::Ns => !sf,
        Condition::P => pf,
        Condition::Np => !pf,
        Condition::L => sf != of,
        Condition::Ge => sf == of,
        Condition::Le => zf || sf != of,
        Condition::G => !zf && sf == of,
    }
}
