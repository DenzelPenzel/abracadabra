//! Bounded, deterministic host execution of decoded VM bytecode.

use thiserror::Error;

use crate::bytecode::{
    Condition, Instruction, Program, Register, Width, HEADER_SIZE, MAX_CONTAINER_SIZE,
    MAX_INSTRUCTIONS,
};

const MAX_STACK_SLOTS: usize = 4_096;
const MAX_STEPS: u64 = 1_000_000;
const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const MODELED_FLAGS: u64 = CF | PF | AF | ZF | SF | OF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    width: Width,
    value: u64,
}

/// Mutable state owned by one host execution.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MachineState {
    gpr: [u64; 16],
    flags_bits: u64,
    flags_defined: u64,
    stack: Vec<Slot>,
    pc: u32,
    steps: u64,
}

impl MachineState {
    pub fn register(&self, register: Register) -> u64 {
        self.gpr[usize::from(register.id())]
    }

    pub fn set_register(&mut self, register: Register, value: u64) {
        self.gpr[usize::from(register.id())] = value;
    }

    pub fn set_flags(&mut self, bits: u64, defined: u64) {
        self.flags_bits = bits;
        self.flags_defined = defined;
    }

    pub fn flags_bits(&self) -> u64 {
        self.flags_bits
    }

    pub fn flags_defined(&self) -> u64 {
        self.flags_defined
    }

    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    pub fn steps(&self) -> u64 {
        self.steps
    }

    pub fn pc(&self) -> u32 {
        self.pc
    }

    pub fn set_steps(&mut self, steps: u64) {
        self.steps = steps;
    }

    fn push(&mut self, slot: Slot) -> Result<(), ExecutionError> {
        if self.stack.len() == MAX_STACK_SLOTS {
            return Err(ExecutionError::StackOverflow {
                maximum: MAX_STACK_SLOTS,
            });
        }
        self.stack
            .try_reserve(1)
            .map_err(|_| ExecutionError::Allocation {
                context: "growing the VM stack",
            })?;
        self.stack.push(slot);
        Ok(())
    }

    fn pop(&mut self) -> Result<Slot, ExecutionError> {
        self.stack.pop().ok_or(ExecutionError::StackUnderflow)
    }
}

/// Abstract v1 termination result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Ret,
}

/// Successful host execution and its final state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    state: MachineState,
    termination: Termination,
}

impl Execution {
    pub fn state(&self) -> &MachineState {
        &self.state
    }

    pub fn termination(&self) -> Termination {
        self.termination
    }
}

/// Typed host execution trap.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecutionError {
    #[error("invalid VM PC 0x{pc:08x}")]
    InvalidPc { pc: u32 },
    #[error("branch at code offset 0x{code_offset:08x} targets non-boundary 0x{target:08x}")]
    InvalidBranchTarget { code_offset: u32, target: u32 },
    #[error("VM program instruction count {count} exceeds {maximum}")]
    TooManyInstructions { count: usize, maximum: usize },
    #[error("VM program container size {size} exceeds {maximum}")]
    ProgramTooLarge { size: usize, maximum: usize },
    #[error("immediate 0x{value:x} does not fit width {width:?}")]
    ImmediateOutOfRange { width: Width, value: u64 },
    #[error("execution fell off bytecode after PC 0x{pc:08x}")]
    Fallthrough { pc: u32 },
    #[error("VM step limit {maximum} reached")]
    StepLimit { maximum: u64 },
    #[error("VM stack limit {maximum} reached")]
    StackOverflow { maximum: usize },
    #[error("VM stack underflow")]
    StackUnderflow,
    #[error("VM slot width mismatch: instruction {instruction:?}, lhs {lhs:?}, rhs {rhs:?}")]
    WidthMismatch {
        instruction: Width,
        lhs: Width,
        rhs: Width,
    },
    #[error("VM pop width mismatch: expected {expected:?}, actual {actual:?}")]
    PopWidthMismatch { expected: Width, actual: Width },
    #[error("ret reached with {depth} VM stack slots")]
    NonEmptyStackAtRet { depth: usize },
    #[error(
        "condition {condition:?} requires flags 0x{required:x}, but only 0x{defined:x} are defined"
    )]
    UndefinedConditionFlags {
        condition: Condition,
        required: u64,
        defined: u64,
    },
    #[error("VM execution size arithmetic overflow")]
    SizeOverflow,
    #[error("allocation failed while {context}")]
    Allocation { context: &'static str },
}

/// Execute one immutable decoded program from the supplied machine state.
pub fn execute(program: &Program, mut state: MachineState) -> Result<Execution, ExecutionError> {
    let offsets = instruction_offsets(program)?;
    state.pc = program.entry_offset();

    loop {
        if state.steps >= MAX_STEPS {
            return Err(ExecutionError::StepLimit { maximum: MAX_STEPS });
        }
        let index = offsets
            .binary_search(&state.pc)
            .map_err(|_| ExecutionError::InvalidPc { pc: state.pc })?;
        let instruction = program
            .instructions()
            .get(index)
            .ok_or(ExecutionError::InvalidPc { pc: state.pc })?;
        let current_pc = state.pc;
        state.steps += 1;

        match instruction {
            Instruction::Ret => {
                if !state.stack.is_empty() {
                    return Err(ExecutionError::NonEmptyStackAtRet {
                        depth: state.stack.len(),
                    });
                }
                return Ok(Execution {
                    state,
                    termination: Termination::Ret,
                });
            }
            Instruction::PushImm { width, value } => {
                state.push(Slot {
                    width: *width,
                    value: *value & width.mask(),
                })?;
            }
            Instruction::PushReg { width, register } => {
                state.push(Slot {
                    width: *width,
                    value: state.register(*register) & width.mask(),
                })?;
            }
            Instruction::PopReg { width, register } => {
                let slot = state.pop()?;
                if slot.width != *width {
                    return Err(ExecutionError::PopWidthMismatch {
                        expected: *width,
                        actual: slot.width,
                    });
                }
                write_register(&mut state, *register, *width, slot.value);
            }
            Instruction::Drop(width) => {
                let slot = state.pop()?;
                if slot.width != *width {
                    return Err(ExecutionError::PopWidthMismatch {
                        expected: *width,
                        actual: slot.width,
                    });
                }
            }
            Instruction::Add(width) => execute_add(&mut state, *width)?,
            Instruction::Sub(width) => execute_sub(&mut state, *width)?,
            Instruction::Xor(width) => execute_xor(&mut state, *width)?,
            Instruction::And(width) => execute_and(&mut state, *width)?,
            Instruction::Jmp { target } => {
                state.pc = *target;
                continue;
            }
            Instruction::Jcc { condition, target } => {
                if evaluate_condition(&state, *condition)? {
                    state.pc = *target;
                    continue;
                }
            }
        }

        state.pc = offsets
            .get(index + 1)
            .copied()
            .ok_or(ExecutionError::Fallthrough { pc: current_pc })?;
    }
}

fn instruction_offsets(program: &Program) -> Result<Vec<u32>, ExecutionError> {
    let instruction_count = program.instructions().len();
    if instruction_count > MAX_INSTRUCTIONS {
        return Err(ExecutionError::TooManyInstructions {
            count: instruction_count,
            maximum: MAX_INSTRUCTIONS,
        });
    }
    let mut code_size = 0usize;
    for instruction in program.instructions() {
        if let Instruction::PushImm { width, value } = instruction {
            if value & !width.mask() != 0 {
                return Err(ExecutionError::ImmediateOutOfRange {
                    width: *width,
                    value: *value,
                });
            }
        }
        code_size = code_size
            .checked_add(instruction.encoded_len())
            .ok_or(ExecutionError::SizeOverflow)?;
    }
    let container_size = HEADER_SIZE
        .checked_add(code_size)
        .ok_or(ExecutionError::SizeOverflow)?;
    if container_size > MAX_CONTAINER_SIZE {
        return Err(ExecutionError::ProgramTooLarge {
            size: container_size,
            maximum: MAX_CONTAINER_SIZE,
        });
    }

    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(instruction_count)
        .map_err(|_| ExecutionError::Allocation {
            context: "retaining execution instruction boundaries",
        })?;
    let mut offset = 0usize;
    for instruction in program.instructions() {
        offsets.push(u32::try_from(offset).map_err(|_| ExecutionError::SizeOverflow)?);
        offset = offset
            .checked_add(instruction.encoded_len())
            .ok_or(ExecutionError::SizeOverflow)?;
    }
    if offsets.binary_search(&program.entry_offset()).is_err() {
        return Err(ExecutionError::InvalidPc {
            pc: program.entry_offset(),
        });
    }
    for (code_offset, instruction) in offsets.iter().copied().zip(program.instructions()) {
        let Some(target) = instruction.branch_target() else {
            continue;
        };
        if offsets.binary_search(&target).is_err() {
            return Err(ExecutionError::InvalidBranchTarget {
                code_offset,
                target,
            });
        }
    }
    Ok(offsets)
}

fn execute_add(state: &mut MachineState, width: Width) -> Result<(), ExecutionError> {
    let rhs = state.pop()?;
    let lhs = state.pop()?;
    require_binary_widths(width, lhs, rhs)?;

    let mask = width.mask();
    let full = u128::from(lhs.value) + u128::from(rhs.value);
    let result = (full as u64) & mask;
    let sign = 1u64 << (width.byte_len() * 8 - 1);
    let carry = full > u128::from(mask);
    let parity = (result & u64::from(u8::MAX)).count_ones().is_multiple_of(2);
    let auxiliary = (lhs.value ^ rhs.value ^ result) & 0x10 != 0;
    let overflow = (!(lhs.value ^ rhs.value) & (lhs.value ^ result) & sign) != 0;

    set_arithmetic_flags(
        state,
        carry,
        parity,
        auxiliary,
        result == 0,
        result & sign != 0,
        overflow,
    );
    state.push(Slot {
        width,
        value: result,
    })
}

fn execute_sub(state: &mut MachineState, width: Width) -> Result<(), ExecutionError> {
    let rhs = state.pop()?;
    let lhs = state.pop()?;
    require_binary_widths(width, lhs, rhs)?;

    let mask = width.mask();
    let lhs_value = lhs.value & mask;
    let rhs_value = rhs.value & mask;
    let result = lhs_value.wrapping_sub(rhs_value) & mask;
    let sign = 1u64 << (width.byte_len() * 8 - 1);
    let borrow = lhs_value < rhs_value;
    let parity = (result & u64::from(u8::MAX)).count_ones().is_multiple_of(2);
    let auxiliary = (lhs_value ^ rhs_value ^ result) & 0x10 != 0;
    let overflow = ((lhs_value ^ rhs_value) & (lhs_value ^ result) & sign) != 0;

    set_arithmetic_flags(
        state,
        borrow,
        parity,
        auxiliary,
        result == 0,
        result & sign != 0,
        overflow,
    );
    state.push(Slot {
        width,
        value: result,
    })
}

fn execute_xor(state: &mut MachineState, width: Width) -> Result<(), ExecutionError> {
    let rhs = state.pop()?;
    let lhs = state.pop()?;
    require_binary_widths(width, lhs, rhs)?;

    let result = (lhs.value ^ rhs.value) & width.mask();
    let sign = 1u64 << (width.byte_len() * 8 - 1);
    let parity = (result & u64::from(u8::MAX)).count_ones().is_multiple_of(2);
    let defined = CF | PF | ZF | SF | OF;
    let mut bits = state.flags_bits & !MODELED_FLAGS;
    if parity {
        bits |= PF;
    }
    if result == 0 {
        bits |= ZF;
    }
    if result & sign != 0 {
        bits |= SF;
    }
    state.flags_bits = bits;
    state.flags_defined = (state.flags_defined & !MODELED_FLAGS) | defined;
    state.push(Slot {
        width,
        value: result,
    })
}

fn execute_and(state: &mut MachineState, width: Width) -> Result<(), ExecutionError> {
    let rhs = state.pop()?;
    let lhs = state.pop()?;
    require_binary_widths(width, lhs, rhs)?;

    let result = (lhs.value & rhs.value) & width.mask();
    let sign = 1u64 << (width.byte_len() * 8 - 1);
    let parity = (result & u64::from(u8::MAX)).count_ones().is_multiple_of(2);
    let defined = CF | PF | ZF | SF | OF;
    let mut bits = state.flags_bits & !MODELED_FLAGS;
    if parity {
        bits |= PF;
    }
    if result == 0 {
        bits |= ZF;
    }
    if result & sign != 0 {
        bits |= SF;
    }
    state.flags_bits = bits;
    state.flags_defined = (state.flags_defined & !MODELED_FLAGS) | defined;
    state.push(Slot {
        width,
        value: result,
    })
}

fn evaluate_condition(state: &MachineState, condition: Condition) -> Result<bool, ExecutionError> {
    let required = match condition {
        Condition::O | Condition::No => OF,
        Condition::B | Condition::Ae => CF,
        Condition::E | Condition::Ne => ZF,
        Condition::Be | Condition::A => CF | ZF,
        Condition::S | Condition::Ns => SF,
        Condition::P | Condition::Np => PF,
        Condition::L | Condition::Ge => SF | OF,
        Condition::Le | Condition::G => ZF | SF | OF,
    };
    if state.flags_defined & required != required {
        return Err(ExecutionError::UndefinedConditionFlags {
            condition,
            required,
            defined: state.flags_defined,
        });
    }
    let is_set = |flag| state.flags_bits & flag != 0;
    let value = match condition {
        Condition::O => is_set(OF),
        Condition::No => !is_set(OF),
        Condition::B => is_set(CF),
        Condition::Ae => !is_set(CF),
        Condition::E => is_set(ZF),
        Condition::Ne => !is_set(ZF),
        Condition::Be => is_set(CF) || is_set(ZF),
        Condition::A => !is_set(CF) && !is_set(ZF),
        Condition::S => is_set(SF),
        Condition::Ns => !is_set(SF),
        Condition::P => is_set(PF),
        Condition::Np => !is_set(PF),
        Condition::L => is_set(SF) != is_set(OF),
        Condition::Ge => is_set(SF) == is_set(OF),
        Condition::Le => is_set(ZF) || is_set(SF) != is_set(OF),
        Condition::G => !is_set(ZF) && is_set(SF) == is_set(OF),
    };
    Ok(value)
}

fn require_binary_widths(width: Width, lhs: Slot, rhs: Slot) -> Result<(), ExecutionError> {
    if lhs.width != width || rhs.width != width {
        return Err(ExecutionError::WidthMismatch {
            instruction: width,
            lhs: lhs.width,
            rhs: rhs.width,
        });
    }
    Ok(())
}

fn set_arithmetic_flags(
    state: &mut MachineState,
    carry: bool,
    parity: bool,
    auxiliary: bool,
    zero: bool,
    sign: bool,
    overflow: bool,
) {
    let values = [
        (CF, carry),
        (PF, parity),
        (AF, auxiliary),
        (ZF, zero),
        (SF, sign),
        (OF, overflow),
    ];
    let mut bits = state.flags_bits & !MODELED_FLAGS;
    for (mask, value) in values {
        if value {
            bits |= mask;
        }
    }
    state.flags_bits = bits;
    state.flags_defined = (state.flags_defined & !MODELED_FLAGS) | MODELED_FLAGS;
}

fn write_register(state: &mut MachineState, register: Register, width: Width, value: u64) {
    let old = state.register(register);
    let value = value & width.mask();
    let updated = match width {
        Width::Qword | Width::Dword => value,
        Width::Word | Width::Byte => (old & !width.mask()) | value,
    };
    state.set_register(register, updated);
}
