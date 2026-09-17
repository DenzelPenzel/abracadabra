//! Bounded, unversioned body commands for one native qword register MOV, ADD or SUB

use iced_x86::{Code, OpKind, Register as NativeRegister};
use thiserror::Error;
use vmp_ir::Instruction;
use vmp_types::Architecture;

use crate::{
    operand::{Register, Width},
    stack::{self, BinaryOp},
};

/// Logical operations with no opcode assignment or serialization contract
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Stack(stack::Instruction),
    PushContext(ContextRegister),
    PopContext(ContextRegister),
    /// Replaces two operands with a result below a qword raw flags word
    Binary {
        op: BinaryOp,
        width: Width,
    },
}

/// VM context words distinct from architectural GPRs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRegister {
    Flags,
    IntermediateFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LogicalError {
    #[error("unsupported native architecture {architecture:?}")]
    UnsupportedArchitecture { architecture: Architecture },
    #[error("expected an unprefixed qword GPR MOV, ADD or SUB without RSP or operand references")]
    UnsupportedInstruction,
}

/// Body commands borrowing exactly one caller-owned instruction and its source identity
#[derive(Debug)]
pub struct LogicalInstruction<'source> {
    source: &'source Instruction,
    body: Body,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "sealed bodies keep bounded lowering allocation-free"
)]
enum Body {
    Mov([Command; 2]),
    Binary([Command; 5]),
    Sub([Command; 29]),
}

impl<'source> LogicalInstruction<'source> {
    pub fn source(&self) -> &'source Instruction {
        self.source
    }

    pub fn commands(&self) -> &[Command] {
        match &self.body {
            Body::Mov(commands) => commands,
            Body::Binary(commands) => commands,
            Body::Sub(commands) => commands,
        }
    }

    pub(crate) fn max_stack_bytes(&self) -> usize {
        match self.body {
            Body::Mov(_) => 8,
            Body::Binary(_) => 16,
            Body::Sub(_) => 24,
        }
    }
}

/// Produces only the context-free instruction body, using fixed storage and no allocation
///
/// Accepts both opcode directions of qword GPR MOV/ADD/SUB, excluding RSP, with just one
/// REX.W prefix and no operand references; the IR's paired payload/encoding is trusted
/// Arithmetic always saves flags; SUB uses the deterministic all-NOR decomposition
/// PopFlags transports raw data, not architectural POPF
///
/// The caller retains ownership and must separately handle any required unwind frame-register
/// shadow stores, entry/exit sections and merging; these commands alone do not implement them
/// In particular, writes to RBX/RBP/RSI/RDI do not emit context-dependent frame shadow stores
pub fn lower_instruction(
    architecture: Architecture,
    source: &Instruction,
) -> Result<LogicalInstruction<'_>, LogicalError> {
    match architecture {
        Architecture::X86 => return Err(LogicalError::UnsupportedArchitecture { architecture }),
        Architecture::X64 => {}
    }
    let raw = source.raw();
    if !source.refs().is_empty()
        || !matches!(source.bytes(), [0x48..=0x4f, _, _])
        || raw.op_count() != 2
        || raw.op0_kind() != OpKind::Register
        || raw.op1_kind() != OpKind::Register
    {
        return Err(LogicalError::UnsupportedInstruction);
    }
    let destination = register(raw.op0_register())?;
    let source_register = register(raw.op1_register())?;
    let push = |register| {
        Command::Stack(stack::Instruction::PushReg {
            width: Width::Qword,
            register,
        })
    };
    let pop = Command::Stack(stack::Instruction::PopReg {
        width: Width::Qword,
        register: destination,
    });
    let binary = |op| {
        Body::Binary([
            push(source_register),
            push(destination),
            Command::Binary {
                op,
                width: Width::Qword,
            },
            Command::Stack(stack::Instruction::PopFlags),
            pop,
        ])
    };
    let body = match raw.code() {
        Code::Mov_rm64_r64 | Code::Mov_r64_rm64 => Body::Mov([push(source_register), pop]),
        Code::Add_rm64_r64 | Code::Add_r64_rm64 => binary(BinaryOp::Add),
        Code::Sub_rm64_r64 | Code::Sub_r64_rm64 => {
            let nor = Command::Binary {
                op: BinaryOp::Nor,
                width: Width::Qword,
            };
            let add = Command::Binary {
                op: BinaryOp::Add,
                width: Width::Qword,
            };
            let discard_flags = Command::Stack(stack::Instruction::Drop {
                width: Width::Qword,
            });
            let flags = Command::Stack(stack::Instruction::PopFlags);
            let mask = 0x815u64;
            Body::Sub([
                push(source_register),
                push(destination),
                push(destination),
                nor,
                discard_flags,
                add,
                flags,
                Command::Stack(stack::Instruction::PushStackPointer),
                Command::Stack(stack::Instruction::LoadStack {
                    width: Width::Qword,
                }),
                nor,
                Command::PopContext(ContextRegister::IntermediateFlags),
                pop,
                // Keep P/O/A/C from ADD and take the other bits from the final inversion
                Command::PushContext(ContextRegister::Flags),
                Command::PushContext(ContextRegister::Flags),
                nor,
                discard_flags,
                Command::Stack(stack::Instruction::PushImm {
                    width: Width::Qword,
                    value: !mask,
                }),
                nor,
                discard_flags,
                Command::PushContext(ContextRegister::IntermediateFlags),
                Command::PushContext(ContextRegister::IntermediateFlags),
                nor,
                discard_flags,
                Command::Stack(stack::Instruction::PushImm {
                    width: Width::Qword,
                    value: mask,
                }),
                nor,
                discard_flags,
                add,
                discard_flags,
                flags,
            ])
        }
        _ => return Err(LogicalError::UnsupportedInstruction),
    };
    Ok(LogicalInstruction { source, body })
}

fn register(native: NativeRegister) -> Result<Register, LogicalError> {
    match native {
        NativeRegister::RAX => Ok(Register::Rax),
        NativeRegister::RCX => Ok(Register::Rcx),
        NativeRegister::RDX => Ok(Register::Rdx),
        NativeRegister::RBX => Ok(Register::Rbx),
        NativeRegister::RBP => Ok(Register::Rbp),
        NativeRegister::RSI => Ok(Register::Rsi),
        NativeRegister::RDI => Ok(Register::Rdi),
        NativeRegister::R8 => Ok(Register::R8),
        NativeRegister::R9 => Ok(Register::R9),
        NativeRegister::R10 => Ok(Register::R10),
        NativeRegister::R11 => Ok(Register::R11),
        NativeRegister::R12 => Ok(Register::R12),
        NativeRegister::R13 => Ok(Register::R13),
        NativeRegister::R14 => Ok(Register::R14),
        NativeRegister::R15 => Ok(Register::R15),
        _ => Err(LogicalError::UnsupportedInstruction),
    }
}
