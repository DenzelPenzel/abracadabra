//! The persistent intermediate representation of a decoded function.
//!
//! `vmp-x86` builds these structures from an image; `vmp-mutation` and `vmp-vm`
//! consume them. The crate owns the container model — functions, basic blocks,
//! edges and operand references — and nothing else: decoding, semantics and
//! encoding all live in `vmp-x86`.
//!
//! # Instruction payload
//!
//! [`Instruction`] wraps `iced_x86::Instruction` directly rather than
//! re-modelling x86 operands. ADR-0001 already makes iced-x86 the project's
//! codec, and the only architecture in the MVP is x86-64, so a parallel operand
//! model would be duplicated work that has to be kept in sync. What this crate
//! adds on top is the part iced cannot know: how an operand binds to the PE
//! container — see [`OperandRef`].
//!
//! # Address convention
//!
//! Instructions are decoded with `ip` set to their RVA, not to their virtual
//! address. Branch targets and RIP-relative targets are therefore RVAs
//! directly, and re-encoding a block at a new RVA needs no rebasing step.

mod block;
mod function;
mod instruction;

pub use block::{BasicBlock, BlockId, Edge, EdgeKind, EdgeTarget, Terminator};
pub use function::{CompileStage, DecodeIssue, Function, UnwindRange};
pub use instruction::{
    AbsoluteWidth, BranchKind, FieldSpan, Instruction, OperandRef, Origin, TargetKind,
    MAX_INSTRUCTION_LEN,
};
