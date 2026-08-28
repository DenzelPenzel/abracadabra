//! The decoded function: blocks, unwind range and decode issues.

use std::fmt;

use vmp_types::{Architecture, Rva};

use crate::block::{BasicBlock, BlockId, EdgeTarget};

/// A function reconstructed from an image.
///
/// A function is safe to protect only when [`Function::is_complete`] holds:
/// every reachable path was decoded and every direct branch resolved. Anything
/// the decoder could not account for is recorded in [`Function::issues`] rather
/// than silently dropped, because a silently incomplete CFG becomes a corrupted
/// output file one stage later.
#[derive(Debug, Clone)]
pub struct Function {
    /// The architecture the instructions were decoded for. Carried explicitly
    /// so no later stage has to guess it from the host.
    pub architecture: Architecture,
    /// The address decoding started from.
    pub entry: Rva,
    /// Blocks indexed by [`BlockId`].
    pub blocks: Vec<BasicBlock>,
    pub entry_block: BlockId,
    /// The `RUNTIME_FUNCTION` range covering the entry, when the image has an
    /// exception directory that describes this function.
    pub unwind: Option<UnwindRange>,
    pub issues: Vec<DecodeIssue>,
    pub stage: CompileStage,
}

impl Function {
    /// Whether the function was decoded completely enough to be protected.
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }

    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id.index())
    }

    pub fn block_containing(&self, rva: Rva) -> Option<BlockId> {
        self.blocks
            .iter()
            .find(|block| rva >= block.start && rva < block.end)
            .map(|block| block.id)
    }

    /// Total number of decoded instructions.
    pub fn instruction_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| block.instructions.len())
            .sum()
    }

    /// Instructions of every block in address order.
    pub fn instructions(&self) -> impl Iterator<Item = &crate::Instruction> {
        let mut blocks: Vec<&BasicBlock> = self.blocks.iter().collect();
        blocks.sort_by_key(|block| block.start);
        blocks
            .into_iter()
            .flat_map(|block| block.instructions.iter())
    }

    /// Addresses outside the function that control can reach.
    pub fn external_targets(&self) -> Vec<Rva> {
        let mut targets: Vec<Rva> = self
            .blocks
            .iter()
            .flat_map(|block| block.successors.iter())
            .filter_map(|edge| match edge.target {
                EdgeTarget::External(rva) => Some(rva),
                EdgeTarget::Block(_) => None,
            })
            .collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

/// The `.pdata` range describing a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindRange {
    pub begin: Rva,
    /// Exclusive.
    pub end: Rva,
    pub unwind_info: Rva,
}

impl UnwindRange {
    pub fn contains(self, rva: Rva) -> bool {
        rva >= self.begin && rva < self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompileStage {
    Decoded,
}

/// Something the decoder could not account for.
///
/// Every variant means the same thing to the protector: do not modify this
/// function. They are distinguished so diagnostics can say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeIssue {
    /// An indirect `jmp` whose target set is unknown. Jump-table recovery is
    /// deferred, so any indirect jump makes the function unprotectable.
    IndirectJump { rva: Rva },
    /// The decoder produced an invalid or unsupported opcode.
    InvalidOpcode { rva: Rva },
    /// A direct branch into an address that is not executable.
    TargetNotExecutable { rva: Rva, target: Rva },
    /// A direct branch into the middle of another instruction, which means the
    /// two disagree about where instructions begin.
    BranchIntoInstruction { rva: Rva, target: Rva },
    /// A base relocation lands inside an instruction but not on any encoded
    /// field, which means the instruction was decoded wrongly.
    FixupOutsideField { rva: Rva, fixup: Rva },
    /// Traversal hit the instruction budget before it converged.
    BudgetExceeded { limit: usize },
    /// A control transfer the decoder models but cannot reason about, such as
    /// the transactional-memory `xbegin` family.
    UnsupportedControlFlow { rva: Rva },
}

impl fmt::Display for DecodeIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeIssue::IndirectJump { rva } => {
                write!(f, "indirect jump at {rva} with an unknown target set")
            }
            DecodeIssue::InvalidOpcode { rva } => write!(f, "invalid opcode at {rva}"),
            DecodeIssue::TargetNotExecutable { rva, target } => {
                write!(f, "branch at {rva} targets non-executable address {target}")
            }
            DecodeIssue::BranchIntoInstruction { rva, target } => {
                write!(
                    f,
                    "branch at {rva} targets {target}, inside another instruction"
                )
            }
            DecodeIssue::FixupOutsideField { rva, fixup } => {
                write!(f, "base relocation at {fixup} is inside the instruction at {rva} but not on an encoded field")
            }
            DecodeIssue::BudgetExceeded { limit } => {
                write!(f, "decoding exceeded the budget of {limit} instruction(s)")
            }
            DecodeIssue::UnsupportedControlFlow { rva } => {
                write!(f, "unsupported control transfer at {rva}")
            }
        }
    }
}
