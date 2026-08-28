//! Basic blocks and control-flow edges.
//!
//! Real basic blocks: every branch
//! target begins one, and both successors and predecessors are materialised.

use vmp_types::Rva;

use crate::instruction::Instruction;

/// Dense index of a basic block inside one [`Function`](crate::Function).
///
/// Ids are only meaningful within the function that produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub u32);

impl BlockId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A straight-line run of instructions ending in exactly one terminator.
///
/// A `call` does not end a block: call targets are never
/// followed, so a call is an ordinary instruction that happens to carry a
/// reference to another function.
/// Freshly decoded, a block's instructions tile `[start, end)` exactly. That
/// holds only until a transform runs: an inserted instruction has no address at
/// all, so after mutation `start` and `end` describe the extent the block
/// occupied *in the input image* and no longer bound the instruction list.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// RVA of the first decoded instruction.
    pub start: Rva,
    /// RVA one past the last decoded instruction.
    pub end: Rva,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
    pub successors: Vec<Edge>,
    pub predecessors: Vec<BlockId>,
}

impl BasicBlock {
    /// The instruction that ends the block, if the block is not empty.
    pub fn last(&self) -> Option<&Instruction> {
        self.instructions.last()
    }

    /// Whether control can leave this block into code that was not decoded.
    pub fn leaves_function(&self) -> bool {
        self.successors
            .iter()
            .any(|edge| matches!(edge.target, EdgeTarget::External(_)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Terminator {
    /// The block was split because the next instruction is a branch target;
    /// control simply flows on.
    FallThrough,
    /// A direct unconditional `jmp`.
    Jump,
    /// `jcc`, `jcxz` or `loop`: a taken edge plus a fall-through edge.
    Conditional,
    /// `ret` or `iret`.
    Return,
    /// An indirect `jmp` whose target could not be resolved.
    IndirectJump,
    /// An indirect `jmp` through an import address table slot: a tail call to
    /// an imported function.
    ///
    /// The target is as known as a direct branch's — the loader fills the slot
    /// — so this is not the unresolved case above. Control does not return, so
    /// the block has no successor inside the function.
    ImportTailCall,
    /// Control does not continue: `int3`, `int 0x29`, `hlt`, `ud2`, or a call
    /// into a function known not to return.
    Halt,
    /// Decoding produced data rather than an instruction.
    Data,
}

/// A control-flow edge leaving a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub kind: EdgeKind,
    pub target: EdgeTarget,
}

impl Edge {
    pub const fn new(kind: EdgeKind, target: EdgeTarget) -> Edge {
        Edge { kind, target }
    }
}

/// Why an edge exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Control flows into the next block without a branch.
    FallThrough,
    /// The taken side of a conditional branch.
    Taken,
    /// The not-taken side of a conditional branch.
    NotTaken,
    /// An unconditional `jmp`.
    Jump,
}

/// Where an edge points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeTarget {
    /// A block of the same function.
    Block(BlockId),
    /// An address outside the decoded function: a tail call, a thunk, or a
    /// branch the traversal declined to follow.
    External(Rva),
}
