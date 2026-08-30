//! Fail-closed lowering from decoded x64 IR to logical bytecode v1.

use iced_x86::{
    Code, ConditionCode as NativeCondition, Instruction as NativeInstruction, Mnemonic, OpKind,
    Register as NativeRegister,
};
use thiserror::Error;
use vmp_ir::{BasicBlock, BlockId, DecodeIssue, EdgeKind, EdgeTarget, Function, Terminator};
use vmp_types::{Architecture, Rva};

use crate::bytecode::{Condition, Instruction, Program, Register, Width, MAX_INSTRUCTIONS};

const MAX_CFG_RELATIONS: usize = MAX_INSTRUCTIONS * 4;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoweringError {
    #[error("unsupported native architecture {architecture:?}")]
    UnsupportedArchitecture { architecture: Architecture },
    #[error("native function is incomplete: {issue}")]
    IncompleteFunction { issue: DecodeIssue },
    #[error("lowered instruction count {count} exceeds {maximum}")]
    TooManyInstructions { count: usize, maximum: usize },
    #[error("native instruction count {count} exceeds {maximum}")]
    TooManyNativeInstructions { count: usize, maximum: usize },
    #[error("native CFG relation count {count} exceeds {maximum}")]
    TooManyCfgRelations { count: usize, maximum: usize },
    #[error("native basic block count {count} exceeds {maximum}")]
    TooManyBlocks { count: usize, maximum: usize },
    #[error("native basic block at dense index {index} carries id {actual:?}")]
    BlockIdMismatch { index: usize, actual: BlockId },
    #[error("multiple native basic blocks start at {rva}")]
    DuplicateBlockStart { rva: Rva },
    #[error("native basic blocks {first:?} and {second:?} overlap")]
    OverlappingBlocks { first: BlockId, second: BlockId },
    #[error("native basic block {block:?} is empty")]
    EmptyBlock { block: BlockId },
    #[error(
        "native block {block:?} terminator {terminator:?} disagrees with final instruction {code:?}"
    )]
    TerminatorInstructionMismatch {
        block: BlockId,
        terminator: Terminator,
        code: Code,
    },
    #[error("native block {block:?} has interior control-flow instruction {code:?} at {rva:?}")]
    InteriorControlFlow {
        block: BlockId,
        rva: Option<Rva>,
        code: Code,
    },
    #[error(
        "native block {block:?} declares end {declared}, but decoded instructions tile to {tiled}"
    )]
    BlockEndMismatch {
        block: BlockId,
        declared: Rva,
        tiled: Rva,
    },
    #[error("native block {block:?} expected instruction at {expected}, found {actual}")]
    InstructionRvaMismatch {
        block: BlockId,
        expected: Rva,
        actual: Rva,
    },
    #[error(
        "native block {block:?} instruction at {rva} has stored length {actual}, decoded length {expected}"
    )]
    InvalidInstructionLength {
        block: BlockId,
        rva: Rva,
        expected: usize,
        actual: usize,
    },
    #[error("native branch at {rva:?} targets unsupported RVA 0x{target:x}")]
    InvalidBranchTarget { rva: Option<Rva>, target: u64 },
    #[error("native entry {entry} is not a basic-block boundary")]
    InvalidEntry { entry: Rva },
    #[error("native entry block {entry_block:?} does not exist")]
    InvalidEntryBlock { entry_block: BlockId },
    #[error(
        "native entry block {entry_block:?} starts at {block_start}, but function entry is {entry}"
    )]
    EntryBlockMismatch {
        entry_block: BlockId,
        entry: Rva,
        block_start: Rva,
    },
    #[error("native block {block:?} has unsupported external {kind:?} edge to {target}")]
    ExternalEdge {
        block: BlockId,
        kind: EdgeKind,
        target: Rva,
    },
    #[error("native block {block:?} has invalid internal {kind:?} edge to {target:?}")]
    InvalidInternalEdge {
        block: BlockId,
        kind: EdgeKind,
        target: BlockId,
    },
    #[error("native block {block:?} is missing predecessor {predecessor:?}")]
    MissingPredecessor {
        block: BlockId,
        predecessor: BlockId,
    },
    #[error("native block {block:?} has unexpected predecessor {predecessor:?}")]
    UnexpectedPredecessor {
        block: BlockId,
        predecessor: BlockId,
    },
    #[error("native block {block:?} repeats predecessor {predecessor:?}")]
    DuplicatePredecessor {
        block: BlockId,
        predecessor: BlockId,
    },
    #[error(
        "native block {block:?} {kind:?} edge targets {actual}, expected physical RVA {expected}"
    )]
    EdgeRvaMismatch {
        block: BlockId,
        kind: EdgeKind,
        expected: Rva,
        actual: Rva,
    },
    #[error("native block {block:?} has successors incompatible with {terminator:?}")]
    InvalidSuccessorShape {
        block: BlockId,
        terminator: Terminator,
    },
    #[error("native block {block:?} has unsupported terminator {terminator:?}")]
    UnsupportedTerminator {
        block: BlockId,
        terminator: Terminator,
    },
    #[error("lowered byte offset arithmetic overflow")]
    SizeOverflow,
    #[error("allocation failed while {context}")]
    Allocation { context: &'static str },
    #[error("unsupported native register {register:?} at {rva:?}")]
    UnsupportedRegister {
        rva: Option<vmp_types::Rva>,
        register: NativeRegister,
    },
    #[error("unsupported native instruction {code:?} at {rva:?}")]
    UnsupportedInstruction {
        rva: Option<vmp_types::Rva>,
        code: Code,
    },
}

pub fn lower(function: &Function) -> Result<Program, LoweringError> {
    if function.architecture != Architecture::X64 {
        return Err(LoweringError::UnsupportedArchitecture {
            architecture: function.architecture,
        });
    }
    if let Some(issue) = function.issues.first().copied() {
        return Err(LoweringError::IncompleteFunction { issue });
    }
    if function.blocks.len() > MAX_INSTRUCTIONS {
        return Err(LoweringError::TooManyBlocks {
            count: function.blocks.len(),
            maximum: MAX_INSTRUCTIONS,
        });
    }
    let mut native_instruction_count = 0usize;
    let mut cfg_relation_count = 0usize;
    for block in &function.blocks {
        native_instruction_count = native_instruction_count
            .checked_add(block.instructions.len())
            .ok_or(LoweringError::SizeOverflow)?;
        if native_instruction_count > MAX_INSTRUCTIONS {
            return Err(LoweringError::TooManyNativeInstructions {
                count: native_instruction_count,
                maximum: MAX_INSTRUCTIONS,
            });
        }
        cfg_relation_count = cfg_relation_count
            .checked_add(block.successors.len())
            .and_then(|count| count.checked_add(block.predecessors.len()))
            .ok_or(LoweringError::SizeOverflow)?;
        if cfg_relation_count > MAX_CFG_RELATIONS {
            return Err(LoweringError::TooManyCfgRelations {
                count: cfg_relation_count,
                maximum: MAX_CFG_RELATIONS,
            });
        }
    }
    for (index, block) in function.blocks.iter().enumerate() {
        if block.id.index() != index {
            return Err(LoweringError::BlockIdMismatch {
                index,
                actual: block.id,
            });
        }
    }
    let entry_block =
        function
            .block(function.entry_block)
            .ok_or(LoweringError::InvalidEntryBlock {
                entry_block: function.entry_block,
            })?;
    if entry_block.start != function.entry {
        return Err(LoweringError::EntryBlockMismatch {
            entry_block: function.entry_block,
            entry: function.entry,
            block_start: entry_block.start,
        });
    }
    for block in &function.blocks {
        if block.instructions.is_empty() {
            return Err(LoweringError::EmptyBlock { block: block.id });
        }
        if matches!(
            block.terminator,
            Terminator::IndirectJump
                | Terminator::ImportTailCall
                | Terminator::Halt
                | Terminator::Data
        ) {
            return Err(LoweringError::UnsupportedTerminator {
                block: block.id,
                terminator: block.terminator,
            });
        }
        let mut tiled = block.start;
        let mut has_decoded = false;
        for instruction in &block.instructions {
            let Some(actual) = instruction.rva() else {
                continue;
            };
            has_decoded = true;
            let expected_len = instruction.raw().len();
            let actual_len = instruction.bytes().len();
            if expected_len == 0 || actual_len == 0 || expected_len != actual_len {
                return Err(LoweringError::InvalidInstructionLength {
                    block: block.id,
                    rva: actual,
                    expected: expected_len,
                    actual: actual_len,
                });
            }
            if actual != tiled {
                return Err(LoweringError::InstructionRvaMismatch {
                    block: block.id,
                    expected: tiled,
                    actual,
                });
            }
            tiled = instruction.next_rva().ok_or(LoweringError::SizeOverflow)?;
        }
        if !has_decoded {
            return Err(LoweringError::EmptyBlock { block: block.id });
        }
        if tiled != block.end {
            return Err(LoweringError::BlockEndMismatch {
                block: block.id,
                declared: block.end,
                tiled,
            });
        }
        for instruction in &block.instructions[..block.instructions.len() - 1] {
            let raw = instruction.raw();
            if raw.is_jmp_short_or_near()
                || raw.is_jcc_short_or_near()
                || raw.mnemonic() == Mnemonic::Ret
            {
                return Err(LoweringError::InteriorControlFlow {
                    block: block.id,
                    rva: instruction.rva(),
                    code: raw.code(),
                });
            }
        }
        let last = block.last().expect("nonempty block checked above").raw();
        let terminator_matches = match block.terminator {
            Terminator::Return => last.code() == Code::Retnq,
            Terminator::Jump => last.is_jmp_short_or_near(),
            Terminator::Conditional => last.is_jcc_short_or_near(),
            Terminator::FallThrough => {
                !last.is_jmp_short_or_near()
                    && !last.is_jcc_short_or_near()
                    && last.mnemonic() != Mnemonic::Ret
            }
            Terminator::IndirectJump
            | Terminator::ImportTailCall
            | Terminator::Halt
            | Terminator::Data => false,
        };
        if !terminator_matches {
            return Err(LoweringError::TerminatorInstructionMismatch {
                block: block.id,
                terminator: block.terminator,
                code: last.code(),
            });
        }
        for edge in &block.successors {
            match edge.target {
                EdgeTarget::External(target) => {
                    return Err(LoweringError::ExternalEdge {
                        block: block.id,
                        kind: edge.kind,
                        target,
                    });
                }
                EdgeTarget::Block(target) => {
                    let target_block = function.block(target).filter(|block| block.id == target);
                    if target_block.is_none() {
                        return Err(LoweringError::InvalidInternalEdge {
                            block: block.id,
                            kind: edge.kind,
                            target,
                        });
                    }
                }
            }
        }
        let valid_shape = match block.terminator {
            Terminator::Return => block.successors.is_empty(),
            Terminator::Jump => {
                matches!(block.successors.as_slice(), [edge] if edge.kind == EdgeKind::Jump)
            }
            Terminator::Conditional => {
                block.successors.len() == 2
                    && block
                        .successors
                        .iter()
                        .filter(|edge| edge.kind == EdgeKind::Taken)
                        .count()
                        == 1
                    && block
                        .successors
                        .iter()
                        .filter(|edge| edge.kind == EdgeKind::NotTaken)
                        .count()
                        == 1
            }
            Terminator::FallThrough => {
                matches!(block.successors.as_slice(), [edge] if edge.kind == EdgeKind::FallThrough)
            }
            Terminator::IndirectJump
            | Terminator::ImportTailCall
            | Terminator::Halt
            | Terminator::Data => false,
        };
        if !valid_shape {
            return Err(LoweringError::InvalidSuccessorShape {
                block: block.id,
                terminator: block.terminator,
            });
        }
    }

    for block in &function.blocks {
        for edge in &block.successors {
            if let EdgeTarget::Block(target) = edge.target {
                let target_block =
                    function
                        .block(target)
                        .ok_or(LoweringError::InvalidInternalEdge {
                            block: block.id,
                            kind: edge.kind,
                            target,
                        })?;
                if !target_block.predecessors.contains(&block.id) {
                    return Err(LoweringError::MissingPredecessor {
                        block: target,
                        predecessor: block.id,
                    });
                }
            }
        }
        let mut predecessors = Vec::new();
        predecessors
            .try_reserve_exact(block.predecessors.len())
            .map_err(|_| LoweringError::Allocation {
                context: "checking duplicate native predecessors",
            })?;
        predecessors.extend_from_slice(&block.predecessors);
        predecessors.sort_unstable();

        if let Some(predecessor) = predecessors
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0])
        {
            return Err(LoweringError::DuplicatePredecessor {
                block: block.id,
                predecessor,
            });
        }
        for predecessor in &block.predecessors {
            let reciprocal = function
                .block(*predecessor)
                .filter(|source| source.id == *predecessor)
                .is_some_and(|source| {
                    source.successors.iter().any(
                        |edge| matches!(edge.target, EdgeTarget::Block(target) if target == block.id),
                    )
                });
            if !reciprocal {
                return Err(LoweringError::UnexpectedPredecessor {
                    block: block.id,
                    predecessor: *predecessor,
                });
            }
        }
        match block.terminator {
            Terminator::Jump
                if block
                    .last()
                    .is_some_and(|last| last.raw().is_jmp_short_or_near()) =>
            {
                let target = block
                    .last()
                    .expect("checked above")
                    .raw()
                    .near_branch_target();
                if let Ok(target) = u32::try_from(target) {
                    validate_edge_rva(function, block, EdgeKind::Jump, Rva(target))?;
                }
            }
            Terminator::Conditional
                if block
                    .last()
                    .is_some_and(|last| last.raw().is_jcc_short_or_near()) =>
            {
                let target = block
                    .last()
                    .expect("checked above")
                    .raw()
                    .near_branch_target();
                if let Ok(target) = u32::try_from(target) {
                    validate_edge_rva(function, block, EdgeKind::Taken, Rva(target))?;
                }
                validate_edge_rva(function, block, EdgeKind::NotTaken, block.end)?;
            }
            Terminator::FallThrough => {
                validate_edge_rva(function, block, EdgeKind::FallThrough, block.end)?;
            }
            Terminator::Return
            | Terminator::Jump
            | Terminator::Conditional
            | Terminator::IndirectJump
            | Terminator::ImportTailCall
            | Terminator::Halt
            | Terminator::Data => {}
        }
    }

    let blocks = ordered_blocks(function)?;
    let mut lowered = Output::default();
    let mut block_offsets = Vec::new();
    block_offsets
        .try_reserve_exact(blocks.len())
        .map_err(|_| LoweringError::Allocation {
            context: "retaining lowered basic-block offsets",
        })?;
    let mut branches = Vec::new();

    for block in blocks {
        let offset = u32::try_from(lowered.code_size).map_err(|_| LoweringError::SizeOverflow)?;
        block_offsets.push((block.start, offset));
        for instruction in &block.instructions {
            lower_instruction(&mut lowered, &mut branches, instruction)?;
        }
    }

    for branch in branches {
        let target =
            u32::try_from(branch.target).map_err(|_| LoweringError::InvalidBranchTarget {
                rva: branch.rva,
                target: branch.target,
            })?;
        let target = block_offsets
            .binary_search_by_key(&Rva(target), |(start, _)| *start)
            .ok()
            .and_then(|index| block_offsets.get(index).map(|(_, offset)| *offset))
            .ok_or(LoweringError::InvalidBranchTarget {
                rva: branch.rva,
                target: branch.target,
            })?;
        let instruction = lowered
            .instructions
            .get_mut(branch.instruction_index)
            .ok_or(LoweringError::SizeOverflow)?;
        match instruction {
            Instruction::Jmp { target: slot } | Instruction::Jcc { target: slot, .. } => {
                *slot = target;
            }
            _ => return Err(LoweringError::SizeOverflow),
        }
    }

    let entry_offset = block_offsets
        .binary_search_by_key(&function.entry, |(start, _)| *start)
        .ok()
        .and_then(|index| block_offsets.get(index).map(|(_, offset)| *offset))
        .ok_or(LoweringError::InvalidEntry {
            entry: function.entry,
        })?;
    Ok(Program::new(entry_offset, lowered.instructions))
}

fn validate_edge_rva(
    function: &Function,
    block: &BasicBlock,
    kind: EdgeKind,
    expected: Rva,
) -> Result<(), LoweringError> {
    let actual = block
        .successors
        .iter()
        .find(|edge| edge.kind == kind)
        .and_then(|edge| match edge.target {
            EdgeTarget::Block(target) => function.block(target),
            EdgeTarget::External(_) => None,
        })
        .map(|target| target.start)
        .ok_or(LoweringError::InvalidSuccessorShape {
            block: block.id,
            terminator: block.terminator,
        })?;
    if actual != expected {
        return Err(LoweringError::EdgeRvaMismatch {
            block: block.id,
            kind,
            expected,
            actual,
        });
    }
    Ok(())
}

fn ordered_blocks(function: &Function) -> Result<Vec<&BasicBlock>, LoweringError> {
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(function.blocks.len())
        .map_err(|_| LoweringError::Allocation {
            context: "ordering native basic blocks",
        })?;
    blocks.extend(function.blocks.iter());
    blocks.sort_unstable_by_key(|block| block.start);
    for blocks in blocks.windows(2) {
        if blocks[0].start == blocks[1].start {
            return Err(LoweringError::DuplicateBlockStart {
                rva: blocks[0].start,
            });
        }
        if blocks[0].end > blocks[1].start {
            return Err(LoweringError::OverlappingBlocks {
                first: blocks[0].id,
                second: blocks[1].id,
            });
        }
    }
    Ok(blocks)
}

#[derive(Debug, Clone, Copy)]
struct BranchFixup {
    instruction_index: usize,
    rva: Option<Rva>,
    target: u64,
}

fn lower_instruction(
    lowered: &mut Output,
    branches: &mut Vec<BranchFixup>,
    instruction: &vmp_ir::Instruction,
) -> Result<(), LoweringError> {
    let raw = instruction.raw();
    match raw.mnemonic() {
        Mnemonic::Mov if raw.op_count() == 2 && raw.op0_kind() == OpKind::Register => {
            let (register, width) = lower_register(instruction.rva(), raw.op0_register())?;
            push_source(lowered, instruction.rva(), raw, width)?;
            lowered.push(Instruction::PopReg { width, register })?;
        }
        mnemonic @ (Mnemonic::Add | Mnemonic::Sub | Mnemonic::Xor | Mnemonic::Cmp)
            if raw.op_count() == 2 && raw.op0_kind() == OpKind::Register =>
        {
            let (register, width) = lower_register(instruction.rva(), raw.op0_register())?;
            lowered.push(Instruction::PushReg { width, register })?;
            push_source(lowered, instruction.rva(), raw, width)?;
            lowered.push(match mnemonic {
                Mnemonic::Add => Instruction::Add(width),
                Mnemonic::Sub | Mnemonic::Cmp => Instruction::Sub(width),
                Mnemonic::Xor => Instruction::Xor(width),
                _ => unreachable!("guarded arithmetic mnemonic"),
            })?;
            if mnemonic == Mnemonic::Cmp {
                lowered.push(Instruction::Drop(width))?;
            } else {
                lowered.push(Instruction::PopReg { width, register })?;
            }
        }
        Mnemonic::Jmp if raw.is_jmp_short_or_near() => {
            push_branch(
                lowered,
                branches,
                instruction.rva(),
                raw.near_branch_target(),
                None,
            )?;
        }
        _ if raw.is_jcc_short_or_near() => {
            let condition = lower_condition(raw.condition_code())
                .ok_or_else(|| unsupported_instruction(instruction.rva(), raw))?;
            push_branch(
                lowered,
                branches,
                instruction.rva(),
                raw.near_branch_target(),
                Some(condition),
            )?;
        }
        Mnemonic::Ret if raw.code() == Code::Retnq => lowered.push(Instruction::Ret)?,
        _ => return Err(unsupported_instruction(instruction.rva(), raw)),
    }
    Ok(())
}

fn push_branch(
    lowered: &mut Output,
    branches: &mut Vec<BranchFixup>,
    rva: Option<Rva>,
    target: u64,
    condition: Option<Condition>,
) -> Result<(), LoweringError> {
    branches
        .try_reserve(1)
        .map_err(|_| LoweringError::Allocation {
            context: "retaining native branch fixups",
        })?;
    let instruction_index = lowered.instructions.len();
    lowered.push(match condition {
        Some(condition) => Instruction::Jcc {
            condition,
            target: 0,
        },
        None => Instruction::Jmp { target: 0 },
    })?;
    branches.push(BranchFixup {
        instruction_index,
        rva,
        target,
    });
    Ok(())
}

fn lower_condition(condition: NativeCondition) -> Option<Condition> {
    Some(match condition {
        NativeCondition::o => Condition::O,
        NativeCondition::no => Condition::No,
        NativeCondition::b => Condition::B,
        NativeCondition::ae => Condition::Ae,
        NativeCondition::e => Condition::E,
        NativeCondition::ne => Condition::Ne,
        NativeCondition::be => Condition::Be,
        NativeCondition::a => Condition::A,
        NativeCondition::s => Condition::S,
        NativeCondition::ns => Condition::Ns,
        NativeCondition::p => Condition::P,
        NativeCondition::np => Condition::Np,
        NativeCondition::l => Condition::L,
        NativeCondition::ge => Condition::Ge,
        NativeCondition::le => Condition::Le,
        NativeCondition::g => Condition::G,
        NativeCondition::None => return None,
    })
}

#[derive(Default)]
struct Output {
    instructions: Vec<Instruction>,
    code_size: usize,
}

impl Output {
    fn push(&mut self, instruction: Instruction) -> Result<(), LoweringError> {
        let count = self.instructions.len().saturating_add(1);
        if count > MAX_INSTRUCTIONS {
            return Err(LoweringError::TooManyInstructions {
                count,
                maximum: MAX_INSTRUCTIONS,
            });
        }
        self.instructions
            .try_reserve(1)
            .map_err(|_| LoweringError::Allocation {
                context: "growing lowered VM instructions",
            })?;
        let code_size = self
            .code_size
            .checked_add(instruction.encoded_len())
            .ok_or(LoweringError::SizeOverflow)?;
        self.instructions.push(instruction);
        self.code_size = code_size;
        Ok(())
    }
}

fn push_source(
    lowered: &mut Output,
    rva: Option<vmp_types::Rva>,
    raw: &NativeInstruction,
    width: Width,
) -> Result<(), LoweringError> {
    match raw.op1_kind() {
        OpKind::Register => {
            let (register, source_width) = lower_register(rva, raw.op1_register())?;
            if source_width != width {
                return Err(unsupported_instruction(rva, raw));
            }
            lowered.push(Instruction::PushReg { width, register })?;
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let value = raw
                .try_immediate(1)
                .map_err(|_| unsupported_instruction(rva, raw))?
                & width.mask();
            lowered.push(Instruction::PushImm { width, value })?;
        }
        _ => return Err(unsupported_instruction(rva, raw)),
    }
    Ok(())
}

fn lower_register(
    rva: Option<vmp_types::Rva>,
    native: NativeRegister,
) -> Result<(Register, Width), LoweringError> {
    if matches!(
        native,
        NativeRegister::AH | NativeRegister::CH | NativeRegister::DH | NativeRegister::BH
    ) || native.full_register() == NativeRegister::RSP
    {
        return Err(LoweringError::UnsupportedRegister {
            rva,
            register: native,
        });
    }

    let register = match native.full_register() {
        NativeRegister::RAX => Register::Rax,
        NativeRegister::RCX => Register::Rcx,
        NativeRegister::RDX => Register::Rdx,
        NativeRegister::RBX => Register::Rbx,
        NativeRegister::RBP => Register::Rbp,
        NativeRegister::RSI => Register::Rsi,
        NativeRegister::RDI => Register::Rdi,
        NativeRegister::R8 => Register::R8,
        NativeRegister::R9 => Register::R9,
        NativeRegister::R10 => Register::R10,
        NativeRegister::R11 => Register::R11,
        NativeRegister::R12 => Register::R12,
        NativeRegister::R13 => Register::R13,
        NativeRegister::R14 => Register::R14,
        NativeRegister::R15 => Register::R15,
        _ => {
            return Err(LoweringError::UnsupportedRegister {
                rva,
                register: native,
            });
        }
    };
    let width = match native.size() {
        1 => Width::Byte,
        2 => Width::Word,
        4 => Width::Dword,
        8 => Width::Qword,
        _ => {
            return Err(LoweringError::UnsupportedRegister {
                rva,
                register: native,
            });
        }
    };
    Ok((register, width))
}

fn unsupported_instruction(rva: Option<vmp_types::Rva>, raw: &NativeInstruction) -> LoweringError {
    LoweringError::UnsupportedInstruction {
        rva,
        code: raw.code(),
    }
}
