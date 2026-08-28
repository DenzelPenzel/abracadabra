//! Turning the flat sweep result into basic blocks.
//!
//! The C++ original never builds a control-flow graph: `CommandBlock` is an
//! emission chunk whose boundaries come from layout concerns, jump targets do
//! not start blocks, and predecessors do not exist at all
//! (`core/processors.cc:1155`, `core/intel.cc:15627`). Mutation and lowering
//! both need real edges, so blocks are rebuilt properly here.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use vmp_ir::{
    BasicBlock, BlockId, CompileStage, DecodeIssue, Edge, EdgeKind, EdgeTarget, Function,
    Terminator, UnwindRange,
};
use vmp_types::{Architecture, Rva};

use crate::decode::{FlowKind, LinkKind};
use crate::error::X86Error;
use crate::sweep::{Command, Link};

/// Builds the function from the decoded commands.
pub(crate) fn build(
    architecture: Architecture,
    entry: Rva,
    mut commands: BTreeMap<Rva, Command>,
    unwind: Option<UnwindRange>,
    mut issues: Vec<DecodeIssue>,
) -> Result<Function, X86Error> {
    if commands.is_empty() {
        return Err(X86Error::NothingDecoded { rva: entry });
    }

    let leaders = collect_leaders(entry, &commands, &mut issues);
    let ranges = split_ranges(&commands, &leaders);

    let starts: HashMap<Rva, BlockId> = ranges
        .iter()
        .enumerate()
        .filter_map(|(index, range)| Some((*range.first()?, BlockId(index as u32))))
        .collect();

    let mut blocks = Vec::with_capacity(ranges.len());
    for (index, range) in ranges.iter().enumerate() {
        blocks.push(build_block(
            BlockId(index as u32),
            range,
            &mut commands,
            &starts,
        ));
    }
    link_predecessors(&mut blocks);

    let entry_block = *starts
        .get(&entry)
        .ok_or(X86Error::NothingDecoded { rva: entry })?;

    Ok(Function {
        architecture,
        entry,
        blocks,
        entry_block,
        unwind,
        issues,
        stage: CompileStage::Decoded,
    })
}

/// Addresses that must begin a block: the entry, every internal branch target,
/// and whatever follows an instruction control cannot fall out of.
fn collect_leaders(
    entry: Rva,
    commands: &BTreeMap<Rva, Command>,
    issues: &mut Vec<DecodeIssue>,
) -> BTreeSet<Rva> {
    let mut leaders = BTreeSet::new();
    leaders.insert(entry);

    for (rva, command) in commands {
        if let Some(Link { kind, to }) = command.link {
            if matches!(kind, LinkKind::Jmp | LinkKind::JmpWithFlag) {
                if commands.contains_key(&to) {
                    leaders.insert(to);
                } else if covers(commands, to) {
                    // rejects this in `PrepareLinks` as `lsJumpToCommandPart`
                    issues.push(DecodeIssue::BranchIntoInstruction {
                        rva: *rva,
                        target: to,
                    });
                }
            }
        }

        let ends_run = command.flow.is_end()
            || command.flow.is_breaked()
            || command.flow == FlowKind::Conditional;
        if ends_run {
            if let Some(next) = command.next_rva() {
                if commands.contains_key(&next) {
                    leaders.insert(next);
                }
            }
        }
    }

    leaders
}

/// Groups consecutive commands into block-sized runs.
fn split_ranges(commands: &BTreeMap<Rva, Command>, leaders: &BTreeSet<Rva>) -> Vec<Vec<Rva>> {
    let mut ranges: Vec<Vec<Rva>> = Vec::new();
    let mut current: Vec<Rva> = Vec::new();
    let mut previous_end: Option<Rva> = None;

    for (rva, command) in commands {
        let split = !current.is_empty() && (leaders.contains(rva) || previous_end != Some(*rva));
        if split {
            ranges.push(std::mem::take(&mut current));
        }
        current.push(*rva);
        previous_end = command.next_rva();
    }
    if !current.is_empty() {
        ranges.push(current);
    }
    ranges
}

fn build_block(
    id: BlockId,
    range: &[Rva],
    commands: &mut BTreeMap<Rva, Command>,
    starts: &HashMap<Rva, BlockId>,
) -> BasicBlock {
    let start = range.first().copied().unwrap_or(Rva(0));
    let mut instructions = Vec::with_capacity(range.len());
    let mut flow = FlowKind::Normal;
    let mut link = None;
    let mut end = start;

    for rva in range {
        let Some(command) = commands.remove(rva) else {
            continue;
        };
        flow = command.flow;
        link = command.link;
        end = command.next_rva().unwrap_or(*rva);
        instructions.push(command.insn);
    }

    let resolve = |target: Rva| match starts.get(&target) {
        Some(id) => EdgeTarget::Block(*id),
        None => EdgeTarget::External(target),
    };

    let (terminator, successors) = match flow {
        FlowKind::Data => (Terminator::Data, Vec::new()),
        FlowKind::Halt => (Terminator::Halt, Vec::new()),
        FlowKind::Return => (Terminator::Return, Vec::new()),
        FlowKind::IndirectJump => (Terminator::IndirectJump, Vec::new()),
        FlowKind::ImportTailCall => (Terminator::ImportTailCall, Vec::new()),
        FlowKind::Jump => match link {
            Some(Link { to, .. }) => (
                Terminator::Jump,
                vec![Edge::new(EdgeKind::Jump, resolve(to))],
            ),
            None => (Terminator::IndirectJump, Vec::new()),
        },
        FlowKind::Conditional => {
            let mut edges = Vec::with_capacity(2);
            if let Some(Link { to, .. }) = link {
                edges.push(Edge::new(EdgeKind::Taken, resolve(to)));
            }
            edges.push(Edge::new(EdgeKind::NotTaken, resolve(end)));
            (Terminator::Conditional, edges)
        }
        FlowKind::Normal => (
            Terminator::FallThrough,
            vec![Edge::new(EdgeKind::FallThrough, resolve(end))],
        ),
    };

    BasicBlock {
        id,
        start,
        end,
        instructions,
        terminator,
        successors,
        predecessors: Vec::new(),
    }
}

fn link_predecessors(blocks: &mut [BasicBlock]) {
    let edges: Vec<(BlockId, BlockId)> = blocks
        .iter()
        .flat_map(|block| {
            block
                .successors
                .iter()
                .filter_map(move |edge| match edge.target {
                    EdgeTarget::Block(target) => Some((block.id, target)),
                    EdgeTarget::External(_) => None,
                })
        })
        .collect();

    for (from, to) in edges {
        if let Some(block) = blocks.get_mut(to.index()) {
            block.predecessors.push(from);
        }
    }
    for block in blocks.iter_mut() {
        block.predecessors.sort_unstable();
        block.predecessors.dedup();
    }
}

/// Whether some decoded instruction covers `rva` without starting at it.
fn covers(commands: &BTreeMap<Rva, Command>, rva: Rva) -> bool {
    use std::ops::Bound;

    commands
        .range((Bound::Unbounded, Bound::Excluded(rva)))
        .next_back()
        .and_then(|(start, command)| {
            let end = start.checked_add(command.insn.len() as u32)?;
            Some(rva < end)
        })
        .unwrap_or(false)
}
