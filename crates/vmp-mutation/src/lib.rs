//! Mutation of a decoded function: equivalent rewrites, liveness and inert
//! junk.
//!
//! The crate transforms [`vmp_ir::Function`] in place and knows nothing about
//! the PE container. Deciding *which* function to mutate, where the result is
//! placed and how the image is patched belongs to `vmp-emit`.
//!
//! # What a mutation may change
//!
//! Mutations normally change only the instruction stream. The one controlled
//! CFG metadata change is the indirect-jump-to-push-ret rewrite: it marks the
//! block as returning and clears successors. The result remains a valid input
//! to [`vmp_x86::relocate`].
//!
//! Addresses of mutated instructions are left as they were. They are identity,
//! not layout: the block encoder retargets a branch by matching its target
//! against the original address of an instruction in the same block, and
//! recomputes every displacement from the address the function is finally
//! encoded at.
//!
//! # Frozen ranges
//!
//! Some bytes of a function must be reproduced exactly, and [`Frozen`] is how a
//! caller says so. On x64 that is at least the prologue: `UNWIND_CODE` offsets
//! are measured from the start of the function, so changing the size of
//! anything inside the prologue invalidates the unwind description.

use std::collections::BTreeMap;

use iced_x86::{
    FlowControl, Instruction as RawInstruction, InstructionInfoFactory, Mnemonic, OpAccess,
    Register,
};
use vmp_ir::{Function, Instruction};
use vmp_types::{Architecture, Rva};
use vmp_x86::{analyze_liveness, encode_one};

mod junk;
mod rewrite;
mod rng;

pub use rng::{Rng, Seed};

/// Which transforms a run may apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Replace instructions with equivalent encodings.
    pub rewrites: bool,
    /// Insert instructions that disturb only what is provably dead.
    pub junk: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            rewrites: true,
            junk: true,
        }
    }
}

/// Which original instructions and insertion points a mutation run may touch.
///
/// `Exact` owns sorted, deduplicated RVA sets. It is used by SDK markers, whose
/// region follows CFG edges and cannot be represented faithfully as one interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationScope {
    All,
    Exact {
        rewrite_rvas: Vec<Rva>,
        insertion_after_rvas: Vec<Rva>,
    },
}

impl MutationScope {
    pub fn exact(mut rewrite_rvas: Vec<Rva>, mut insertion_after_rvas: Vec<Rva>) -> MutationScope {
        rewrite_rvas.sort_unstable();
        rewrite_rvas.dedup();
        insertion_after_rvas.sort_unstable();
        insertion_after_rvas.dedup();
        MutationScope::Exact {
            rewrite_rvas,
            insertion_after_rvas,
        }
    }

    fn allows_rewrite(&self, rva: Rva) -> bool {
        match self {
            MutationScope::All => true,
            MutationScope::Exact { rewrite_rvas, .. } => rewrite_rvas.binary_search(&rva).is_ok(),
        }
    }

    fn allows_insertion_after(&self, rva: Rva) -> bool {
        match self {
            MutationScope::All => true,
            MutationScope::Exact {
                insertion_after_rvas,
                ..
            } => insertion_after_rvas.binary_search(&rva).is_ok(),
        }
    }
}

/// Address ranges whose instructions must survive verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frozen {
    ranges: Vec<(Rva, Rva)>,
}

impl Frozen {
    pub fn new() -> Frozen {
        Frozen::default()
    }

    /// Freezes `begin..end`. An empty or reversed range is ignored, so a caller
    /// computing a range from unwind data does not have to special-case a
    /// function with no prologue.
    pub fn freeze(&mut self, begin: Rva, end: Rva) {
        if begin < end {
            self.ranges.push((begin, end));
        }
    }

    pub fn contains(&self, rva: Rva) -> bool {
        self.ranges
            .iter()
            .any(|(begin, end)| rva >= *begin && rva < *end)
    }

    pub fn allows_insertion_at(&self, rva: Rva) -> bool {
        !self
            .ranges
            .iter()
            .any(|(begin, end)| rva > *begin && rva < *end)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// What one mutation run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// How many times each transform fired, keyed by its stable name — a
    /// rewrite by the entry it matched, an insertion by the template placed.
    pub applied: BTreeMap<&'static str, usize>,
    /// Instructions the run considered.
    pub visited: usize,
    /// Instructions skipped because they sit in a [`Frozen`] range.
    pub frozen: usize,
}

impl Report {
    /// Total number of instructions the run changed.
    pub fn changes(&self) -> usize {
        self.applied.values().sum()
    }

    /// Whether the run left the function byte-identical.
    pub fn is_noop(&self) -> bool {
        self.changes() == 0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MutationError {
    /// The decoder could not account for every path, so rewriting the function
    /// would rewrite something we do not fully understand.
    #[error("function at {entry} is not completely decoded")]
    Incomplete { entry: Rva },
    /// A rewritten instruction did not encode. The catalogue is supposed to
    /// produce only encodable instructions, so this is a defect in the
    /// catalogue rather than a property of the input.
    #[error("re-encoding the instruction at {rva} failed: {reason}")]
    Encode { rva: Rva, reason: String },
}

/// Applies the enabled transforms to `function`.
///
/// Deterministic: the same function, seed and options always produce the same
/// result. The random stream is derived from the function's entry address, so
/// mutating a different set of functions does not change what happens to this
/// one.
pub fn mutate(
    function: &mut Function,
    frozen: &Frozen,
    seed: Seed,
    options: &Options,
) -> Result<Report, MutationError> {
    mutate_scoped(function, frozen, &MutationScope::All, seed, options)
}

/// Applies transforms only at addresses admitted by `scope`.
pub fn mutate_scoped(
    function: &mut Function,
    frozen: &Frozen,
    scope: &MutationScope,
    seed: Seed,
    options: &Options,
) -> Result<Report, MutationError> {
    mutate_scoped_with_encoder(
        function,
        frozen,
        scope,
        seed,
        options,
        |architecture, raw, rva| {
            encode_one(architecture, raw, rva).map_err(|error| error.to_string())
        },
    )
}

fn mutate_scoped_with_encoder(
    function: &mut Function,
    frozen: &Frozen,
    scope: &MutationScope,
    seed: Seed,
    options: &Options,
    mut encode: impl FnMut(Architecture, &RawInstruction, Rva) -> Result<Vec<u8>, String>,
) -> Result<Report, MutationError> {
    if !function.is_complete() {
        return Err(MutationError::Incomplete {
            entry: function.entry,
        });
    }

    let mut staged = function.clone();
    let architecture = staged.architecture;
    let rewrite_liveness = options.rewrites.then(|| analyze_liveness(&staged));
    let mut rng = seed.for_function(staged.entry.get());
    let mut report = Report::default();

    for block in &mut staged.blocks {
        let original = block.instructions.clone();
        let mut rebuilt = Vec::with_capacity(original.len());
        let mut replacement_terminator = None;
        for mut instruction in original {
            report.visited += 1;
            let Some(rva) = instruction.rva() else {
                rebuilt.push(instruction);
                continue;
            };
            if frozen.contains(rva) {
                report.frozen += 1;
                rebuilt.push(instruction);
                continue;
            }
            if !scope.allows_rewrite(rva) || !options.rewrites {
                rebuilt.push(instruction);
                continue;
            }

            let dead_after = rewrite_liveness
                .as_ref()
                .and_then(|liveness| liveness.dead_after(rva))
                .map(|state| state.flags);
            let mut inserted = None;
            for entry in rewrite::CATALOGUE {
                let Some(replacement) = (entry.apply)(instruction.raw(), architecture, dead_after)
                else {
                    continue;
                };
                // The coin is flipped only once a rewrite matches, so the
                // stream is consumed at the sites that matter and stays stable
                // when an unrelated instruction changes.
                if rng.coin() {
                    replacement_terminator = replacement.terminator;
                    let bytes = encode(architecture, &replacement.first, rva)
                        .map_err(|reason| MutationError::Encode { rva, reason })?;
                    instruction.replace(replacement.first, &bytes);
                    if let Some(second) = replacement.second {
                        let bytes = encode(architecture, &second, rva)
                            .map_err(|reason| MutationError::Encode { rva, reason })?;
                        inserted = Some(Instruction::inserted(second, &bytes));
                    }
                    *report.applied.entry(entry.name).or_default() += 1;
                }
                // At most one rewrite per instruction, as in the original's
                // `switch`.
                break;
            }
            rebuilt.push(instruction);
            rebuilt.extend(inserted);
        }
        block.instructions = rebuilt;
        if let Some(terminator) = replacement_terminator {
            block.terminator = terminator;
            block.successors.clear();
        }
    }

    if options.junk {
        insert_junk(
            &mut staged,
            frozen,
            scope,
            &mut rng,
            &mut report,
            &mut encode,
        )?;
    }

    *function = staged;
    Ok(report)
}

/// Places inert instructions wherever the point after an instruction admits
/// one.
///
/// Runs after the rewrites so the liveness it consults describes the code that
/// will actually be emitted: a rewrite may leave a flag defined that the
/// original left undefined, and the insertion is entitled to the better answer.
fn insert_junk(
    function: &mut Function,
    frozen: &Frozen,
    scope: &MutationScope,
    rng: &mut Rng,
    report: &mut Report,
    encode: &mut impl FnMut(Architecture, &RawInstruction, Rva) -> Result<Vec<u8>, String>,
) -> Result<(), MutationError> {
    let architecture = function.architecture;
    let liveness = analyze_liveness(function);
    let mut factory = InstructionInfoFactory::new();

    for block in &mut function.blocks {
        let original = block.instructions.clone();
        let mut rebuilt = Vec::with_capacity(original.len());
        let mut applied = BTreeMap::<&'static str, usize>::new();

        for instruction in original {
            let site = insertion_point(&instruction, frozen, scope, &mut factory);
            // The liveness question is asked of the instruction being followed,
            // not of the address the insertion gets. `at` is where the *next*
            // instruction starts, and `dead_after` keyed by that address would
            // answer for the point one instruction further on — past a reader of
            // the very flag the insertion is about to write.
            let after = instruction.rva();
            rebuilt.push(instruction);

            let (Some(at), Some(after)) = (site, after) else {
                continue;
            };
            let Some(dead) = liveness.dead_after(after) else {
                continue;
            };

            let mut candidates = junk::candidates(architecture, dead);
            if candidates.is_empty() {
                continue;
            }

            // Drawn only once a point admits something, so the stream is
            // consumed where it matters and adding a template later does not
            // shift what happens at unrelated points
            let Some(count) = rng.below(4) else {
                continue;
            };
            for _ in 0..count {
                let Some((name, raw)) = junk::select_candidate(rng, architecture, &mut candidates)
                else {
                    break;
                };
                let bytes = encode(architecture, &raw, at)
                    .map_err(|reason| MutationError::Encode { rva: at, reason })?;
                rebuilt.push(Instruction::inserted(raw, &bytes));
                *applied.entry(name).or_default() += 1;
            }
        }

        block.instructions = rebuilt;
        for (name, count) in applied {
            *report.applied.entry(name).or_default() += count;
        }
    }

    Ok(())
}

/// The address an instruction may be inserted at just after `instruction`, if
/// one may be.
///
/// Four refusals. Control leaving the straight-line run ends it, which is the
/// original's `is_end` (`core/intel.cc:16373`) and covers `call` for the same
/// reason it does — the free set past a control transfer is not something
/// either analysis is willing to claim. An instruction that opens an interrupt
/// shadow may not be parted from the one it shadows. An instruction the
/// mutation itself produced has no address, so there is no point after it to
/// name. And a frozen run may not be split.
fn insertion_point(
    instruction: &Instruction,
    frozen: &Frozen,
    scope: &MutationScope,
    factory: &mut InstructionInfoFactory,
) -> Option<Rva> {
    if instruction.raw().flow_control() != FlowControl::Next {
        return None;
    }
    if opens_interrupt_shadow(factory, instruction.raw()) {
        return None;
    }
    let source = instruction.rva()?;
    let at = instruction.next_rva()?;
    (frozen.allows_insertion_at(at) && scope.allows_insertion_after(source)).then_some(at)
}

/// Whether the instruction defers interrupts until the one after it has run.
///
/// Three instructions do, and in each case the deferral is the point of the
/// sequence rather than an accident of it. `STI` enables interrupts only "at
/// the end of the next instruction", so `sti; cli` is guaranteed to recognise
/// none at all, and `sti; hlt` cannot lose a wakeup. Loading `SS` "inhibits
/// interrupts on the following instruction boundary", which is what lets
/// `mov ss, ax; mov rsp, rbp` install a stack without an event arriving between
/// the halves. An instruction inserted after any of them becomes the one that
/// is shadowed, and the one that needed the shadow loses it.
///
/// The `SS` half keys on the effect rather than on a list of opcodes, the same
/// way epilogue recognition keys on writes to `RSP`. A list can be short by an
/// encoding, and being short here is a race in someone else's driver that no
/// test of ours would ever see. `LSS` is caught by the effect although the
/// manuals name only `MOV SS` and `POP SS`; the wider gate costs nothing, since
/// the fixture contains no shadow instruction at all.
fn opens_interrupt_shadow(factory: &mut InstructionInfoFactory, raw: &RawInstruction) -> bool {
    if raw.mnemonic() == Mnemonic::Sti {
        return true;
    }
    factory
        .info(raw)
        .used_registers()
        .iter()
        .any(|used| used.register() == Register::SS && writes(used.access()))
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

#[cfg(test)]
mod tests {
    use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    use vmp_ir::{
        BasicBlock, BlockId, CompileStage, Edge, EdgeKind, EdgeTarget, OperandRef, Origin,
        Terminator, UnwindRange,
    };
    use vmp_types::Architecture;

    use super::*;

    /// One block of straight-line code at `0x1000` ending in `ret`.
    fn straight_line(bytes: &[u8]) -> Function {
        straight_line_for(Architecture::X64, bytes)
    }

    fn straight_line_for(architecture: Architecture, bytes: &[u8]) -> Function {
        let block = decoded_block(architecture, BlockId(0), Rva(0x1000), bytes);
        Function {
            architecture,
            entry: Rva(0x1000),
            blocks: vec![block],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    fn decoded_block(
        architecture: Architecture,
        id: BlockId,
        start: Rva,
        bytes: &[u8],
    ) -> BasicBlock {
        let bitness = match architecture {
            Architecture::X86 => 32,
            Architecture::X64 => 64,
        };
        let mut decoder =
            Decoder::with_ip(bitness, bytes, u64::from(start.get()), DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let offset = usize::try_from(raw.ip() - u64::from(start.get()))
                .expect("test block offset fits usize");
            instructions.push(Instruction::decoded(
                Rva(raw.ip() as u32),
                raw,
                &bytes[offset..offset + raw.len()],
            ));
        }
        let end = instructions
            .last()
            .and_then(|last| last.next_rva())
            .expect("the test bytes decode to at least one instruction");
        BasicBlock {
            id,
            start,
            end,
            instructions,
            terminator: Terminator::Return,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FunctionSnapshot {
        architecture: Architecture,
        entry: Rva,
        blocks: Vec<BlockSnapshot>,
        entry_block: BlockId,
        unwind: Option<UnwindRange>,
        issues: Vec<vmp_ir::DecodeIssue>,
        stage: CompileStage,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct BlockSnapshot {
        id: BlockId,
        start: Rva,
        end: Rva,
        instructions: Vec<InstructionSnapshot>,
        terminator: Terminator,
        successors: Vec<Edge>,
        predecessors: Vec<BlockId>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct InstructionSnapshot {
        origin: Origin,
        raw: RawInstruction,
        bytes: Vec<u8>,
        refs: Vec<OperandRef>,
    }

    fn snapshot(function: &Function) -> FunctionSnapshot {
        FunctionSnapshot {
            architecture: function.architecture,
            entry: function.entry,
            blocks: function
                .blocks
                .iter()
                .map(|block| BlockSnapshot {
                    id: block.id,
                    start: block.start,
                    end: block.end,
                    instructions: block
                        .instructions
                        .iter()
                        .map(|instruction| InstructionSnapshot {
                            origin: instruction.origin(),
                            raw: *instruction.raw(),
                            bytes: instruction.bytes().to_vec(),
                            refs: instruction.refs().to_vec(),
                        })
                        .collect(),
                    terminator: block.terminator,
                    successors: block.successors.clone(),
                    predecessors: block.predecessors.clone(),
                })
                .collect(),
            entry_block: function.entry_block,
            unwind: function.unwind,
            issues: function.issues.clone(),
            stage: function.stage,
        }
    }

    fn function_with_blocks(mut blocks: Vec<BasicBlock>) -> Function {
        blocks[0].predecessors.push(BlockId(1));
        blocks[1].predecessors.push(BlockId(0));
        Function {
            architecture: Architecture::X64,
            entry: Rva(0x1000),
            blocks,
            entry_block: BlockId(0),
            unwind: Some(UnwindRange {
                begin: Rva(0x1000),
                end: Rva(0x2007),
                unwind_info: Rva(0x3000),
            }),
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    fn decode_emitted(architecture: Architecture, instruction: &Instruction) -> RawInstruction {
        let bitness = match architecture {
            Architecture::X86 => 32,
            Architecture::X64 => 64,
        };
        Decoder::with_ip(
            bitness,
            instruction.bytes(),
            instruction.rva().map_or(0, |rva| u64::from(rva.get())),
            DecoderOptions::NONE,
        )
        .decode()
    }

    fn original_bytes_at<'a>(bytes: &'a [u8], instruction: &Instruction) -> &'a [u8] {
        let Some(rva) = instruction.rva() else {
            return &[];
        };
        let offset = usize::try_from(rva.get() - 0x1000).expect("small test RVA");
        &bytes[offset..offset + instruction.len()]
    }

    fn rewritten_function(architecture: Architecture, bytes: &[u8]) -> Option<Function> {
        let options = Options {
            rewrites: true,
            junk: false,
        };
        for seed in 0..64 {
            let mut function = straight_line_for(architecture, bytes);
            mutate(&mut function, &Frozen::new(), Seed::new(seed), &options).expect("mutates");
            if function
                .instructions()
                .any(|instruction| instruction.bytes() != original_bytes_at(bytes, instruction))
            {
                return Some(function);
            }
        }
        None
    }

    fn assert_never_rewritten(architecture: Architecture, bytes: &[u8]) {
        assert!(
            rewritten_function(architecture, bytes).is_none(),
            "an unsupported or unsafe source instruction was rewritten: {bytes:02x?}"
        );
    }

    #[test]
    fn add_register_to_full_width_register_becomes_equivalent_lea() {
        // add rax, rbx / add rcx, rdx / ret. The second add kills every flag
        // clobbered by the first, while RAX remains live at the return boundary.
        let bytes = &[0x48, 0x01, 0xd8, 0x48, 0x01, 0xd1, 0xc3];
        let function = rewritten_function(Architecture::X64, bytes)
            .expect("some deterministic seed must select the add rewrite");
        let emitted = decode_emitted(Architecture::X64, &function.blocks[0].instructions[0]);
        assert_eq!(emitted.mnemonic(), Mnemonic::Lea);
        assert_eq!(emitted.op0_kind(), OpKind::Register);
        assert_eq!(emitted.op0_register(), Register::RAX);
        assert_eq!(emitted.op1_kind(), OpKind::Memory);
        assert_eq!(emitted.memory_base(), Register::RAX);
        assert_eq!(emitted.memory_index(), Register::RBX);
        assert_eq!(emitted.memory_index_scale(), 1);
        assert_eq!(emitted.memory_displacement64(), 0);
    }

    #[test]
    fn add_and_sub_immediates_become_lea_displacements_on_x86() {
        for (bytes, displacement) in [
            (&[0x83, 0xc0, 0x20, 0x01, 0xd1, 0xc3][..], 32u64),
            (&[0x83, 0xe8, 0x20, 0x01, 0xd1, 0xc3][..], 0xffff_ffe0u64),
        ] {
            let function = rewritten_function(Architecture::X86, bytes)
                .expect("some deterministic seed must select the immediate rewrite");
            let emitted = decode_emitted(Architecture::X86, &function.blocks[0].instructions[0]);
            assert_eq!(emitted.mnemonic(), Mnemonic::Lea);
            assert_eq!(emitted.op0_register(), Register::EAX);
            assert_eq!(emitted.op1_kind(), OpKind::Memory);
            assert_eq!(emitted.memory_base(), Register::EAX);
            assert_eq!(emitted.memory_index(), Register::None);
            assert_eq!(emitted.memory_displacement64(), displacement);
        }
    }

    #[test]
    fn add_and_sub_rewrites_reject_unsafe_operand_and_flag_cases() {
        for bytes in [
            // Destination is memory.
            &[0x48, 0x01, 0x18, 0x48, 0x01, 0xd1, 0xc3][..],
            // Source is memory.
            &[0x48, 0x03, 0x01, 0x48, 0x01, 0xd1, 0xc3][..],
            // Destination is the stack pointer.
            &[0x48, 0x01, 0xdc, 0x48, 0x01, 0xd1, 0xc3][..],
            // RSP cannot be a SIB index.
            &[0x48, 0x01, 0xe0, 0x48, 0x01, 0xd1, 0xc3][..],
            // Register source is unsupported for sub.
            &[0x48, 0x29, 0xd8, 0x48, 0x01, 0xd1, 0xc3][..],
            // The following ADC reads CF, so not every clobbered flag is dead.
            &[0x48, 0x01, 0xd8, 0x48, 0x11, 0xd1, 0xc3][..],
            // Immediate forms are intentionally limited to 32-bit address size.
            &[0x48, 0x83, 0xc0, 0x20, 0x48, 0x01, 0xd1, 0xc3][..],
        ] {
            assert_never_rewritten(Architecture::X64, bytes);
        }
        // ESP destination is rejected on x86 too.
        assert_never_rewritten(Architecture::X86, &[0x83, 0xc4, 0x20, 0x01, 0xd1, 0xc3]);
    }

    #[test]
    fn near_indirect_jump_becomes_physical_push_and_ret() {
        for (architecture, bytes, operand_kind, register) in [
            (
                Architecture::X64,
                &[0xff, 0xe0][..],
                OpKind::Register,
                Register::RAX,
            ),
            (
                Architecture::X64,
                &[0xff, 0x60, 0x08][..],
                OpKind::Memory,
                Register::RAX,
            ),
            (
                Architecture::X86,
                &[0xff, 0xe1][..],
                OpKind::Register,
                Register::ECX,
            ),
        ] {
            let function = rewritten_function(architecture, bytes)
                .expect("some deterministic seed must select the jump rewrite");
            assert_eq!(function.blocks[0].instructions.len(), 2);
            let push = decode_emitted(architecture, &function.blocks[0].instructions[0]);
            let ret = decode_emitted(architecture, &function.blocks[0].instructions[1]);
            assert_eq!(push.mnemonic(), Mnemonic::Push);
            assert_eq!(push.op0_kind(), operand_kind);
            if operand_kind == OpKind::Register {
                assert_eq!(push.op0_register(), register);
            } else {
                assert_eq!(push.memory_base(), register);
                assert_eq!(push.memory_displacement64(), 8);
            }
            assert_eq!(ret.mnemonic(), Mnemonic::Ret);
            assert!(function.blocks[0].instructions[1].rva().is_none());
        }
    }

    #[test]
    fn indirect_jump_rewrite_updates_the_block_terminator() {
        let options = Options {
            rewrites: true,
            junk: false,
        };
        for (architecture, bytes, push_code, ret_code) in [
            (
                Architecture::X64,
                &[0xff, 0xe0][..],
                Code::Push_rm64,
                Code::Retnq,
            ),
            (
                Architecture::X86,
                &[0xff, 0xe0][..],
                Code::Push_rm32,
                Code::Retnd,
            ),
        ] {
            let mut rewritten = false;
            for seed in 0..64 {
                let mut function = straight_line_for(architecture, bytes);
                function.blocks[0].terminator = Terminator::IndirectJump;
                function.blocks[0]
                    .successors
                    .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x2000))));
                let report = mutate(&mut function, &Frozen::new(), Seed::new(seed), &options)
                    .expect("mutates");
                if report.applied.contains_key("indirect-jump-to-push-ret") {
                    let block = &function.blocks[0];
                    assert_eq!(block.terminator, Terminator::Return);
                    assert!(block.successors.is_empty());
                    assert_eq!(block.instructions.len(), 2);
                    assert_eq!(
                        decode_emitted(architecture, &block.instructions[0]).code(),
                        push_code
                    );
                    assert_eq!(
                        decode_emitted(architecture, &block.instructions[1]).code(),
                        ret_code
                    );
                    rewritten = true;
                    break;
                }
            }
            assert!(
                rewritten,
                "the seed sweep did not select the {architecture:?} rewrite"
            );
        }
    }

    #[test]
    fn encoder_failure_leaves_the_original_block_unchanged() {
        let options = Options {
            rewrites: true,
            junk: false,
        };
        for seed in 0..64 {
            let mut function = straight_line(&[0xff, 0xe0]);
            function.blocks[0].terminator = Terminator::IndirectJump;
            function.blocks[0]
                .successors
                .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x2000))));
            let original_instructions = function.blocks[0]
                .instructions
                .iter()
                .map(|instruction| (instruction.rva(), instruction.bytes().to_vec()))
                .collect::<Vec<_>>();
            let original_terminator = function.blocks[0].terminator;
            let original_successors = function.blocks[0].successors.clone();
            let mut encodes = 0;

            let result = mutate_scoped_with_encoder(
                &mut function,
                &Frozen::new(),
                &MutationScope::All,
                Seed::new(seed),
                &options,
                |architecture, raw, rva| {
                    encodes += 1;
                    if encodes == 2 {
                        return Err("injected encoder failure".to_owned());
                    }
                    encode_one(architecture, raw, rva).map_err(|error| error.to_string())
                },
            );
            if let Err(MutationError::Encode { reason, .. }) = result {
                assert_eq!(reason, "injected encoder failure");
                let block = &function.blocks[0];
                let instructions = block
                    .instructions
                    .iter()
                    .map(|instruction| (instruction.rva(), instruction.bytes().to_vec()))
                    .collect::<Vec<_>>();
                assert_eq!(instructions, original_instructions);
                assert_eq!(block.terminator, original_terminator);
                assert_eq!(block.successors, original_successors);
                return;
            }
        }
        panic!("the seed sweep did not reach the injected encoder failure");
    }

    #[test]
    fn junk_encoder_failure_leaves_the_original_block_unchanged() {
        let options = Options {
            rewrites: false,
            junk: true,
        };
        for seed in 0..256 {
            // nop / mov eax, 1 / ret: only RAX is dead after the nop.
            let mut function = straight_line(&[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
            let original = function.blocks[0]
                .instructions
                .iter()
                .map(|instruction| (instruction.rva(), instruction.bytes().to_vec()))
                .collect::<Vec<_>>();
            let mut encodes = 0;
            let result = mutate_scoped_with_encoder(
                &mut function,
                &Frozen::new(),
                &MutationScope::All,
                Seed::new(seed),
                &options,
                |architecture, raw, rva| {
                    encodes += 1;
                    if encodes == 2 {
                        return Err("injected junk encoder failure".to_owned());
                    }
                    encode_one(architecture, raw, rva).map_err(|error| error.to_string())
                },
            );
            if matches!(result, Err(MutationError::Encode { .. })) {
                let actual = function.blocks[0]
                    .instructions
                    .iter()
                    .map(|instruction| (instruction.rva(), instruction.bytes().to_vec()))
                    .collect::<Vec<_>>();
                assert_eq!(actual, original);
                return;
            }
        }
        panic!("seed sweep did not produce two junk encodes");
    }

    #[test]
    fn later_block_rewrite_failure_rolls_back_the_whole_function() {
        let options = Options {
            rewrites: true,
            junk: false,
        };
        for seed in 0..256 {
            let mut first =
                decoded_block(Architecture::X64, BlockId(0), Rva(0x1000), &[0xff, 0xe0]);
            first.terminator = Terminator::IndirectJump;
            first
                .successors
                .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x4000))));
            let mut second =
                decoded_block(Architecture::X64, BlockId(1), Rva(0x2000), &[0xff, 0xe1]);
            second.terminator = Terminator::IndirectJump;
            second
                .successors
                .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x5000))));
            let mut function = function_with_blocks(vec![first, second]);
            let original = snapshot(&function);
            let mut encodes = 0;

            let result = mutate_scoped_with_encoder(
                &mut function,
                &Frozen::new(),
                &MutationScope::All,
                Seed::new(seed),
                &options,
                |architecture, raw, rva| {
                    encodes += 1;
                    if encodes == 3 {
                        return Err("later block encoder failure".to_owned());
                    }
                    encode_one(architecture, raw, rva).map_err(|error| error.to_string())
                },
            );

            if let Err(MutationError::Encode { rva, reason }) = result {
                assert_eq!(rva, Rva(0x2000));
                assert_eq!(reason, "later block encoder failure");
                assert_eq!(encodes, 3, "the first block completed both encodes");
                assert_eq!(snapshot(&function), original);
                return;
            }
        }
        panic!("the seed sweep did not rewrite both blocks");
    }

    #[test]
    fn junk_failure_after_rewrite_staging_rolls_back_the_whole_function() {
        let options = Options {
            rewrites: true,
            junk: true,
        };
        let scope = MutationScope::exact(vec![Rva(0x1000)], vec![Rva(0x2000)]);
        for seed in 0..1024 {
            let mut first =
                decoded_block(Architecture::X64, BlockId(0), Rva(0x1000), &[0xff, 0xe0]);
            first.terminator = Terminator::IndirectJump;
            first
                .successors
                .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x4000))));
            let second = decoded_block(
                Architecture::X64,
                BlockId(1),
                Rva(0x2000),
                &[0x90, 0xb8, 1, 0, 0, 0, 0xc3],
            );
            let mut function = function_with_blocks(vec![first, second]);
            let original = snapshot(&function);
            let mut rewrite_encodes = 0;

            let result = mutate_scoped_with_encoder(
                &mut function,
                &Frozen::new(),
                &scope,
                Seed::new(seed),
                &options,
                |architecture, raw, rva| {
                    if junk::classify(architecture, raw).is_some() && rewrite_encodes == 2 {
                        return Err("junk encoder failure after rewrite".to_owned());
                    }
                    if matches!(raw.code(), Code::Push_rm64 | Code::Retnq) {
                        rewrite_encodes += 1;
                    }
                    encode_one(architecture, raw, rva).map_err(|error| error.to_string())
                },
            );

            if let Err(MutationError::Encode { rva, reason }) = result {
                assert_eq!(rva, Rva(0x2001));
                assert_eq!(reason, "junk encoder failure after rewrite");
                assert_eq!(rewrite_encodes, 2, "the rewrite phase completed first");
                assert_eq!(snapshot(&function), original);
                return;
            }
        }
        panic!("the seed sweep did not stage a rewrite followed by junk");
    }

    fn inserted_registers(architecture: Architecture, bytes: &[u8]) -> Vec<Register> {
        let options = Options {
            rewrites: false,
            junk: true,
        };
        let mut registers = Vec::new();
        for seed in 0..128 {
            let mut function = straight_line_for(architecture, bytes);
            mutate(&mut function, &Frozen::new(), Seed::new(seed), &options).expect("mutates");
            registers.extend(
                function.blocks[0]
                    .instructions
                    .iter()
                    .filter(|instruction| instruction.rva().is_none())
                    .map(|instruction| instruction.raw().op0_register())
                    .filter(|register| *register != Register::None),
            );
        }
        registers
    }

    #[test]
    fn only_rax_dead_means_every_register_junk_form_uses_eax_or_rax() {
        let registers = inserted_registers(Architecture::X64, &[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
        assert!(!registers.is_empty());
        assert!(
            registers
                .iter()
                .all(|register| register.full_register() == Register::RAX),
            "{registers:?}"
        );
    }

    #[test]
    fn live_cf_excludes_flag_forms_but_register_forms_still_occur() {
        let options = Options {
            rewrites: false,
            junk: true,
        };
        let mut names = BTreeMap::new();
        for seed in 0..128 {
            let mut function = straight_line(&[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
            let report =
                mutate(&mut function, &Frozen::new(), Seed::new(seed), &options).expect("mutates");
            names.extend(report.applied);
        }
        assert!(names.keys().any(|name| matches!(
            *name,
            "junk-mov-imm32"
                | "junk-mov-imm64"
                | "junk-not32"
                | "junk-not64"
                | "junk-bswap32"
                | "junk-bswap64"
        )));
        assert!(!names
            .keys()
            .any(|name| matches!(*name, "junk-clc" | "junk-stc" | "junk-cmc")));
    }

    #[test]
    fn no_dead_gpr_but_dead_cf_means_only_flag_forms() {
        let options = Options {
            rewrites: false,
            junk: true,
        };
        for seed in 0..128 {
            let mut function = straight_line(&[0x90, 0x01, 0xd8, 0xc3]);
            let report =
                mutate(&mut function, &Frozen::new(), Seed::new(seed), &options).expect("mutates");
            assert!(
                report
                    .applied
                    .keys()
                    .all(|name| matches!(*name, "junk-clc" | "junk-stc" | "junk-cmc")),
                "{:?}",
                report.applied
            );
        }
    }

    #[test]
    fn x86_junk_never_uses_64_bit_or_extended_registers() {
        let registers = inserted_registers(Architecture::X86, &[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
        assert!(!registers.is_empty());
        assert!(
            registers
                .iter()
                .all(|register| register.full_register() == Register::RAX),
            "{registers:?}"
        );
    }

    #[test]
    fn jump_rewrite_rejects_direct_far_and_unsupported_width_forms() {
        // Direct near jump.
        assert_never_rewritten(Architecture::X64, &[0xeb, 0x00]);
        // Far memory jump m16:64.
        assert_never_rewritten(Architecture::X64, &[0x48, 0xff, 0x28]);
        // Operand-size override selects r/m16 and cannot pair with a native ret.
        assert_never_rewritten(Architecture::X86, &[0x66, 0xff, 0xe0]);
    }

    fn insertion_sites(bytes: &[u8], frozen: &Frozen, options: &Options) -> (Vec<Rva>, usize) {
        let mut sites = Vec::new();
        let mut seeds_with_work = 0;
        for seed in 0..32u64 {
            let mut function = straight_line(bytes);
            let report = mutate(&mut function, frozen, Seed::new(seed), options).expect("mutates");
            let mut inserted_here = 0;
            let mut previous = None;
            for instruction in &function.blocks[0].instructions {
                match instruction.rva() {
                    Some(rva) => previous = Some(rva),
                    None => {
                        assert!(junk::classify(Architecture::X64, instruction.raw()).is_some());
                        sites.push(previous.expect("an insertion follows some instruction"));
                        inserted_here += 1;
                    }
                }
            }
            let claimed: usize = report
                .applied
                .iter()
                .filter(|(name, _)| name.starts_with("junk-"))
                .map(|(_, count)| *count)
                .sum();
            assert_eq!(inserted_here, claimed, "seed {seed}: the report disagrees");
            if inserted_here > 0 {
                seeds_with_work += 1;
            }
        }
        (sites, seeds_with_work)
    }

    // mov eax, 1 / add eax, ebx / ret — CF is dead only after the `mov`, since
    // the `add` overwrites it and the `ret` is a boundary where everything is
    // assumed live
    const MOV_ADD_RET: &[u8] = &[0xb8, 0x01, 0x00, 0x00, 0x00, 0x01, 0xd8, 0xc3];

    #[test]
    fn junk_lands_only_where_the_flag_it_writes_is_dead() {
        let (sites, with_work) = insertion_sites(MOV_ADD_RET, &Frozen::new(), &Options::default());
        assert!(
            with_work > 0,
            "no seed inserted anything; the sweep proves nothing"
        );
        assert!(
            sites.iter().all(|rva| *rva == Rva(0x1000)),
            "junk appeared somewhere other than after the mov: {sites:?}"
        );
    }

    #[test]
    fn nothing_is_inserted_after_a_call() {
        // mov eax, 1 / add eax, ebx / call +0 / add ecx, edx / ret
        //
        // CF is dead at two points here: after the `mov`, because the first
        // `add` overwrites it, and after the `call`, because the second one
        // does. Only the flow-control gate tells them apart. Note that CF is
        // *not* dead after the first `add` — a call reads everything, so the
        // point before it is a boundary like any other.
        let bytes = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, 0x01, 0xd8, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x01, 0xd1,
            0xc3,
        ];
        let (sites, with_work) = insertion_sites(bytes, &Frozen::new(), &Options::default());
        assert!(with_work > 0, "the sweep must exercise insertion");
        assert!(
            sites.iter().all(|rva| *rva == Rva(0x1000)),
            "junk followed the call at 0x1007: {sites:?}"
        );
    }

    #[test]
    fn exact_scope_keeps_rewrites_and_insertions_inside_its_rva_sets() {
        let scope = MutationScope::exact(
            vec![Rva(0x1005), Rva(0x1005)],
            vec![Rva(0x100a), Rva(0x100a)],
        );
        assert!(!scope.allows_rewrite(Rva(0x1000)));
        assert!(scope.allows_rewrite(Rva(0x1005)));
        assert!(!scope.allows_rewrite(Rva(0x100a)));
        assert!(!scope.allows_insertion_after(Rva(0x1005)));
        assert!(scope.allows_insertion_after(Rva(0x100a)));
        assert!(!scope.allows_insertion_after(Rva(0x100b)));
    }

    #[test]
    fn a_frozen_range_is_closed_inside_and_open_at_its_end() {
        // mov eax, 1 / mov ecx, 2 / add eax, ebx / ret, with the two movs
        // frozen. The point after the first is strictly inside and refused; the
        // point after the second is the range's end and allowed.
        let bytes = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00, 0x00, 0x00, 0x01, 0xd8, 0xc3,
        ];
        let mut frozen = Frozen::new();
        frozen.freeze(Rva(0x1000), Rva(0x100a));

        let (sites, with_work) = insertion_sites(bytes, &frozen, &Options::default());
        assert!(with_work > 0, "the sweep must exercise insertion");
        assert!(
            sites.iter().all(|rva| *rva == Rva(0x1005)),
            "junk reached a point inside the frozen range: {sites:?}"
        );
    }

    /// An instruction that opens an interrupt shadow protects the one after it,
    /// and an insertion would take that protection for itself.
    ///
    /// The control is what makes this a test of the gate rather than of nothing:
    /// it is the same three instructions with a `nop` in front instead, and it
    /// has to insert. Without it, an inserter broken outright would pass.
    #[test]
    fn nothing_is_inserted_after_an_interrupt_shadow() {
        // <first> / add eax, ebx / ret — CF is dead after the first
        // instruction either way, because the `add` overwrites it
        let control = &[0x90, 0x01, 0xd8, 0xc3];
        let (sites, with_work) = insertion_sites(control, &Frozen::new(), &Options::default());
        assert!(
            with_work > 0 && sites.iter().all(|rva| *rva == Rva(0x1000)),
            "the control must insert after the nop: {sites:?}"
        );

        for (name, bytes) in [
            // sti enables interrupts only at the end of the next instruction,
            // which is what makes `sti; cli` recognise none at all
            ("sti", &[0xfb, 0x01, 0xd8, 0xc3][..]),
            // loading SS inhibits interrupts on the following instruction
            // boundary, which is what lets the stack pointer follow it
            ("mov ss, ax", &[0x8e, 0xd0, 0x01, 0xd8, 0xc3][..]),
        ] {
            let (sites, _) = insertion_sites(bytes, &Frozen::new(), &Options::default());
            assert!(
                sites.is_empty(),
                "junk was inserted into the shadow of {name}: {sites:?}"
            );
        }
    }

    #[test]
    fn a_frozen_range_is_open_at_its_beginning() {
        // The same three instructions with the `add` and the `ret` frozen, as
        // an epilogue would be. The point after the `mov` *is* the range's
        // first address, and it has to stay available: an insertion there is
        // read by the unwinder, fails to match an epilogue, and sends it to the
        // full unwind codes, which are right while the stack is untouched.
        let mut frozen = Frozen::new();
        frozen.freeze(Rva(0x1005), Rva(0x1008));

        let (sites, with_work) = insertion_sites(MOV_ADD_RET, &frozen, &Options::default());
        assert!(
            with_work > 0,
            "the range's first address was treated as interior"
        );
        assert!(
            sites.iter().all(|rva| *rva == Rva(0x1000)),
            "junk reached a point inside the frozen range: {sites:?}"
        );
    }

    #[test]
    fn turning_junk_off_leaves_the_function_alone() {
        let options = Options {
            rewrites: false,
            junk: false,
        };
        let (sites, with_work) = insertion_sites(MOV_ADD_RET, &Frozen::new(), &options);
        assert!(sites.is_empty() && with_work == 0, "{sites:?}");
    }

    #[test]
    fn the_same_seed_inserts_the_same_instructions() {
        let run = || {
            let mut function = straight_line(MOV_ADD_RET);
            mutate(
                &mut function,
                &Frozen::new(),
                Seed::new(11),
                &Options::default(),
            )
            .expect("mutates");
            function.blocks[0]
                .instructions
                .iter()
                .map(|instruction| instruction.bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn deterministic_junk_has_exact_golden_bytes_and_report() {
        let options = Options {
            rewrites: false,
            junk: true,
        };
        let mut function = straight_line(&[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
        let report =
            mutate(&mut function, &Frozen::new(), Seed::new(11), &options).expect("mutates");
        let bytes = function.blocks[0]
            .instructions
            .iter()
            .flat_map(|instruction| instruction.bytes().iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            bytes,
            vec![
                0x90, 0xf7, 0xd0, 0x0f, 0xc8, 0xb8, 0x95, 0x75, 0x16, 0x77, 0xb8, 1, 0, 0, 0, 0xc3,
            ]
        );
        assert_eq!(
            report.applied,
            BTreeMap::from([
                ("junk-bswap32", 1),
                ("junk-mov-imm32", 1),
                ("junk-not32", 1),
            ])
        );
    }
}
