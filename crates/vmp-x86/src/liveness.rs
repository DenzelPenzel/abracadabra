//! Liveness of general-purpose registers and flags.
//!
//! A mutation may overwrite only what the program provably no longer needs, so
//! every transform that clobbers state has to ask this module first.
//! [`Liveness::live_after`] gives the state still needed immediately after an
//! instruction, which is exactly what an instruction inserted at that point must
//! leave alone, and [`Liveness::dead_after`] is its complement — what may be
//! written freely.
//!
//! # Backward over the CFG, not forward to the next branch
//!
//! The original scans *forward* from the point of interest and stops at the
//! first instruction that transfers control (`GetFreeRegisters`,
//! `core/intel.cc:15989`). That is sound as far as it goes, but it cannot see
//! past a branch, so a register overwritten in the next block is never
//! recognised as dead. This is a real backward dataflow over the edges the
//! decoder recovered, iterated to a fixpoint.
//!
//! # Flags are three-valued
//!
//! A flag is read, definitely written, or left undefined, and **only a definite
//! write kills the previous value**. Undefined must not kill: the processor is
//! permitted to leave the flag alone, so a reader further down the path may
//! still observe the value from before the instruction. The original collapses
//! all three into a single `change_flags` mask (`core/intel.cc:11889`) and
//! therefore claims flags it does not write — `test`, `xor` and `shl` all list
//! `AF` (`core/intel.cc:12567`, `:12601`, `:12520`) while leaving it undefined,
//! and all three are in its junk catalogue.
//!
//! The shift and rotate family needs the same care for a different reason: with
//! a count of zero it modifies no flag at all, so a count in `CL` — unknown
//! until run time — means the old values may survive.
//!
//! # Nothing is assumed dead at a boundary
//!
//! Where control leaves the decoded function — a `ret`, a tail call, an
//! unresolved indirect jump — every tracked register and flag is reported live,
//! and a `call` reads everything while killing nothing. This matches what the
//! original's forward scan achieves by simply stopping at the first control
//! transfer (`core/intel.cc:16028`), and it buys freedom from any assumption
//! about the calling convention. That freedom is not theoretical: `__chkstk`
//! takes its argument in `RAX` and appears in the prologue of every MSVC
//! function with a large frame, so an ABI table claiming `RAX` is volatile
//! across a call would be wrong exactly where it is most often applied.
//!
//! Registers this model does not track — SIMD, x87, mask, segment — are always
//! reported live, so a caller cannot mistake "not modelled" for "free".

use std::collections::BTreeMap;
use std::fmt;

use iced_x86::{
    FlowControl, Instruction as RawInstruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, RflagsBits,
};
use vmp_ir::{BasicBlock, EdgeTarget, Function, Terminator};
use vmp_types::{Architecture, Rva};

/// The full-width general-purpose registers, indexed by bitset slot.
///
/// Slots are assigned by `Register::number`, which is the architectural encoding
/// order, so the table is indexed by it rather than by enum arithmetic.
const GPR64: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Every flag `iced` can report, with the name used in diagnostics.
const FLAG_NAMES: [(u32, &str); 14] = [
    (RflagsBits::CF, "cf"),
    (RflagsBits::PF, "pf"),
    (RflagsBits::AF, "af"),
    (RflagsBits::ZF, "zf"),
    (RflagsBits::SF, "sf"),
    (RflagsBits::OF, "of"),
    (RflagsBits::DF, "df"),
    (RflagsBits::IF, "if"),
    (RflagsBits::AC, "ac"),
    (RflagsBits::UIF, "uif"),
    (RflagsBits::C0, "c0"),
    (RflagsBits::C1, "c1"),
    (RflagsBits::C2, "c2"),
    (RflagsBits::C3, "c3"),
];

/// A backstop on the fixpoint iteration.
///
/// The transfer functions only grow the live sets and the lattice is thirty bits
/// wide, so the iteration provably converges and this bound is never reached by
/// a well-formed analysis. It exists so that a defect here cannot spin a tool
/// that has to fail closed; on exceeding it the analysis reports everything
/// live, which forbids every mutation rather than allowing a wrong one.
const MAX_ROUNDS: usize = 512;

/// A set of general-purpose registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Registers(u16);

impl Registers {
    pub const fn empty() -> Registers {
        Registers(0)
    }

    /// Every register the architecture has.
    pub const fn all(architecture: Architecture) -> Registers {
        match architecture {
            Architecture::X64 => Registers(0xffff),
            Architecture::X86 => Registers(0x00ff),
        }
    }

    /// Whether `register` is in the set.
    ///
    /// A register with no slot — anything outside the general-purpose file — is
    /// reported present, because this model can prove nothing about it and the
    /// safe answer to "is it in use" is yes.
    pub fn contains(self, register: Register) -> bool {
        match slot(register) {
            Some(slot) => self.0 & (1 << slot) != 0,
            None => true,
        }
    }

    /// Adds `register`, ignoring anything without a slot.
    pub fn insert(&mut self, register: Register) {
        if let Some(slot) = slot(register) {
            self.0 |= 1 << slot;
        }
    }

    /// Removes `register`, ignoring anything without a slot.
    pub fn remove(&mut self, register: Register) {
        if let Some(slot) = slot(register) {
            self.0 &= !(1 << slot);
        }
    }

    pub fn union(self, other: Registers) -> Registers {
        Registers(self.0 | other.0)
    }

    /// The registers of `architecture` that are not in this set.
    pub const fn complement(self, architecture: Architecture) -> Registers {
        Registers(!self.0 & Registers::all(architecture).0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// The registers in the set, in slot order.
    pub fn iter(self) -> impl Iterator<Item = Register> {
        GPR64
            .into_iter()
            .enumerate()
            .filter_map(move |(slot, register)| (self.0 & (1 << slot) != 0).then_some(register))
    }
}

impl fmt::Display for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        for (index, register) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{register:?}")?;
        }
        Ok(())
    }
}

/// A set of flags, as an `RflagsBits` mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Flags(u32);

impl Flags {
    pub const fn empty() -> Flags {
        Flags(0)
    }

    /// Every flag `iced` can report on.
    pub const fn all() -> Flags {
        let mut bits = 0;
        let mut index = 0;
        // A const loop rather than a written-out disjunction so that the set
        // stays exactly the set the names cover
        while index < FLAG_NAMES.len() {
            bits |= FLAG_NAMES[index].0;
            index += 1;
        }
        Flags(bits)
    }

    pub const fn from_bits(bits: u32) -> Flags {
        Flags(bits & Flags::all().0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every flag of `mask` is in the set.
    pub const fn contains_all(self, mask: u32) -> bool {
        let mask = Flags::from_bits(mask).0;
        self.0 & mask == mask
    }

    /// Whether any flag of `mask` is in the set.
    pub const fn intersects(self, mask: u32) -> bool {
        self.0 & Flags::from_bits(mask).0 != 0
    }

    pub const fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }

    pub const fn without(self, other: Flags) -> Flags {
        Flags(self.0 & !other.0)
    }

    pub const fn complement(self) -> Flags {
        Flags(!self.0 & Flags::all().0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// The name of each flag in the set, in architectural bit order.
    ///
    /// The way to render the set anywhere but a listing: a caller that needs the
    /// individual names must not have to take [`fmt::Display`] apart to get them.
    pub fn iter_names(self) -> impl Iterator<Item = &'static str> {
        FLAG_NAMES
            .into_iter()
            .filter_map(move |(bit, name)| (self.0 & bit != 0).then_some(name))
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        for (index, name) in self.iter_names().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

/// What is in use at one point in the function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct State {
    pub registers: Registers,
    pub flags: Flags,
}

impl State {
    pub const fn empty() -> State {
        State {
            registers: Registers::empty(),
            flags: Flags::empty(),
        }
    }

    /// Everything the architecture has: the boundary value, and the answer that
    /// forbids every mutation.
    pub const fn all(architecture: Architecture) -> State {
        State {
            registers: Registers::all(architecture),
            flags: Flags::all(),
        }
    }

    pub fn union(self, other: State) -> State {
        State {
            registers: self.registers.union(other.registers),
            flags: self.flags.union(other.flags),
        }
    }

    /// What is *not* in use here.
    pub fn complement(self, architecture: Architecture) -> State {
        State {
            registers: self.registers.complement(architecture),
            flags: self.flags.complement(),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "regs[{}] flags[{}]", self.registers, self.flags)
    }
}

/// Liveness for one function, addressed by instruction.
#[derive(Debug, Clone)]
pub struct Liveness {
    architecture: Architecture,
    /// In use immediately before each instruction executes.
    before: BTreeMap<Rva, State>,
    /// In use immediately after each instruction executes, which is the same as
    /// `before` of whatever runs next.
    after: BTreeMap<Rva, State>,
    /// Fixpoint rounds the analysis took, one meaning it converged on the first
    /// backward pass.
    rounds: usize,
    /// Whether [`MAX_ROUNDS`] was hit and every answer degraded to "in use".
    saturated: bool,
}

impl Liveness {
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Whether the fixpoint gave up and every answer is the boundary value.
    pub fn saturated(&self) -> bool {
        self.saturated
    }

    /// What is in use just before the instruction at `rva`.
    pub fn live_before(&self, rva: Rva) -> Option<State> {
        self.before.get(&rva).copied()
    }

    /// What is in use just after the instruction at `rva`.
    ///
    /// This is the question an inserted instruction asks: it may write anything
    /// this does not name.
    pub fn live_after(&self, rva: Rva) -> Option<State> {
        self.after.get(&rva).copied()
    }

    /// What may be overwritten just before the instruction at `rva`.
    pub fn dead_before(&self, rva: Rva) -> Option<State> {
        Some(self.live_before(rva)?.complement(self.architecture))
    }

    /// What may be overwritten just after the instruction at `rva`.
    pub fn dead_after(&self, rva: Rva) -> Option<State> {
        Some(self.live_after(rva)?.complement(self.architecture))
    }
}

/// Computes liveness for every instruction of `function`.
///
/// Sound on an incomplete function as well: an edge the decoder could not
/// resolve is an edge out of the function, and control leaving the function is
/// already the boundary case where everything is in use.
pub fn analyze(function: &Function) -> Liveness {
    analyze_bounded(function, MAX_ROUNDS)
}

/// [`analyze`] with the iteration bound spelled out, so that the fail-closed
/// fallback can be reached from a test instead of only reasoned about.
fn analyze_bounded(function: &Function, max_rounds: usize) -> Liveness {
    let architecture = function.architecture;
    let boundary = State::all(architecture);
    let mut factory = InstructionInfoFactory::new();

    // Live-in per block, grown from empty to the fixpoint. Blocks are visited in
    // reverse creation order, which for a traversal-ordered CFG is close to
    // reverse postorder and converges in a couple of rounds.
    let mut live_in = vec![State::empty(); function.blocks.len()];
    let mut rounds = 0;
    let mut saturated = true;
    while rounds < max_rounds {
        rounds += 1;
        let mut changed = false;
        for block in function.blocks.iter().rev() {
            let mut state = live_out(block, &live_in, boundary);
            for instruction in block.instructions.iter().rev() {
                state = transfer(state, instruction.raw(), &mut factory, architecture);
            }
            if live_in[block.id.index()] != state {
                live_in[block.id.index()] = state;
                changed = true;
            }
        }
        if !changed {
            saturated = false;
            break;
        }
    }

    // The fixpoint is monotone, so this is unreachable; degrading to the
    // boundary value keeps a defect from becoming a wrong mutation
    if saturated {
        live_in.fill(boundary);
    }

    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    for block in &function.blocks {
        let mut state = if saturated {
            boundary
        } else {
            live_out(block, &live_in, boundary)
        };
        for instruction in block.instructions.iter().rev() {
            let rva = instruction.rva();
            if let Some(rva) = rva {
                after.insert(rva, state);
            }
            state = transfer(state, instruction.raw(), &mut factory, architecture);
            if let Some(rva) = rva {
                before.insert(rva, state);
            }
        }
    }

    Liveness {
        architecture,
        before,
        after,
        rounds,
        saturated,
    }
}

fn live_out(block: &BasicBlock, live_in: &[State], boundary: State) -> State {
    if escapes(block) {
        return boundary;
    }

    let mut state = State::empty();
    for edge in &block.successors {
        if let EdgeTarget::Block(id) = edge.target {
            if let Some(target) = live_in.get(id.index()) {
                state = state.union(*target);
            } else {
                // An edge to a block that does not exist means the CFG is not
                // what this analysis assumes, so it stops proving things
                return boundary;
            }
        }
    }
    state
}

/// Whether control can leave the decoded function from `block`.
///
/// Everything here is a boundary: either the code on the other side is unknown,
/// or nothing runs afterwards at all. Both answer the same way — assume in use.
/// A block that halts could in principle report nothing in use, but a `Halt` is
/// also how a call to a non-returning function is modelled, and that callee
/// reads its arguments.
fn escapes(block: &BasicBlock) -> bool {
    if block.leaves_function() || block.successors.is_empty() {
        return true;
    }
    matches!(
        block.terminator,
        Terminator::Return
            | Terminator::IndirectJump
            | Terminator::ImportTailCall
            | Terminator::Halt
            | Terminator::Data
    )
}

/// Walks one instruction backwards: given what is in use after it, what is in
/// use before it.
fn transfer(
    state: State,
    instruction: &RawInstruction,
    factory: &mut InstructionInfoFactory,
    architecture: Architecture,
) -> State {
    if is_opaque(instruction) {
        return State::all(architecture);
    }

    let mut registers = state.registers;
    let info = factory.info(instruction);

    // Kills first, then reads, so an instruction that does both leaves the
    // register in use
    for used in info.used_registers() {
        if kills(used.register(), used.access()) {
            registers.remove(used.register());
        }
    }
    for used in info.used_registers() {
        if reads(used.access()) {
            registers.insert(used.register());
        }
    }

    // The stack pointer is never reported free. Dataflow would mostly get this
    // right on its own, but "the stack pointer is dead here" is never an answer
    // worth acting on, and the original excludes it outright
    // (`core/intel.cc:16015`).
    registers.insert(Register::RSP);

    let written = if flag_writes_may_not_happen(instruction) {
        Flags::empty()
    } else {
        // Cleared and set are definite writes to a known value; `written` is a
        // definite write to an unknown one. `undefined` is deliberately absent:
        // the processor may leave the flag alone, so the old value survives.
        Flags::from_bits(
            instruction.rflags_written() | instruction.rflags_cleared() | instruction.rflags_set(),
        )
    };
    let flags = state
        .flags
        .without(written)
        .union(Flags::from_bits(instruction.rflags_read()));

    State { registers, flags }
}

/// Whether the instruction transfers control to code the analysis has not seen
/// and then comes back.
fn is_opaque(instruction: &RawInstruction) -> bool {
    matches!(
        instruction.flow_control(),
        FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend
    )
}

/// Whether an access ends the life of the register's previous value.
///
/// Only an unconditional write of the whole register does. A write narrower than
/// four bytes leaves the upper bits in place, so the old value flows through it;
/// a 32-bit write on x86-64 zero-extends and therefore does kill. A conditional
/// write may not happen, so the old value can flow through that too.
fn kills(register: Register, access: OpAccess) -> bool {
    access == OpAccess::Write && register.is_gpr() && register.size() >= 4
}

/// Whether an access needs the register's previous value.
fn reads(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Whether the instruction's flag writes may not happen at all.
///
/// `iced` reports the shift and rotate family as writing flags, but with a
/// count of zero they modify none, so the previous values survive. A count in
/// `CL` is unknown until run time and a zero immediate is explicit; both mean
/// the writes cannot be treated as kills.
fn flag_writes_may_not_happen(instruction: &RawInstruction) -> bool {
    let count_operand = match instruction.mnemonic() {
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Sal
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr => 1,
        Mnemonic::Shld | Mnemonic::Shrd => 2,
        _ => return false,
    };

    if count_operand >= instruction.op_count() {
        return true;
    }
    match instruction.op_kind(count_operand) {
        // The processor masks the count to five bits, or six for a 64-bit
        // operand. Masking with five is the conservative choice for both: it can
        // only report more counts as possibly-zero, never fewer.
        OpKind::Immediate8 => instruction.immediate8() & 0x1f == 0,
        // The count is in `CL`
        _ => true,
    }
}

/// The bitset position tracking `register`.
///
/// `None` for anything outside the general-purpose file. Sub-registers are
/// widened first, so `AH`, `AX` and `EAX` all answer with `RAX`'s slot.
fn slot(register: Register) -> Option<u32> {
    if !register.is_gpr() {
        return None;
    }
    u32::try_from(register.full_register().number()).ok()
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions};
    use vmp_ir::{BasicBlock, BlockId, CompileStage, Edge, EdgeKind, Instruction};

    use super::*;

    /// Decodes `bytes` as one straight run of instructions starting at `rva`.
    fn decode_run(rva: u32, bytes: &[u8]) -> Vec<Instruction> {
        decode_run_at(64, rva, bytes)
    }

    fn decode_run_at(bitness: u32, rva: u32, bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(bitness, bytes, u64::from(rva), DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let offset = usize::try_from(raw.ip() - u64::from(rva)).expect("run fits in memory");
            let encoded = &bytes[offset..offset + raw.len()];
            let at = u32::try_from(raw.ip()).expect("test addresses are small");
            instructions.push(Instruction::decoded(Rva(at), raw, encoded));
        }
        instructions
    }

    /// One block. `successors` names edges by target block id; the analysis walks
    /// successors only, so `predecessors` is left empty on purpose.
    fn block(
        id: u32,
        rva: u32,
        bytes: &[u8],
        terminator: Terminator,
        successors: &[(EdgeKind, EdgeTarget)],
    ) -> BasicBlock {
        let instructions = decode_run(rva, bytes);
        let end = instructions
            .last()
            .and_then(|last| last.next_rva())
            .unwrap_or(Rva(rva));
        BasicBlock {
            id: BlockId(id),
            start: Rva(rva),
            end,
            instructions,
            terminator,
            successors: successors
                .iter()
                .map(|(kind, target)| Edge::new(*kind, *target))
                .collect(),
            predecessors: Vec::new(),
        }
    }

    fn to_block(id: u32) -> EdgeTarget {
        EdgeTarget::Block(BlockId(id))
    }

    fn function(blocks: Vec<BasicBlock>) -> Function {
        let entry = blocks.first().expect("at least one block").start;
        let entry_block = blocks.first().expect("at least one block").id;
        Function {
            architecture: Architecture::X64,
            entry,
            blocks,
            entry_block,
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    /// A single-block function ending in `ret`, the common shape here.
    fn straight_line(bytes: &[u8]) -> Function {
        function(vec![block(0, 0x1000, bytes, Terminator::Return, &[])])
    }

    fn dead_after(function: &Function, rva: u32) -> State {
        analyze(function)
            .dead_after(Rva(rva))
            .expect("the address must name an instruction")
    }

    fn live_after(function: &Function, rva: u32) -> State {
        analyze(function)
            .live_after(Rva(rva))
            .expect("the address must name an instruction")
    }

    #[test]
    fn a_full_width_overwrite_kills_the_previous_value() {
        // mov ecx, 1 / mov ecx, 2 / ret
        let function = straight_line(&[
            0xb9, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00, 0x00, 0x00, 0xc3,
        ]);
        assert!(
            dead_after(&function, 0x1000)
                .registers
                .contains(Register::RCX),
            "the second write makes the first value dead"
        );
        // The second write is followed only by `ret`, and the boundary reports
        // everything in use
        assert!(!dead_after(&function, 0x1005)
            .registers
            .contains(Register::RCX));
    }

    #[test]
    fn a_narrow_overwrite_does_not_kill() {
        // mov cl, 1 / mov cl, 2 / ret: the upper 56 bits of RCX survive both, so
        // the previous value flows through and stays in use
        let function = straight_line(&[0xb1, 0x01, 0xb1, 0x02, 0xc3]);
        assert!(!dead_after(&function, 0x1000)
            .registers
            .contains(Register::RCX));
    }

    #[test]
    fn a_thirty_two_bit_overwrite_kills_the_whole_register() {
        // mov rcx, 5 / mov ecx, 6 / ret: writing ECX zero-extends into RCX
        let function = straight_line(&[
            0x48, 0xc7, 0xc1, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x00, 0x00, 0x00, 0xc3,
        ]);
        assert!(dead_after(&function, 0x1000)
            .registers
            .contains(Register::RCX));
    }

    #[test]
    fn sub_registers_share_one_slot() {
        // mov ah, 1 / mov eax, 2 / ret: the write to EAX kills what AH held
        let function = straight_line(&[0xb4, 0x01, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3]);
        assert!(dead_after(&function, 0x1000)
            .registers
            .contains(Register::RAX));
    }

    #[test]
    fn a_conditional_write_does_not_kill() {
        // mov rax, 5 / cmovz rax, rcx / ret
        //
        // If the condition fails the `cmov` leaves RAX holding the 5, and the
        // boundary at the `ret` says that value may be read. So the write cannot
        // count as a kill and RAX has to stay in use after the `mov`.
        let function = straight_line(&[
            0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, 0x48, 0x0f, 0x44, 0xc1, 0xc3,
        ]);
        assert!(
            !dead_after(&function, 0x1000)
                .registers
                .contains(Register::RAX),
            "a conditional write may not happen"
        );
        assert!(
            !dead_after(&function, 0x1000)
                .registers
                .contains(Register::RCX),
            "the source is read either way"
        );
    }

    #[test]
    fn a_thirty_two_bit_cmov_is_not_a_conditional_write() {
        // mov rax, 5 / cmovz eax, ecx / ret
        //
        // The narrower form is a different instruction as far as liveness goes:
        // on x86-64 `cmovcc r32` always writes the destination, zeroing the upper
        // half whether the condition held or not, and `iced` reports it as
        // `EAX Read` plus `RAX Write` rather than as a conditional write. RAX
        // therefore stays in use through the read, not through a missing kill —
        // the same answer by a different route, which is worth pinning because
        // only the wider form exercises the conditional path above.
        let function = straight_line(&[
            0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, 0x0f, 0x44, 0xc1, 0xc3,
        ]);
        assert!(!dead_after(&function, 0x1000)
            .registers
            .contains(Register::RAX));
    }

    #[test]
    fn an_undefined_flag_is_not_killed() {
        // xor eax, eax / test ecx, ecx / ret
        //
        // `test` definitely writes CF PF ZF SF OF and leaves AF undefined, so the
        // five are dead after the `xor` and AF is not. A model with one mask for
        // "changes" — as the original has — would report AF dead here and let a
        // junk instruction overwrite a value a later `lahf` can still observe.
        let function = straight_line(&[0x31, 0xc0, 0x85, 0xc9, 0xc3]);
        let dead = dead_after(&function, 0x1000).flags;
        assert!(
            dead.contains_all(
                RflagsBits::CF | RflagsBits::PF | RflagsBits::ZF | RflagsBits::SF | RflagsBits::OF
            ),
            "definite writes kill: {dead}"
        );
        assert!(
            !dead.intersects(RflagsBits::AF),
            "AF is left undefined, so the old value may survive: {dead}"
        );
    }

    #[test]
    fn a_shift_by_cl_kills_no_flag() {
        // cmp eax, ecx / shl edx, cl / ret
        //
        // With CL zero the shift modifies nothing, so every flag the `cmp` wrote
        // may still be read further on and none of them is dead.
        let function = straight_line(&[0x39, 0xc8, 0xd3, 0xe2, 0xc3]);
        assert!(
            dead_after(&function, 0x1000).flags.is_empty(),
            "a run-time count means the writes may not happen"
        );
    }

    #[test]
    fn a_shift_by_one_kills_the_flags_it_defines() {
        // cmp eax, ecx / shl edx, 1 / ret: a non-zero immediate always writes
        let function = straight_line(&[0x39, 0xc8, 0xd1, 0xe2, 0xc3]);
        let dead = dead_after(&function, 0x1000).flags;
        assert!(dead.contains_all(
            RflagsBits::CF | RflagsBits::PF | RflagsBits::ZF | RflagsBits::SF | RflagsBits::OF
        ));
        // Shifting by one defines OF but still leaves AF undefined
        assert!(!dead.intersects(RflagsBits::AF), "{dead}");
    }

    /// `nop` / `jz`, then two paths joining on a block that reads `EDX`.
    ///
    /// `tail` is the body of the not-taken block, which is the only difference
    /// between the two join tests.
    fn diamond(taken_body: &[u8]) -> Function {
        function(vec![
            // nop / jz 0x1020
            block(
                0,
                0x1000,
                &[0x90, 0x74, 0x1c],
                Terminator::Conditional,
                &[
                    (EdgeKind::NotTaken, to_block(1)),
                    (EdgeKind::Taken, to_block(2)),
                ],
            ),
            // mov edx, 1 / jmp 0x1030
            block(
                1,
                0x1010,
                &[0xba, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x16, 0x00, 0x00, 0x00],
                Terminator::Jump,
                &[(EdgeKind::Jump, to_block(3))],
            ),
            block(
                2,
                0x1020,
                taken_body,
                Terminator::Jump,
                &[(EdgeKind::Jump, to_block(3))],
            ),
            // mov eax, edx / ret
            block(3, 0x1030, &[0x8b, 0xc2, 0xc3], Terminator::Return, &[]),
        ])
    }

    #[test]
    fn a_register_killed_on_one_path_only_stays_live() {
        // The taken side is nop / jmp: it leaves EDX alone, so the value reaching
        // the join through it is the one from before the branch
        let function = diamond(&[0x90, 0xe9, 0x0b, 0x00, 0x00, 0x00]);
        assert!(
            live_after(&function, 0x1000)
                .registers
                .contains(Register::RDX),
            "one surviving path is enough to keep it in use"
        );
    }

    #[test]
    fn a_register_killed_on_every_path_is_dead_before_the_branch() {
        // mov edx, 2 / jmp 0x1030: now both sides overwrite EDX before the join
        // reads it
        let function = diamond(&[0xba, 0x02, 0x00, 0x00, 0x00, 0xe9, 0x06, 0x00, 0x00, 0x00]);
        assert!(
            dead_after(&function, 0x1000)
                .registers
                .contains(Register::RDX),
            "the join can only observe values written after the branch"
        );
    }

    /// A block that jumps to itself, reached from a first block.
    ///
    /// The only shape where nothing reachable is a boundary, which is what makes
    /// a small live set observable at all.
    fn self_loop(body: &[u8]) -> Function {
        function(vec![
            // mov ecx, 1
            block(
                0,
                0x1000,
                &[0xb9, 0x01, 0x00, 0x00, 0x00],
                Terminator::FallThrough,
                &[(EdgeKind::FallThrough, to_block(1))],
            ),
            block(
                1,
                0x1005,
                body,
                Terminator::Jump,
                &[(EdgeKind::Jump, to_block(1))],
            ),
        ])
    }

    #[test]
    fn the_fixpoint_converges_over_a_back_edge() {
        // mov edx, ecx / jmp 0x1005
        //
        // Only ECX is read and nothing is a boundary, so the answer is exactly
        // RCX plus the stack pointer, and every flag is dead. Reaching it takes
        // more than one pass: the first cannot know what the back edge carries.
        let function = self_loop(&[0x8b, 0xd1, 0xe9, 0xfb, 0xff, 0xff, 0xff]);
        let liveness = analyze(&function);
        assert!(!liveness.saturated(), "the iteration must reach a fixpoint");

        let live = liveness
            .live_after(Rva(0x1000))
            .expect("the address must name an instruction");
        assert_eq!(live.registers.len(), 2, "expected RCX and RSP: {live}");
        assert!(live.registers.contains(Register::RCX));
        assert!(
            live.registers.contains(Register::RSP),
            "the stack pointer is never reported free"
        );
        assert!(live.flags.is_empty(), "no flag is read anywhere: {live}");
    }

    #[test]
    fn a_call_reads_everything() {
        // call 0x2000 / jmp 0x1005, in the same shape as the test above, where
        // without the call almost everything was dead
        let function = self_loop(&[0xe8, 0xf6, 0x0f, 0x00, 0x00, 0xe9, 0xfb, 0xff, 0xff, 0xff]);
        assert_eq!(
            live_after(&function, 0x1000),
            State::all(Architecture::X64),
            "the callee may read anything, so nothing may be overwritten before it"
        );
    }

    #[test]
    fn leaving_the_function_is_a_boundary() {
        // mov ecx, 1 / jmp into an address the decoder did not follow
        let function = function(vec![block(
            0,
            0x1000,
            &[0xb9, 0x01, 0x00, 0x00, 0x00],
            Terminator::Jump,
            &[(EdgeKind::Jump, EdgeTarget::External(Rva(0x9000)))],
        )]);
        assert_eq!(
            live_after(&function, 0x1000),
            State::all(Architecture::X64),
            "what the code on the other side needs is unknown"
        );
    }

    #[test]
    fn giving_up_on_the_fixpoint_reports_everything_in_use() {
        // The self-loop needs a second pass, so a bound of one forces the
        // fallback. Every answer must degrade to the boundary rather than to the
        // half-computed set the first pass produced, which would name registers
        // free that the back edge still reads.
        let function = self_loop(&[0x8b, 0xd1, 0xe9, 0xfb, 0xff, 0xff, 0xff]);
        let liveness = analyze_bounded(&function, 1);
        assert!(liveness.saturated(), "one pass cannot converge here");

        for rva in [0x1000, 0x1005, 0x1007] {
            assert_eq!(
                liveness
                    .live_after(Rva(rva))
                    .expect("the address must name an instruction"),
                State::all(Architecture::X64),
                "the answer at {rva:#x} must forbid every mutation"
            );
        }
        // And the converged run does not: the fallback is a fallback, not the
        // normal answer
        assert!(!analyze(&function).saturated());
    }

    #[test]
    fn a_thirty_two_bit_function_uses_the_narrow_register_file() {
        // mov ecx, 1 / mov ecx, 2 / ret, decoded as x86
        let instructions = decode_run_at(
            32,
            0x1000,
            &[
                0xb9, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00, 0x00, 0x00, 0xc3,
            ],
        );
        let end = instructions
            .last()
            .and_then(|last| last.next_rva())
            .expect("the run is not empty");
        let function = Function {
            architecture: Architecture::X86,
            entry: Rva(0x1000),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
                end,
                instructions,
                terminator: Terminator::Return,
                successors: Vec::new(),
                predecessors: Vec::new(),
            }],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        };

        let liveness = analyze(&function);
        let dead = liveness
            .dead_after(Rva(0x1000))
            .expect("the address must name an instruction");
        assert!(
            dead.registers.contains(Register::RCX),
            "ECX shares RCX's slot"
        );
        // The boundary on x86 is eight registers, so the complement can never
        // name one that does not exist
        for absent in [Register::R8, Register::R15] {
            assert!(
                !dead.registers.contains(absent),
                "{absent:?} does not exist on x86"
            );
        }
        let live = liveness
            .live_after(Rva(0x1005))
            .expect("the address must name an instruction");
        assert_eq!(live.registers.len(), 8, "the boundary is the whole file");
    }

    #[test]
    fn an_untracked_register_is_never_reported_free() {
        let empty = Registers::empty();
        assert!(empty.contains(Register::XMM0), "SIMD is not modelled");
        assert!(empty.contains(Register::ST0), "x87 is not modelled");
        assert!(empty.contains(Register::FS), "segments are not modelled");
        assert!(!empty.contains(Register::RAX), "but GPRs are");
    }

    #[test]
    fn x86_has_only_the_first_eight_slots() {
        assert_eq!(Registers::all(Architecture::X86).len(), 8);
        assert_eq!(Registers::all(Architecture::X64).len(), 16);
    }

    #[test]
    fn sets_render_for_diagnostics() {
        let mut registers = Registers::empty();
        registers.insert(Register::EAX);
        registers.insert(Register::R11D);
        assert_eq!(registers.to_string(), "RAX R11");
        assert_eq!(Registers::empty().to_string(), "-");

        assert_eq!(
            Flags::from_bits(RflagsBits::CF | RflagsBits::ZF).to_string(),
            "cf zf"
        );
        assert_eq!(Flags::empty().to_string(), "-");
    }

    #[test]
    fn every_flag_all_covers_has_a_name() {
        // `Flags::all` is built from the name table, so a bit without a name
        // could only come from a mask that bypasses `from_bits`
        let named = FLAG_NAMES.iter().fold(0, |bits, (bit, _)| bits | bit);
        assert_eq!(Flags::all().bits(), named);
        assert!(Flags::all().complement().is_empty());
    }
}
