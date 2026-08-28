//! Instructions and the references embedded in their operands.

use iced_x86::Instruction as RawInstruction;
use vmp_types::{Rva, VirtualAddress};

/// The longest legal x86-64 instruction encoding.
pub const MAX_INSTRUCTION_LEN: usize = 15;

/// A decoded instruction together with everything the protector must preserve
/// when the instruction moves to a new address.
///
/// The decoder runs with `ip` set to the instruction's RVA rather than to its
/// virtual address, so [`RawInstruction::near_branch_target`] and
/// [`RawInstruction::ip_rel_memory_address`] already yield RVAs. Absolute
/// addresses encoded in an immediate or displacement stay virtual addresses and
/// are converted explicitly; see [`OperandRef::Absolute`].
#[derive(Debug, Clone)]
pub struct Instruction {
    origin: Origin,
    raw: RawInstruction, // iced
    bytes: [u8; MAX_INSTRUCTION_LEN],
    len: u8,
    refs: Vec<OperandRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Decoded from the image at this address.
    Decoded(Rva),
    /// Produced by a transform, with no counterpart in the input image.
    Inserted,
}

impl Instruction {
    /// Wraps an instruction decoded from the image at `rva`.
    ///
    /// `bytes` is the original encoding as it appears in the image; it can
    /// never exceed [`MAX_INSTRUCTION_LEN`] because that is the architectural
    /// limit the decoder enforces.
    pub fn decoded(rva: Rva, raw: RawInstruction, bytes: &[u8]) -> Instruction {
        debug_assert_eq!(
            bytes.len(),
            raw.len(),
            "encoding length must match the decode"
        );
        Instruction::new(Origin::Decoded(rva), raw, bytes)
    }

    /// Wraps an instruction a transform produced.
    ///
    /// `bytes` must encode `raw`; the caller supplies them because encoding
    /// lives in `vmp-x86`.
    ///
    /// Unlike [`Instruction::decoded`], that cannot be checked here.
    /// `iced` fills in `RawInstruction::len` while decoding and nowhere else, so
    /// an instruction built with `Instruction::with*` reports a length of zero
    /// and one re-coded with `set_code` reports the length it had before. Only a
    /// decode gives a length worth comparing against.
    pub fn inserted(raw: RawInstruction, bytes: &[u8]) -> Instruction {
        Instruction::new(Origin::Inserted, raw, bytes)
    }

    fn new(origin: Origin, raw: RawInstruction, bytes: &[u8]) -> Instruction {
        debug_assert!(!bytes.is_empty(), "an instruction occupies at least a byte");

        let len = bytes.len().min(MAX_INSTRUCTION_LEN);
        let mut stored = [0u8; MAX_INSTRUCTION_LEN];
        stored[..len].copy_from_slice(&bytes[..len]);

        Instruction {
            origin,
            raw,
            bytes: stored,
            len: len as u8,
            refs: Vec::new(),
        }
    }

    pub fn origin(&self) -> Origin {
        self.origin
    }

    /// Address of the instruction inside the image, or `None` when a transform
    /// produced it and it never had one.
    pub fn rva(&self) -> Option<Rva> {
        match self.origin {
            Origin::Decoded(rva) => Some(rva),
            Origin::Inserted => None,
        }
    }

    /// Length of the original encoding in bytes.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Always false: a decoded instruction occupies at least one byte.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The original encoding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The decoded form, decoded with `ip` equal to [`Instruction::rva`].
    pub fn raw(&self) -> &RawInstruction {
        &self.raw
    }

    /// Replaces the decoded form together with its encoding.
    ///
    /// The two are replaced as a pair because every consumer assumes
    /// [`Instruction::bytes`] is an encoding of [`Instruction::raw`]; encoding
    /// itself belongs to `vmp-x86`, so the caller supplies the bytes.
    ///
    /// The reference list is cleared. [`FieldSpan`] offsets describe positions
    /// inside the previous encoding, and a rewritten instruction is not
    /// required to keep an operand at the same offset — or to keep it at all.
    /// Callers that need the references back must re-bind them.
    pub fn replace(&mut self, mut raw: RawInstruction, bytes: &[u8]) {
        debug_assert!(!bytes.is_empty(), "an instruction occupies at least a byte");
        if let Origin::Decoded(rva) = self.origin {
            // BlockEncoder identifies internal branch targets by instruction IP.
            // A replacement built with `Instruction::with*` starts at IP zero,
            // so preserve the authoritative address carried by the IR origin.
            raw.set_ip(u64::from(rva.get()));
        }
        let len = bytes.len().min(MAX_INSTRUCTION_LEN);
        self.bytes = [0u8; MAX_INSTRUCTION_LEN]; // clean buffer
        self.bytes[..len].copy_from_slice(&bytes[..len]); // copy new bytes
        self.len = len as u8;
        self.raw = raw;
        self.refs.clear();
    }

    /// RVA of the byte after this instruction.
    ///
    /// `None` for an inserted instruction, which occupies no address in the
    /// input, and — for a decoded one — only when it sits at the very top of the
    /// 32-bit RVA space, which no mapped image can produce.
    pub fn next_rva(&self) -> Option<Rva> {
        self.rva()?.checked_add(u32::from(self.len))
    }

    /// References carried by this instruction's operands.
    pub fn refs(&self) -> &[OperandRef] {
        &self.refs
    }

    /// Records a reference discovered while binding operands.
    pub fn push_ref(&mut self, reference: OperandRef) {
        self.refs.push(reference);
    }

    /// The direct branch or call target, if the instruction has one.
    pub fn branch_target(&self) -> Option<Rva> {
        self.refs.iter().find_map(|r| match r {
            OperandRef::Branch { target, .. } => Some(*target),
            OperandRef::RipRelative { .. } | OperandRef::Absolute { .. } => None,
        })
    }
}

/// A reference embedded in one operand that must be rebound whenever the
/// instruction or its target moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandRef {
    /// A relative branch or call displacement (`jmp`, `jcc`, `call rel32`).
    Branch {
        target: Rva,
        kind: BranchKind,
        field: FieldSpan,
    },
    /// A RIP-relative memory operand.
    RipRelative {
        target: Rva,
        target_kind: TargetKind,
        field: FieldSpan,
    },
    /// An absolute address encoded in an immediate or a displacement and
    /// covered by a PE base relocation.
    ///
    /// `target` is `None` when the address falls outside the image, which
    /// happens for relocated constants that are not addresses at all.
    Absolute {
        va: VirtualAddress,
        target: Option<Rva>,
        width: AbsoluteWidth,
        target_kind: TargetKind,
        field: FieldSpan,
    },
}

impl OperandRef {
    /// The encoded field this reference occupies.
    pub fn field(&self) -> FieldSpan {
        match self {
            OperandRef::Branch { field, .. }
            | OperandRef::RipRelative { field, .. }
            | OperandRef::Absolute { field, .. } => *field,
        }
    }
}

/// What kind of control transfer a [`OperandRef::Branch`] encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BranchKind {
    /// `call rel32`
    Call,
    /// `jmp rel8/rel32`
    Jump,
    /// `jcc`, `jcxz`, `loop`
    Conditional,
}

/// What a reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetKind {
    /// An executable section.
    Code,
    /// A mapped, non-executable section.
    Data,
    /// An import address table slot, which the loader fills at run time.
    ImportThunk,
    /// Outside every mapped section.
    Unmapped,
}

/// Width of an absolute address embedded in an instruction field.
///
/// This is deliberately not `vmp_pe::FixupKind`: the IR only needs the width to
/// decide what kind of base relocation a moved instruction requires, and
/// keeping the PE fixup taxonomy out of the IR keeps this crate dependent on
/// `vmp-types` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbsoluteWidth {
    Bits32,
    Bits64,
}

impl AbsoluteWidth {
    /// Size of the encoded field in bytes.
    pub const fn byte_len(self) -> u8 {
        match self {
            AbsoluteWidth::Bits32 => 4,
            AbsoluteWidth::Bits64 => 8,
        }
    }
}

/// The span of an encoded field inside an instruction, relative to the
/// instruction's first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldSpan {
    pub offset: u8,
    pub size: u8,
}

impl FieldSpan {
    pub const fn new(offset: u8, size: u8) -> FieldSpan {
        FieldSpan { offset, size }
    }

    /// Whether `byte` — an offset from the instruction's first byte — lands
    /// inside this field.
    pub const fn contains(self, byte: u8) -> bool {
        byte >= self.offset && (byte - self.offset) < self.size
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::{Code, Decoder, DecoderOptions};

    use super::*;

    #[test]
    fn field_span_contains_only_its_own_bytes() {
        let field = FieldSpan::new(3, 4);
        assert!(!field.contains(2));
        assert!(field.contains(3));
        assert!(field.contains(6));
        assert!(!field.contains(7));
    }

    #[test]
    fn empty_field_contains_nothing() {
        let field = FieldSpan::new(3, 0);
        assert!(!field.contains(3));
    }

    #[test]
    fn replacing_a_decoded_instruction_preserves_its_authoritative_ip() {
        let original = Decoder::with_ip(64, &[0x90], 0x1234, DecoderOptions::NONE).decode();
        let mut instruction = Instruction::decoded(Rva(0x1234), original, &[0x90]);

        instruction.replace(RawInstruction::with(Code::Nopd), &[0x90]);

        assert_eq!(instruction.raw().ip(), 0x1234);
    }
}
