//! Re-encoding a decoded function at a new address.
//!
//! Because instructions are decoded with `ip` set to their RVA, the block
//! encoder's notion of an absolute target is also an RVA, so moving a function
//! is a single call: relative branches and RIP-relative displacements are
//! recomputed for the new location without any rebasing on our side.
//!
//! What the block encoder does *not* do is update the PE container — `.reloc`,
//! the IAT, `.pdata` and `.xdata` all stay the responsibility of `vmp-pe` and
//! `vmp-emit`, as ADR-0001 records.

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Encoder,
    Instruction as RawInstruction, InstructionBlock,
};
use vmp_ir::Function;
use vmp_types::{Architecture, Rva};

use crate::error::X86Error;

/// Encodes one instruction as it would appear at `rva`.
///
/// Only meaningful for instructions whose encoding is address-dependent — a
/// relative branch or a RIP-relative memory operand. Everything else encodes
/// identically at any address, and callers rewriting such an instruction can
/// pass its current address.
pub fn encode_one(
    architecture: Architecture,
    raw: &RawInstruction,
    rva: Rva,
) -> Result<Vec<u8>, X86Error> {
    let mut encoder = Encoder::new(bitness(architecture));
    encoder
        .encode(raw, u64::from(rva.get()))
        .map_err(|error| X86Error::Encode {
            rva,
            reason: error.to_string(),
        })?;
    Ok(encoder.take_buffer())
}

fn bitness(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    }
}

/// A function re-encoded at a new address.
#[derive(Debug, Clone)]
pub struct Relocated {
    /// The address the code was encoded for.
    pub rva: Rva,
    pub bytes: Vec<u8>,
    /// Where each original instruction ended up, in address order.
    ///
    /// An instruction the encoder had to rewrite into a different form — a
    /// short branch that no longer reaches, say — has no single new address and
    /// is absent from this map.
    pub moved: Vec<(Rva, Rva)>,
}

impl Relocated {
    /// The new address of an original instruction.
    pub fn new_rva(&self, original: Rva) -> Option<Rva> {
        self.moved
            .iter()
            .find(|(from, _)| *from == original)
            .map(|(_, to)| *to)
    }

    /// Length of one original instruction in the relocated byte stream.
    ///
    /// The next original instruction is not a reliable right edge: the block
    /// encoder omits a rewritten branch from [`Self::moved`]. Decoding at this
    /// instruction's own mapped address measures its extent without depending
    /// on anything that follows it.
    pub fn instruction_len(&self, architecture: Architecture, original: Rva) -> Option<usize> {
        let moved = self.new_rva(original)?;
        let offset = moved.get().checked_sub(self.rva.get())?;
        let bytes = self.bytes.get(usize::try_from(offset).ok()?..)?;
        let mut decoder = Decoder::with_ip(
            bitness(architecture),
            bytes,
            u64::from(moved.get()),
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        (!instruction.is_invalid()).then_some(instruction.len())
    }
}

/// The first address handed to an instruction that has none of its own.
///
/// `BlockEncoder` identifies a branch target by matching it against the `ip` of
/// the instructions in the block, so every instruction needs one — including the
/// ones a transform inserted, which have no address in the input image. Anything
/// above the 32-bit RVA space serves: no decoded instruction can sit there and
/// no branch can name it, so a temporary address from this range cannot be
/// mistaken for a real one. It exists only for the length of one call.
const SYNTHETIC_IP_BASE: u64 = 1 << 32;

/// Re-encodes every instruction of `function`, in address order, at `rva`.
///
/// Instructions a transform inserted are encoded along with the rest; they are
/// simply absent from [`Relocated::moved`], because nothing can ask where an
/// address that never existed ended up.
pub fn relocate(function: &Function, rva: Rva) -> Result<Relocated, X86Error> {
    let bitness = bitness(function.architecture);

    let mut originals = Vec::with_capacity(function.instruction_count());
    let mut raw = Vec::with_capacity(function.instruction_count());
    for (index, instruction) in function.instructions().enumerate() {
        originals.push(instruction.rva());
        let mut encoded = *instruction.raw();
        if instruction.rva().is_none() {
            encoded.set_ip(SYNTHETIC_IP_BASE + index as u64);
        }
        raw.push(encoded);
    }

    let block = InstructionBlock::new(&raw, u64::from(rva.get()));
    let result = BlockEncoder::encode(
        bitness,
        block,
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )
    .map_err(|error| X86Error::Encode {
        rva,
        reason: error.to_string(),
    })?;

    let moved = originals
        .iter()
        .zip(result.new_instruction_offsets.iter())
        .filter(|(_, offset)| **offset != u32::MAX)
        .filter_map(|(original, offset)| Some(((*original)?, rva.checked_add(*offset)?)))
        .collect();

    Ok(Relocated {
        rva,
        bytes: result.code_buffer,
        moved,
    })
}

#[cfg(test)]
mod tests {
    use iced_x86::{Code, Decoder, DecoderOptions, Register};
    use vmp_ir::{BasicBlock, BlockId, CompileStage, Instruction, Terminator};
    use vmp_types::Architecture;

    use super::*;

    /// `jz 0x100a` / `nop` / `mov eax, 1` at 0x100a / `ret`.
    ///
    /// The branch crosses the point where a transform would insert, so its
    /// displacement has to grow by exactly what is inserted there.
    const BODY: &[u8] = &[
        0x74, 0x06, // 0x1000  jz 0x1008
        0x90, // 0x1002  nop
        0x48, 0x31, 0xc0, // 0x1003  xor rax, rax
        0x90, 0x90, // 0x1006  nop nop
        0xb8, 0x01, 0x00, 0x00, 0x00, // 0x1008  mov eax, 1
        0xc3, // 0x100d  ret
    ];

    fn decoded_body() -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(64, BODY, 0x1000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let start = usize::try_from(raw.ip() - 0x1000).expect("small");
            let rva = Rva(u32::try_from(raw.ip()).expect("small"));
            out.push(Instruction::decoded(
                rva,
                raw,
                &BODY[start..start + raw.len()],
            ));
        }
        out
    }

    fn function(instructions: Vec<Instruction>) -> Function {
        Function {
            architecture: Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
                end: Rva(0x100e),
                instructions,
                terminator: Terminator::Return,
                successors: Vec::new(),
                predecessors: Vec::new(),
            }],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    /// `cmp rcx, rcx`, three bytes, standing in for inert junk.
    fn junk() -> Instruction {
        let raw = iced_x86::Instruction::with2(Code::Cmp_rm64_r64, Register::RCX, Register::RCX)
            .expect("must build");
        // Built rather than decoded, so `raw.len()` is zero; the bytes are the
        // encoding the caller is responsible for producing
        assert_eq!(raw.len(), 0, "a built instruction carries no length");
        Instruction::inserted(raw, &[0x48, 0x39, 0xc9])
    }

    #[test]
    fn an_inserted_instruction_is_encoded_and_pushes_the_branch_target() {
        let plain = relocate(&function(decoded_body()), Rva(0x20000)).expect("must encode");

        let mut with_junk = decoded_body();
        // Between the `nop` at 0x1006 and the branch target at 0x1008
        let at = with_junk
            .iter()
            .position(|instruction| instruction.rva() == Some(Rva(0x1007)))
            .expect("the second nop is there");
        with_junk.insert(at, junk());
        let mutated = relocate(&function(with_junk), Rva(0x20000)).expect("must encode");

        assert_eq!(
            mutated.bytes.len(),
            plain.bytes.len() + 3,
            "the function grows by exactly the inserted encoding"
        );

        // The branch still points at the instruction it did, which has moved
        let target = mutated
            .new_rva(Rva(0x1008))
            .expect("the target is a decoded instruction");
        assert_eq!(
            target.get(),
            plain
                .new_rva(Rva(0x1008))
                .expect("present without junk either")
                .get()
                + 3,
            "the target moved by the length of the insertion"
        );
        let branch = Decoder::with_ip(64, &mutated.bytes, 0x20000, DecoderOptions::NONE).decode();
        assert_eq!(
            branch.near_branch_target(),
            u64::from(target.get()),
            "the branch was retargeted across the insertion"
        );
    }

    #[test]
    fn an_inserted_instruction_has_no_entry_in_the_move_map() {
        let mut instructions = decoded_body();
        let decoded_count = instructions.len();
        instructions.insert(1, junk());
        let relocated = relocate(&function(instructions), Rva(0x20000)).expect("must encode");

        assert_eq!(
            relocated.moved.len(),
            decoded_count,
            "only instructions that had an address are mapped"
        );
    }
}
