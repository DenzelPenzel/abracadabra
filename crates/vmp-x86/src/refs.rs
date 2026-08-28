//! Binding instruction operands to the PE container.

use iced_x86::{ConstantOffsets, Instruction as RawInstruction};
use vmp_ir::{AbsoluteWidth, BranchKind, DecodeIssue, FieldSpan, Instruction, OperandRef};
use vmp_types::{Rva, VirtualAddress};

use crate::decode::near_branch_rva;
use crate::image::Image;

/// Records every reference the instruction's operands carry.
pub(crate) fn bind(
    image: &Image<'_>,
    insn: &mut Instruction,
    offsets: &ConstantOffsets,
    issues: &mut Vec<DecodeIssue>,
) {
    let raw = *insn.raw();

    if let Some(reference) = branch_ref(&raw, offsets) {
        insn.push_ref(reference);
    }
    if let Some(reference) = rip_relative_ref(image, &raw, offsets) {
        insn.push_ref(reference);
    }
    bind_fixups(image, insn, offsets, issues);
}

/// The relative displacement of a direct branch or call.
fn branch_ref(raw: &RawInstruction, offsets: &ConstantOffsets) -> Option<OperandRef> {
    let target = near_branch_rva(raw)?;
    let kind = match raw.flow_control() {
        iced_x86::FlowControl::Call => BranchKind::Call,
        iced_x86::FlowControl::ConditionalBranch => BranchKind::Conditional,
        _ => BranchKind::Jump,
    };
    // A near branch encodes its displacement in the immediate field
    let field = span(offsets.immediate_offset(), offsets.immediate_size());
    Some(OperandRef::Branch {
        target,
        kind,
        field,
    })
}

/// A `[rip + disp32]` memory operand.
fn rip_relative_ref(
    image: &Image<'_>,
    raw: &RawInstruction,
    offsets: &ConstantOffsets,
) -> Option<OperandRef> {
    if !raw.is_ip_rel_memory_operand() {
        return None;
    }
    let target = Rva(u32::try_from(raw.ip_rel_memory_address()).ok()?);
    Some(OperandRef::RipRelative {
        target,
        target_kind: image.classify(target),
        field: span(offsets.displacement_offset(), offsets.displacement_size()),
    })
}

/// Binds every base relocation that falls inside the instruction to the
/// encoded field it patches.
///
/// A relocation that lands inside the instruction but on no field means the
/// instruction was decoded wrongly — the same validation the C++ original does
/// in `ReadValidCommand`.
fn bind_fixups(
    image: &Image<'_>,
    insn: &mut Instruction,
    offsets: &ConstantOffsets,
    issues: &mut Vec<DecodeIssue>,
) {
    let Some(rva) = insn.rva() else {
        return;
    };
    let len = insn.len();
    let fixups = image.fixups_in(rva, len as u8);
    if fixups.is_empty() {
        return;
    }

    let mut fields = Vec::with_capacity(3);
    if offsets.has_displacement() {
        fields.push(span(
            offsets.displacement_offset(),
            offsets.displacement_size(),
        ));
    }
    if offsets.has_immediate() {
        fields.push(span(offsets.immediate_offset(), offsets.immediate_size()));
    }
    if offsets.has_immediate2() {
        fields.push(span(offsets.immediate_offset2(), offsets.immediate_size2()));
    }

    let bytes = insn.bytes().to_vec();
    let base = image.image_base().get();

    for fixup in fixups {
        let inside = fixup.rva.get().wrapping_sub(rva.get());
        let Ok(inside) = u8::try_from(inside) else {
            continue;
        };
        // The loader patches exactly `fixup.kind.width()` bytes starting here,
        // so the encoded field must be that field and that width; anything else
        // means the instruction was decoded wrongly
        let width = match fixup.kind {
            vmp_pe::FixupKind::HighLow => AbsoluteWidth::Bits32,
            vmp_pe::FixupKind::Dir64 => AbsoluteWidth::Bits64,
        };
        let matching = fields
            .iter()
            .copied()
            .find(|f| f.offset == inside && f.size == width.byte_len());
        let Some(field) = matching else {
            issues.push(DecodeIssue::FixupOutsideField {
                rva,
                fixup: fixup.rva,
            });
            continue;
        };
        let Some(va) = read_field(&bytes, field) else {
            continue;
        };
        let target = va
            .checked_sub(base)
            .and_then(|offset| u32::try_from(offset).ok())
            .map(Rva)
            .filter(|target| image.is_mapped(*target));

        insn.push_ref(OperandRef::Absolute {
            va: VirtualAddress(va),
            target,
            width,
            target_kind: target.map_or(vmp_ir::TargetKind::Unmapped, |t| image.classify(t)),
            field,
        });
    }
}

/// Reads a little-endian field out of the instruction encoding.
fn read_field(bytes: &[u8], field: FieldSpan) -> Option<u64> {
    let start = usize::from(field.offset);
    let end = start.checked_add(usize::from(field.size))?;
    let raw = bytes.get(start..end)?;
    let mut value = [0u8; 8];
    value[..raw.len()].copy_from_slice(raw);
    Some(u64::from_le_bytes(value))
}

fn span(offset: usize, size: usize) -> FieldSpan {
    FieldSpan::new(
        u8::try_from(offset).unwrap_or(u8::MAX),
        u8::try_from(size).unwrap_or(0),
    )
}
