//! Decoding one instruction and classifying it for the traversal.

use iced_x86::{
    ConstantOffsets, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};
use vmp_ir::TargetKind;
use vmp_types::Rva;

use crate::image::Image;

/// What the traversal needs to know about one decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classification {
    pub flow: FlowKind,
    pub link: Option<(LinkKind, Rva)>,
    pub issue: Option<IssueKind>,
}

/// How an instruction ends — or does not end — a straight-line run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKind {
    /// Control continues at the next address.
    Normal,
    /// A direct unconditional `jmp`.
    Jump,
    /// `jcc`, `jcxz` or `loop`.
    Conditional,
    /// `ret` or `iret`.
    Return,
    /// An indirect or far `jmp`.
    IndirectJump,
    /// An indirect `jmp` through a resolvable import thunk.
    ImportTailCall,
    /// Control does not continue: `int3`, `int 0x29`, `hlt`, `ud2`.
    Halt,
    /// Not an instruction.
    Data,
}

impl FlowKind {
    /// Mirrors `IntelCommand::is_end`: the linear walk stops here.
    pub(crate) fn is_end(self) -> bool {
        matches!(
            self,
            FlowKind::Jump
                | FlowKind::IndirectJump
                | FlowKind::ImportTailCall
                | FlowKind::Return
                | FlowKind::Data
        )
    }

    /// Mirrors the `roBreaked` option: control never reaches the next address.
    pub(crate) fn is_breaked(self) -> bool {
        matches!(self, FlowKind::Halt)
    }

    pub(crate) fn is_data(self) -> bool {
        matches!(self, FlowKind::Data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkKind {
    /// `ltCall` — recorded but never followed.
    Call,
    /// `ltJmp` — deferred by the traversal until it can be classified.
    Jmp,
    /// `ltJmpWithFlag` — a conditional branch, followed immediately.
    JmpWithFlag,
}

/// A decode problem that makes the function unprotectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IssueKind {
    IndirectJump,
    InvalidOpcode,
    UnsupportedControlFlow,
}

pub(crate) struct Decoded {
    pub raw: Instruction,
    pub offsets: ConstantOffsets,
    pub len: usize,
}

/// Decodes a single instruction at `rva`.
///
/// The decoder's `ip` is the RVA, so branch and RIP-relative targets come back
/// as RVAs without a rebasing step.
pub(crate) fn decode_at(bitness: u32, bytes: &[u8], rva: Rva) -> Option<Decoded> {
    if bytes.is_empty() {
        return None;
    }
    let mut decoder =
        Decoder::try_with_ip(bitness, bytes, u64::from(rva.get()), DecoderOptions::NONE).ok()?;
    let raw = decoder.decode();
    let len = raw.len();
    if len == 0 || len > bytes.len() {
        return None;
    }
    let offsets = decoder.get_constant_offsets(&raw);
    Some(Decoded { raw, offsets, len })
}

/// Whether this decode is the `add byte ptr [rax], al` reading of two zero
/// padding bytes.
///
/// The C++ original deletes such a command outright (`core/intel.cc:14870`)
/// rather than letting alignment padding masquerade as code.
pub(crate) fn is_zero_padding(raw: &Instruction, bytes: &[u8]) -> bool {
    raw.mnemonic() == Mnemonic::Add && bytes == [0, 0]
}

/// Classifies a decoded instruction for the traversal.
pub(crate) fn classify(image: &Image<'_>, raw: &Instruction) -> Classification {
    if raw.is_invalid() {
        return Classification {
            flow: FlowKind::Data,
            link: None,
            issue: Some(IssueKind::InvalidOpcode),
        };
    }

    let plain = |flow: FlowKind| Classification {
        flow,
        link: None,
        issue: None,
    };
    let broken = |flow: FlowKind, issue: IssueKind| Classification {
        flow,
        link: None,
        issue: Some(issue),
    };

    match raw.flow_control() {
        FlowControl::Next => {
            // `hlt` and the `ud` family stop the path without being branches
            match raw.mnemonic() {
                Mnemonic::Hlt | Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2 => {
                    plain(FlowKind::Halt)
                }
                _ => plain(FlowKind::Normal),
            }
        }
        FlowControl::UnconditionalBranch => match near_branch_rva(raw) {
            Some(target) => Classification {
                flow: FlowKind::Jump,
                link: Some((LinkKind::Jmp, target)),
                issue: None,
            },
            // A far jump, or a target outside the RVA space
            None => indirect_jump(image, raw),
        },
        FlowControl::IndirectBranch => indirect_jump(image, raw),
        FlowControl::ConditionalBranch => match near_branch_rva(raw) {
            Some(target) => Classification {
                flow: FlowKind::Conditional,
                link: Some((LinkKind::JmpWithFlag, target)),
                issue: None,
            },
            None => broken(FlowKind::Normal, IssueKind::UnsupportedControlFlow),
        },
        FlowControl::Return => plain(FlowKind::Return),
        // Call targets are never followed, so an unresolvable one is harmless:
        // control still returns to the next instruction
        FlowControl::Call => match near_branch_rva(raw) {
            Some(target) => Classification {
                flow: FlowKind::Normal,
                link: Some((LinkKind::Call, target)),
                issue: None,
            },
            None => plain(FlowKind::Normal),
        },
        FlowControl::IndirectCall => plain(FlowKind::Normal),
        FlowControl::Interrupt => {
            // `int3` and `int 0x29` (__fastfail) do not return
            let breaks = raw.mnemonic() == Mnemonic::Int3
                || (raw.mnemonic() == Mnemonic::Int
                    && raw.op_count() == 1
                    && raw.immediate8() == 0x29);
            if breaks {
                plain(FlowKind::Halt)
            } else {
                plain(FlowKind::Normal)
            }
        }
        FlowControl::Exception => plain(FlowKind::Halt),
        FlowControl::XbeginXabortXend => {
            broken(FlowKind::Normal, IssueKind::UnsupportedControlFlow)
        }
    }
}

/// Classifies an indirect `jmp`.
///
/// A jump through an import thunk is a tail call whose target the loader
/// resolves, so it is as determined as a direct branch. Everything else — a
/// register target, a jump table, a computed address — has an unknown target
/// set and makes the function unprotectable, because table recovery is not part
/// of this stage.
fn indirect_jump(image: &Image<'_>, raw: &Instruction) -> Classification {
    match import_thunk_target(image, raw) {
        Some(_) => Classification {
            flow: FlowKind::ImportTailCall,
            link: None,
            issue: None,
        },
        None => Classification {
            flow: FlowKind::IndirectJump,
            link: None,
            issue: Some(IssueKind::IndirectJump),
        },
    }
}

/// The import thunk read by memory operand `operand`.
///
/// x64 accepts only RIP-relative memory; x86 accepts only an absolute address
/// with no base or index and subtracts ImageBase with checked arithmetic.
pub(crate) fn memory_import_thunk_target(
    image: &Image<'_>,
    raw: &Instruction,
    operand: u32,
) -> Option<Rva> {
    if raw.op_kind(operand) != OpKind::Memory {
        return None;
    }
    let target = match image.architecture() {
        vmp_types::Architecture::X64 if raw.is_ip_rel_memory_operand() => {
            Rva(u32::try_from(raw.ip_rel_memory_address()).ok()?)
        }
        vmp_types::Architecture::X86
            if !raw.is_ip_rel_memory_operand()
                && raw.memory_base() == Register::None
                && raw.memory_index() == Register::None =>
        {
            let offset = raw
                .memory_displacement64()
                .checked_sub(image.image_base().get())?;
            Rva(u32::try_from(offset).ok()?)
        }
        _ => return None,
    };

    (image.classify(target) == TargetKind::ImportThunk).then_some(target)
}

/// The import thunk an indirect branch reads its target from.
///
/// x64 addresses the slot RIP-relatively; x86 encodes its absolute virtual
/// address in the displacement.
pub(crate) fn import_thunk_target(image: &Image<'_>, raw: &Instruction) -> Option<Rva> {
    memory_import_thunk_target(image, raw, 0)
}

/// The near-branch target as an RVA, when the instruction has one.
pub(crate) fn near_branch_rva(raw: &Instruction) -> Option<Rva> {
    let has_near_branch = raw.op_kinds().any(|kind| {
        matches!(
            kind,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    });
    if !has_near_branch {
        return None;
    }
    u32::try_from(raw.near_branch_target()).ok().map(Rva)
}
