//! The catalogue of equivalent rewrites.
//!
//! Each entry replaces one instruction with a different encoding of the same
//! observable behaviour. "Observable" is the load-bearing word: a rewrite may
//! leave a flag *more* defined than the original did, because no correct
//! program can depend on an architecturally undefined flag, but it may never
//! leave one *less* defined.
//!
//! The C++ original keeps its catalogue in `IntelFunction::Mutate`
//! (`core/intel.cc:16293-16371`). That switch has five arms, but the `cmCall`
//! arm has an empty body, so four rewrites actually run.

use iced_x86::{Code, Instruction as RawInstruction, OpKind, Register};
use vmp_ir::Terminator;
use vmp_types::Architecture;
use vmp_x86::Flags;

/// Rewrites available to [`super::mutate`].
///
/// Ordered as they are tried. Each is gated on its own coin flip, matching the
/// `rand() & 1` the original applies per rewrite.
pub(crate) const CATALOGUE: &[Rewrite] = &[
    Rewrite {
        name: "zeroing-xor-to-sub",
        apply: zeroing_xor_to_sub,
    },
    Rewrite {
        name: "add-to-lea",
        apply: add_to_lea,
    },
    Rewrite {
        name: "sub-to-lea",
        apply: sub_to_lea,
    },
    Rewrite {
        name: "indirect-jump-to-push-ret",
        apply: indirect_jump_to_push_ret,
    },
];

pub(crate) struct Rewrite {
    /// Stable identifier, reported so a diff of two protected builds can name
    /// what changed.
    pub name: &'static str,
    pub apply: fn(&RawInstruction, Architecture, Option<Flags>) -> Option<Replacement>,
}

pub(crate) struct Replacement {
    pub first: RawInstruction,
    pub second: Option<RawInstruction>,
    pub terminator: Option<Terminator>,
}

impl Replacement {
    fn one(first: RawInstruction) -> Replacement {
        Replacement {
            first,
            second: None,
            terminator: None,
        }
    }

    fn terminating(
        first: RawInstruction,
        second: RawInstruction,
        terminator: Terminator,
    ) -> Replacement {
        Replacement {
            first,
            second: Some(second),
            terminator: Some(terminator),
        }
    }
}

/// `xor reg, reg` → `sub reg, reg`.
///
/// Both clear the register and set CF=OF=SF=0, ZF=PF=1. They differ in AF
/// alone: `XOR` leaves it undefined, `SUB` defines it as 0. The rewrite
/// therefore only ever removes undefinedness, which is the safe direction.
fn zeroing_xor_to_sub(
    raw: &RawInstruction,
    _architecture: Architecture,
    _dead_after: Option<Flags>,
) -> Option<Replacement> {
    if raw.op0_kind() != OpKind::Register || raw.op1_kind() != OpKind::Register {
        return None;
    }
    if raw.op0_register() != raw.op1_register() {
        return None;
    }

    let code = match raw.code() {
        Code::Xor_rm8_r8 => Code::Sub_rm8_r8,
        Code::Xor_r8_rm8 => Code::Sub_r8_rm8,
        Code::Xor_rm16_r16 => Code::Sub_rm16_r16,
        Code::Xor_r16_rm16 => Code::Sub_r16_rm16,
        Code::Xor_rm32_r32 => Code::Sub_rm32_r32,
        Code::Xor_r32_rm32 => Code::Sub_r32_rm32,
        Code::Xor_rm64_r64 => Code::Sub_rm64_r64,
        Code::Xor_r64_rm64 => Code::Sub_r64_rm64,
        _ => return None,
    };

    let mut rewritten = *raw;
    rewritten.set_code(code);
    Some(Replacement::one(rewritten))
}

fn add_to_lea(
    raw: &RawInstruction,
    architecture: Architecture,
    dead_after: Option<Flags>,
) -> Option<Replacement> {
    arithmetic_to_lea(raw, architecture, dead_after, false)
}

fn sub_to_lea(
    raw: &RawInstruction,
    architecture: Architecture,
    dead_after: Option<Flags>,
) -> Option<Replacement> {
    arithmetic_to_lea(raw, architecture, dead_after, true)
}

fn arithmetic_to_lea(
    raw: &RawInstruction,
    architecture: Architecture,
    dead_after: Option<Flags>,
    subtract: bool,
) -> Option<Replacement> {
    let dead_after = dead_after?;
    let clobbered =
        raw.rflags_written() | raw.rflags_set() | raw.rflags_cleared() | raw.rflags_undefined();
    if !dead_after.contains_all(clobbered) || raw.op0_kind() != OpKind::Register {
        return None;
    }

    let destination = raw.op0_register();
    let (lea_code, full_width_stack) = match architecture {
        Architecture::X86 => (Code::Lea_r32_m, Register::ESP),
        Architecture::X64 => (Code::Lea_r64_m, Register::RSP),
    };
    if destination == full_width_stack {
        return None;
    }

    let mut rewritten = *raw;
    rewritten.set_code(lea_code);
    rewritten.set_op1_kind(OpKind::Memory);
    rewritten.set_memory_base(destination);
    rewritten.set_memory_index(Register::None);
    rewritten.set_memory_index_scale(1);
    rewritten.set_memory_displacement64(0);
    rewritten.set_memory_displ_size(0);

    match (architecture, subtract, raw.code(), raw.op1_kind()) {
        (Architecture::X64, false, Code::Add_rm64_r64 | Code::Add_r64_rm64, OpKind::Register)
        | (Architecture::X86, false, Code::Add_rm32_r32 | Code::Add_r32_rm32, OpKind::Register) => {
            let source = raw.op1_register();
            if source == full_width_stack {
                return None;
            }
            rewritten.set_memory_index(source);
        }
        (
            Architecture::X86,
            is_subtract,
            Code::Add_EAX_imm32
            | Code::Add_rm32_imm32
            | Code::Add_rm32_imm8
            | Code::Sub_EAX_imm32
            | Code::Sub_rm32_imm32
            | Code::Sub_rm32_imm8,
            OpKind::Immediate32 | OpKind::Immediate8to32,
        ) if is_subtract == subtract
            && raw.mnemonic()
                == if subtract {
                    iced_x86::Mnemonic::Sub
                } else {
                    iced_x86::Mnemonic::Add
                } =>
        {
            let immediate = match raw.op1_kind() {
                OpKind::Immediate32 => raw.immediate32(),
                OpKind::Immediate8to32 => raw.immediate8to32() as u32,
                _ => unreachable!(),
            };
            let displacement = if subtract {
                0u32.wrapping_sub(immediate)
            } else {
                immediate
            };
            rewritten.set_memory_displacement32(displacement);
            rewritten.set_memory_displ_size(4);
        }
        _ => return None,
    }

    Some(Replacement::one(rewritten))
}

fn has_carried_prefix(raw: &RawInstruction) -> bool {
    raw.has_lock_prefix()
        || raw.has_rep_prefix()
        || raw.has_repne_prefix()
        || raw.segment_prefix() != Register::None
}

fn indirect_jump_to_push_ret(
    raw: &RawInstruction,
    architecture: Architecture,
    _dead_after: Option<Flags>,
) -> Option<Replacement> {
    let push_code = match (architecture, raw.code()) {
        (Architecture::X86, Code::Jmp_rm32) => Code::Push_rm32,
        (Architecture::X64, Code::Jmp_rm64) => Code::Push_rm64,
        _ => return None,
    };
    if !matches!(raw.op0_kind(), OpKind::Register | OpKind::Memory) || has_carried_prefix(raw) {
        return None;
    }

    let mut push = *raw;
    push.set_code(push_code);
    let ret = RawInstruction::with(match architecture {
        Architecture::X86 => Code::Retnd,
        Architecture::X64 => Code::Retnq,
    });
    Some(Replacement::terminating(push, ret, Terminator::Return))
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};

    use super::*;

    fn decode(bitness: u32, bytes: &[u8]) -> RawInstruction {
        Decoder::new(bitness, bytes, DecoderOptions::NONE).decode()
    }

    #[test]
    fn rewrites_the_zeroing_idiom_at_every_width() {
        for (bitness, bytes, register) in [
            (64u32, &[0x31u8, 0xc0][..], Register::EAX),
            (64, &[0x48, 0x31, 0xdb][..], Register::RBX),
            (64, &[0x66, 0x31, 0xc9][..], Register::CX),
            (64, &[0x30, 0xe4][..], Register::AH),
            (32, &[0x31, 0xff][..], Register::EDI),
        ] {
            let raw = decode(bitness, bytes);
            assert_eq!(
                raw.op0_register(),
                register,
                "test vector decodes as expected"
            );
            let rewritten = zeroing_xor_to_sub(&raw, Architecture::X64, None)
                .unwrap_or_else(|| panic!("{bytes:02x?} must rewrite"))
                .first;
            assert_eq!(rewritten.mnemonic(), Mnemonic::Sub);
            assert_eq!(rewritten.op0_register(), raw.op0_register());
            assert_eq!(rewritten.op1_register(), raw.op1_register());
        }
    }

    #[test]
    fn leaves_a_non_zeroing_xor_alone() {
        // Different registers: not a zeroing idiom
        assert!(zeroing_xor_to_sub(&decode(64, &[0x31, 0xd8]), Architecture::X64, None).is_none());
        // Memory destination
        assert!(zeroing_xor_to_sub(&decode(64, &[0x31, 0x00]), Architecture::X64, None).is_none());
        // Immediate source
        assert!(
            zeroing_xor_to_sub(&decode(64, &[0x83, 0xf0, 0x01]), Architecture::X64, None).is_none()
        );
        // Not an xor at all
        assert!(zeroing_xor_to_sub(&decode(64, &[0x29, 0xc0]), Architecture::X64, None).is_none());
    }

    #[test]
    fn rejects_prefixed_indirect_jumps() {
        for bytes in [[0x3e, 0xff, 0x20], [0x3e, 0xff, 0xe0]] {
            let raw = decode(64, &bytes);
            assert!(
                indirect_jump_to_push_ret(&raw, Architecture::X64, None).is_none(),
                "{bytes:02x?} must not carry its prefix into a push"
            );
        }
    }

    #[test]
    fn rewrites_unprefixed_indirect_jumps() {
        for bytes in [[0xff, 0x20], [0xff, 0xe0]] {
            let raw = decode(64, &bytes);
            assert!(
                indirect_jump_to_push_ret(&raw, Architecture::X64, None).is_some(),
                "{bytes:02x?} must remain eligible"
            );
        }
    }
}
