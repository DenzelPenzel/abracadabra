//! The catalogue of inert instructions placed between the real ones.
//!
//! A form is admitted only when iced's actual instruction information proves
//! that its complete machine-state effect is covered by the dead state.

use iced_x86::{
    Code, Encoder, FlowControl, Instruction as RawInstruction, InstructionInfoFactory, OpAccess,
    Register,
};
use vmp_types::Architecture;
use vmp_x86::{Registers, State};

use crate::Rng;

#[derive(Debug, Clone, Copy)]
enum Form {
    Fixed(Code),
    Mov32,
    Mov64,
    Not32,
    Not64,
    Bswap32,
    Bswap64,
}

pub(crate) struct Junk {
    pub name: &'static str,
    form: Form,
}

/// Template order is stable. Each register template records its valid dead
/// registers in architectural encoding order from [`Registers::iter`].
pub(crate) const CATALOGUE: &[Junk] = &[
    Junk {
        name: "junk-clc",
        form: Form::Fixed(Code::Clc),
    },
    Junk {
        name: "junk-stc",
        form: Form::Fixed(Code::Stc),
    },
    Junk {
        name: "junk-cmc",
        form: Form::Fixed(Code::Cmc),
    },
    Junk {
        name: "junk-mov-imm32",
        form: Form::Mov32,
    },
    Junk {
        name: "junk-mov-imm64",
        form: Form::Mov64,
    },
    Junk {
        name: "junk-not32",
        form: Form::Not32,
    },
    Junk {
        name: "junk-not64",
        form: Form::Not64,
    },
    Junk {
        name: "junk-bswap32",
        form: Form::Bswap32,
    },
    Junk {
        name: "junk-bswap64",
        form: Form::Bswap64,
    },
];

impl Junk {
    fn expected_access(&self) -> Option<OpAccess> {
        match self.form {
            Form::Fixed(_) => None,
            Form::Mov32 | Form::Mov64 => Some(OpAccess::Write),
            Form::Not32 | Form::Not64 | Form::Bswap32 | Form::Bswap64 => Some(OpAccess::ReadWrite),
        }
    }

    fn supported(&self, architecture: Architecture) -> bool {
        architecture == Architecture::X64
            || !matches!(self.form, Form::Mov64 | Form::Not64 | Form::Bswap64)
    }

    fn instantiate(
        &self,
        architecture: Architecture,
        register: Option<Register>,
        rng: &mut Rng,
    ) -> Option<RawInstruction> {
        if !self.supported(architecture) {
            return None;
        }
        if let Form::Fixed(code) = self.form {
            return register.is_none().then(|| RawInstruction::with(code));
        }
        let full = register?;
        let reg32 = full.full_register32();
        let raw = match self.form {
            Form::Fixed(_) => unreachable!("handled above"),
            Form::Mov32 => RawInstruction::with2(Code::Mov_r32_imm32, reg32, rng.next_u64() as u32),
            Form::Mov64 => RawInstruction::with2(Code::Mov_r64_imm64, full, rng.next_u64()),
            Form::Not32 => RawInstruction::with1(Code::Not_rm32, reg32),
            Form::Not64 => RawInstruction::with1(Code::Not_rm64, full),
            Form::Bswap32 => RawInstruction::with1(Code::Bswap_r32, reg32),
            Form::Bswap64 => RawInstruction::with1(Code::Bswap_r64, full),
        };
        raw.ok()
    }

    fn exact_form(&self, raw: &RawInstruction, architecture: Architecture) -> bool {
        if !self.supported(architecture) {
            return false;
        }
        let canonical = match self.form {
            Form::Fixed(code) => Some(RawInstruction::with(code)),
            Form::Mov32 if legal_register(raw.op0_register(), architecture, false) => {
                RawInstruction::with2(Code::Mov_r32_imm32, raw.op0_register(), raw.immediate32())
                    .ok()
            }
            Form::Mov64 if legal_register(raw.op0_register(), architecture, true) => {
                RawInstruction::with2(Code::Mov_r64_imm64, raw.op0_register(), raw.immediate64())
                    .ok()
            }
            Form::Not32 if legal_register(raw.op0_register(), architecture, false) => {
                RawInstruction::with1(Code::Not_rm32, raw.op0_register()).ok()
            }
            Form::Not64 if legal_register(raw.op0_register(), architecture, true) => {
                RawInstruction::with1(Code::Not_rm64, raw.op0_register()).ok()
            }
            Form::Bswap32 if legal_register(raw.op0_register(), architecture, false) => {
                RawInstruction::with1(Code::Bswap_r32, raw.op0_register()).ok()
            }
            Form::Bswap64 if legal_register(raw.op0_register(), architecture, true) => {
                RawInstruction::with1(Code::Bswap_r64, raw.op0_register()).ok()
            }
            _ => None,
        };
        let Some(canonical) = canonical.filter(|canonical| *canonical == *raw) else {
            return false;
        };
        if raw.len() == 0 {
            return true;
        }
        let bitness = match architecture {
            Architecture::X86 => 32,
            Architecture::X64 => 64,
        };
        let mut encoder = Encoder::new(bitness);
        encoder
            .encode(&canonical, raw.ip())
            .is_ok_and(|canonical_len| canonical_len == raw.len())
    }
}

pub(crate) struct Candidate {
    pub name: &'static str,
    entry: &'static Junk,
    registers: Vec<Register>,
}

impl Candidate {
    fn instantiate_for(&self, architecture: Architecture, rng: &mut Rng) -> Option<RawInstruction> {
        let register = if self.registers.is_empty() {
            None
        } else {
            Some(self.registers[rng.below(self.registers.len())?])
        };
        self.entry.instantiate(architecture, register, rng)
    }
}

pub(crate) fn candidates(architecture: Architecture, dead: State) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for entry in CATALOGUE {
        if let Form::Fixed(code) = entry.form {
            let raw = RawInstruction::with(code);
            if dead.flags.contains_all(clobbers(&raw)) {
                candidates.push(Candidate {
                    name: entry.name,
                    entry,
                    registers: Vec::new(),
                });
            }
            continue;
        }
        if !entry.supported(architecture) {
            continue;
        }
        let registers = dead
            .registers
            .iter()
            .filter(|&register| {
                let mut probe_rng = Rng::new(0);
                entry
                    .instantiate(architecture, Some(register), &mut probe_rng)
                    .is_some_and(|raw| {
                        admissible_register_form(entry, &raw, architecture, dead.registers)
                    })
            })
            .collect::<Vec<_>>();
        if !registers.is_empty() {
            candidates.push(Candidate {
                name: entry.name,
                entry,
                registers,
            });
        }
    }
    candidates
}

pub(crate) fn select_candidate(
    parent: &mut Rng,
    architecture: Architecture,
    candidates: &mut Vec<Candidate>,
) -> Option<(&'static str, RawInstruction)> {
    if candidates.is_empty() {
        return None;
    }
    let mut local = Rng::new(parent.next_u64());
    let pick = local.below(candidates.len())?;
    let candidate = candidates.remove(pick);
    let raw = candidate.instantiate_for(architecture, &mut local)?;
    Some((candidate.name, raw))
}

#[cfg(test)]
fn register_candidates(architecture: Architecture, dead: Registers) -> Vec<TestCandidate> {
    candidates(
        architecture,
        State {
            registers: dead,
            flags: vmp_x86::Flags::empty(),
        },
    )
    .into_iter()
    .filter_map(|candidate| {
        let mut rng = Rng::new(0);
        candidate
            .instantiate_for(architecture, &mut rng)
            .map(|raw| TestCandidate {
                name: candidate.name,
                raw,
            })
    })
    .collect()
}

#[cfg(test)]
struct TestCandidate {
    name: &'static str,
    raw: RawInstruction,
}

fn legal_register(register: Register, architecture: Architecture, width64: bool) -> bool {
    matches!(
        (architecture, width64, register),
        (
            Architecture::X86,
            false,
            Register::EAX
                | Register::ECX
                | Register::EDX
                | Register::EBX
                | Register::EBP
                | Register::ESI
                | Register::EDI,
        ) | (
            Architecture::X64,
            false,
            Register::EAX
                | Register::ECX
                | Register::EDX
                | Register::EBX
                | Register::EBP
                | Register::ESI
                | Register::EDI
                | Register::R8D
                | Register::R9D
                | Register::R10D
                | Register::R11D
                | Register::R12D
                | Register::R13D
                | Register::R14D
                | Register::R15D,
        ) | (
            Architecture::X64,
            true,
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::RBX
                | Register::RBP
                | Register::RSI
                | Register::RDI
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
                | Register::R12
                | Register::R13
                | Register::R14
                | Register::R15,
        )
    )
}

fn exact_register_effect(
    entry: &Junk,
    raw: &RawInstruction,
    architecture: Architecture,
) -> Option<Register> {
    if !entry.exact_form(raw, architecture)
        || raw.flow_control() != FlowControl::Next
        || raw.rflags_read() != 0
        || clobbers(raw) != 0
        || raw.op0_kind() != iced_x86::OpKind::Register
    {
        return None;
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(raw);
    if !info.used_memory().is_empty() || info.used_registers().is_empty() {
        return None;
    }
    let used = info.used_registers();
    let family = raw.op0_register().full_register();
    if !used
        .iter()
        .all(|effect| effect.register().full_register() == family)
    {
        return None;
    }
    let exact_access = match entry.expected_access()? {
        OpAccess::Write => matches!(used, [only] if only.access() == OpAccess::Write),
        OpAccess::ReadWrite => {
            matches!(used, [only] if only.access() == OpAccess::ReadWrite)
                || matches!(used, [read, write] if read.access() == OpAccess::Read && write.access() == OpAccess::Write)
        }
        _ => false,
    };
    exact_access.then_some(family)
}

fn admissible_register_form(
    entry: &Junk,
    raw: &RawInstruction,
    architecture: Architecture,
    dead: Registers,
) -> bool {
    classify(architecture, raw) == Some(entry.name)
        && dead.contains(raw.op0_register().full_register())
}

pub(crate) fn classify(architecture: Architecture, raw: &RawInstruction) -> Option<&'static str> {
    CATALOGUE.iter().find_map(|entry| {
        if !entry.exact_form(raw, architecture) {
            return None;
        }
        match entry.form {
            Form::Fixed(_) => Some(entry.name),
            _ if exact_register_effect(entry, raw, architecture).is_some() => Some(entry.name),
            _ => None,
        }
    })
}

/// Every flag the instruction stops describing: written, set, cleared, or left
/// undefined.
pub(crate) fn clobbers(raw: &RawInstruction) -> u32 {
    raw.rflags_written() | raw.rflags_set() | raw.rflags_cleared() | raw.rflags_undefined()
}

#[cfg(test)]
mod tests {
    use iced_x86::{
        Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, OpAccess, RflagsBits,
    };
    use vmp_types::Architecture;
    use vmp_x86::Registers;

    use super::*;

    #[test]
    fn flag_templates_clobber_only_the_carry_flag() {
        for entry in CATALOGUE
            .iter()
            .filter(|entry| matches!(entry.form, Form::Fixed(_)))
        {
            let raw = entry
                .instantiate(Architecture::X64, None, &mut crate::Rng::new(0))
                .expect("flag form");
            assert_eq!(clobbers(&raw), RflagsBits::CF, "{}", entry.name);
        }
    }

    fn architectural_registers(architecture: Architecture) -> &'static [Register] {
        match architecture {
            Architecture::X86 => &[
                Register::EAX,
                Register::ECX,
                Register::EDX,
                Register::EBX,
                Register::EBP,
                Register::ESI,
                Register::EDI,
            ],
            Architecture::X64 => &[
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::RBX,
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
            ],
        }
    }

    #[test]
    fn selection_consumes_exactly_one_parent_word() {
        let mut dead = Registers::empty();
        dead.insert(Register::RAX);
        dead.insert(Register::RCX);
        let state = State {
            registers: dead,
            flags: vmp_x86::Flags::empty(),
        };
        let mut candidates = candidates(Architecture::X64, state);
        let mut parent = Rng::new(0x1234_5678);
        let mut control = parent.clone();
        let _local_seed = control.next_u64();

        let selected = select_candidate(&mut parent, Architecture::X64, &mut candidates);

        assert!(selected.is_some());
        assert_eq!(parent.next_u64(), control.next_u64());
    }

    #[test]
    fn multi_dead_site_never_selects_the_same_template_twice() {
        let state = State {
            registers: Registers::all(Architecture::X64),
            flags: vmp_x86::Flags::empty(),
        };
        let mut candidates = candidates(Architecture::X64, state);
        let mut parent = Rng::new(7);
        let mut names = std::collections::BTreeSet::new();
        while let Some((name, _)) =
            select_candidate(&mut parent, Architecture::X64, &mut candidates)
        {
            assert!(names.insert(name), "selected template {name} twice");
        }
    }

    #[test]
    fn candidate_count_is_independent_of_dead_register_count() {
        let mut one = Registers::empty();
        one.insert(Register::RAX);
        let mut two = one;
        two.insert(Register::RCX);
        assert_eq!(
            register_candidates(Architecture::X64, one).len(),
            register_candidates(Architecture::X64, two).len()
        );
    }

    #[test]
    fn actual_iced_effects_match_every_legal_register_form() {
        let mut factory = InstructionInfoFactory::new();
        for architecture in [Architecture::X86, Architecture::X64] {
            for &register in architectural_registers(architecture) {
                let full = register.full_register();
                let mut dead = Registers::empty();
                dead.insert(full);
                let candidates = register_candidates(architecture, dead);
                let names = candidates
                    .iter()
                    .map(|candidate| candidate.name)
                    .collect::<Vec<_>>();
                let expected = match architecture {
                    Architecture::X86 => vec!["junk-mov-imm32", "junk-not32", "junk-bswap32"],
                    Architecture::X64 => vec![
                        "junk-mov-imm32",
                        "junk-mov-imm64",
                        "junk-not32",
                        "junk-not64",
                        "junk-bswap32",
                        "junk-bswap64",
                    ],
                };
                assert_eq!(names, expected, "{architecture:?} {register:?}");
                for candidate in candidates {
                    let info = factory.info(&candidate.raw);
                    assert_eq!(
                        candidate.raw.flow_control(),
                        FlowControl::Next,
                        "{}",
                        candidate.name
                    );
                    assert!(info.used_memory().is_empty(), "{}", candidate.name);
                    assert_eq!(candidate.raw.rflags_read(), 0, "{}", candidate.name);
                    assert_eq!(clobbers(&candidate.raw), 0, "{}", candidate.name);
                    let used = info.used_registers();
                    assert!(
                        !used.is_empty()
                            && used
                                .iter()
                                .all(|effect| effect.register().full_register() == full),
                        "{} has extra/implicit families: {used:?}",
                        candidate.name
                    );
                    let accesses = used
                        .iter()
                        .map(|effect| effect.access())
                        .collect::<Vec<_>>();
                    if candidate.name.starts_with("junk-mov-") {
                        assert_eq!(accesses, [OpAccess::Write], "{}", candidate.name);
                    } else {
                        assert!(
                            accesses == [OpAccess::ReadWrite]
                                || accesses == [OpAccess::Read, OpAccess::Write],
                            "{} has inexact access {accesses:?}",
                            candidate.name
                        );
                    }
                }
            }
        }
    }

    fn decode(bitness: u32, bytes: &[u8]) -> RawInstruction {
        Decoder::with_ip(bitness, bytes, 0, DecoderOptions::NONE).decode()
    }

    #[test]
    fn exact_classifier_rejects_unsafe_or_unsupported_forms() {
        // Operand kinds are derived from `Code` in iced, so unused internal
        // operand slots cannot appear in encoded bytes. A real extra prefix is
        // observable and must not be classified as one of our canonical forms.
        let prefixed_clc = decode(64, &[0x66, 0xf8]);
        let rsp = RawInstruction::with2(Code::Mov_r64_imm64, Register::RSP, 7u64)
            .expect("construct RSP form");
        let memory_not = decode(64, &[0x48, 0xf7, 0x10]);
        let wrong_architecture = RawInstruction::with2(Code::Mov_r64_imm64, Register::RAX, 7u64)
            .expect("construct x64 form");
        let partial = RawInstruction::with2(Code::Mov_r8_imm8, Register::AL, 7u32)
            .expect("construct partial-register form");
        let non_gpr = decode(64, &[0x0f, 0x20, 0xc0]);
        let extra_family = RawInstruction::with2(Code::Xchg_rm64_r64, Register::RAX, Register::RBX)
            .expect("construct two-family form");

        for (architecture, raw) in [
            (Architecture::X64, prefixed_clc),
            (Architecture::X64, rsp),
            (Architecture::X64, memory_not),
            (Architecture::X86, wrong_architecture),
            (Architecture::X64, partial),
            (Architecture::X64, non_gpr),
            (Architecture::X64, extra_family),
        ] {
            assert!(
                classify(architecture, &raw).is_none(),
                "accepted unsafe form {raw:?} for {architecture:?}"
            );
        }
    }

    #[test]
    fn rsp_forged_register_form_is_rejected() {
        let raw = RawInstruction::with2(Code::Mov_r64_imm64, Register::RSP, 7u64)
            .expect("construct forged form");
        assert!(classify(Architecture::X64, &raw).is_none());
    }

    #[test]
    fn x86_register_catalogue_has_no_64_bit_or_extended_register_forms() {
        let candidates = register_candidates(Architecture::X86, Registers::all(Architecture::X86));
        assert!(!candidates.is_empty());
        for candidate in candidates {
            assert!(matches!(
                candidate.raw.op0_register(),
                Register::EAX
                    | Register::ECX
                    | Register::EDX
                    | Register::EBX
                    | Register::EBP
                    | Register::ESI
                    | Register::EDI
            ));
            assert!(!candidate.name.ends_with("64"), "{}", candidate.name);
        }
    }

    #[test]
    fn every_name_is_distinct() {
        let mut names: Vec<&str> = CATALOGUE.iter().map(|entry| entry.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
