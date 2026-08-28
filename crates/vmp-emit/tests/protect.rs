//! Protecting the committed x64 fixture end to end.
//!
//! The fixture is the only real MSVC binary in the tree, so it is the only
//! place where the eligibility checks meet code they were written for. Each
//! test pins a property of the output rather than a byte count, because the
//! mutation catalogue is expected to grow.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, FlowControl, Instruction as RawInstruction,
    InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, RflagsBits,
};
use vmp_emit::{protect, Options, SkipReason};
use vmp_ir::{EdgeTarget, Function, Terminator};
use vmp_pe::{PeFile, PeImage};
use vmp_types::{Architecture, Rva};
use vmp_x86::{decode_function, Image};

fn test_binaries_dir() -> PathBuf {
    match std::env::var_os("VMP_TEST_BINARIES_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vmp-pe")
            .join("test-corpus"),
    }
}

fn read(name: &str) -> Option<Vec<u8>> {
    let path = test_binaries_dir().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            assert!(
                std::env::var_os("VMP_REQUIRE_TEST_BINARIES").is_none(),
                "VMP_REQUIRE_TEST_BINARIES is set but fixture {} is missing",
                path.display()
            );
            eprintln!("skipping: fixture {} not available", path.display());
            None
        }
    }
}

const FIXTURE: &str = "win64-app-msvc-amd64";

/// Every `.pdata` entry of the fixture, which is the widest set of real
/// function entry points a stripped binary offers.
fn entry_points(pe: &PeFile) -> Vec<Rva> {
    pe.exception_table
        .as_ref()
        .expect("the fixture has an exception directory")
        .functions()
        .map(|function| function.begin)
        .collect()
}

fn label(reason: &SkipReason) -> &'static str {
    match reason {
        SkipReason::NotDecodable(_) => "not-decodable",
        SkipReason::Incomplete(_) => "incomplete",
        SkipReason::NoUnwindData => "no-unwind-data",
        SkipReason::NotAFunctionEntry { .. } => "not-a-function-entry",
        SkipReason::UnwindNotReEmittable(_) => "unwind-not-re-emittable",
        SkipReason::PrologueMoved => "prologue-moved",
        SkipReason::EpilogueMoved => "epilogue-moved",
        SkipReason::HasAbsoluteFixups => "has-absolute-fixups",
        SkipReason::TooShortForStub { .. } => "too-short-for-stub",
        SkipReason::NothingToDo => "nothing-to-do",
        SkipReason::MutationFailed(_) => "mutation-failed",
    }
}

#[test]
fn protects_a_real_x64_binary_and_reports_every_refusal() {
    let Some(data) = read(FIXTURE) else { return };
    let image = PeImage::from_bytes(data).expect("fixture parses");
    let entries = entry_points(image.pe());
    assert!(!entries.is_empty(), "the fixture declares functions");

    let (output, outcome) = protect(image, &entries, &Options::default())
        .expect("at least one function is protectable");

    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    for skipped in &outcome.skipped {
        *reasons.entry(label(&skipped.reason)).or_default() += 1;
    }
    eprintln!(
        "protected {} of {} functions; refusals: {reasons:?}",
        outcome.protected.len(),
        entries.len()
    );

    assert!(
        !outcome.protected.is_empty(),
        "no function survived the checks; refusals were {reasons:?}"
    );
    assert_eq!(
        outcome.protected.len() + outcome.skipped.len(),
        entries.len(),
        "every requested function must be accounted for"
    );
    assert!(
        !reasons.contains_key("mutation-failed"),
        "a rewrite produced an instruction that would not encode: {reasons:?}"
    );

    PeFile::parse(output.bytes()).expect("the protected image must reparse");
}

#[test]
fn every_protected_entry_becomes_a_jump_to_its_copy() {
    let Some(data) = read(FIXTURE) else { return };
    let image = PeImage::from_bytes(data).expect("fixture parses");
    let entries = entry_points(image.pe());
    let (output, outcome) = protect(image, &entries, &Options::default()).expect("protects");

    let pe = output.pe();
    for protected in &outcome.protected {
        let offset = pe
            .rva_to_offset(protected.original)
            .expect("a protected entry is backed by file bytes")
            .get() as usize;
        let stub = &output.bytes()[offset..offset + 5];
        assert_eq!(
            stub[0], 0xe9,
            "entry {} must hold a near jmp",
            protected.original
        );

        let displacement = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
        let landing = (protected.original.get() as i64 + 5 + i64::from(displacement)) as u32;
        assert_eq!(
            landing,
            protected.relocated.get(),
            "the jmp at {} must land on the copy",
            protected.original
        );
    }
}

#[test]
fn every_copy_is_described_by_the_exception_directory() {
    let Some(data) = read(FIXTURE) else { return };
    let image = PeImage::from_bytes(data).expect("fixture parses");
    let entries = entry_points(image.pe());
    let (output, outcome) = protect(image, &entries, &Options::default()).expect("protects");

    let table = output
        .pe()
        .exception_table
        .as_ref()
        .expect("the protected image keeps an exception directory");
    for protected in &outcome.protected {
        let covering = table
            .functions()
            .find(|function| function.begin == protected.relocated);
        let covering = covering.unwrap_or_else(|| {
            panic!(
                "the copy at {} has no RUNTIME_FUNCTION entry",
                protected.relocated
            )
        });
        assert_eq!(
            covering.end.get(),
            protected.relocated.get() + protected.length,
            "the entry for {} must cover the whole copy",
            protected.relocated
        );
    }

    // The originals keep their entries: the stub is still inside them
    for entry in &entries {
        assert!(
            table.functions().any(|function| function.begin == *entry),
            "the original entry {entry} lost its RUNTIME_FUNCTION"
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DeadState {
    registers: u16,
    flags: u32,
}

fn register_slot(register: Register) -> Option<u32> {
    if !register.is_gpr() {
        return None;
    }
    u32::try_from(register.full_register().number()).ok()
}

fn legal_junk_register(architecture: Architecture, register: Register, width: usize) -> bool {
    let full = register.full_register();
    register.size() == width
        && full != Register::RSP
        && register_slot(full).is_some_and(|slot| {
            slot < match architecture {
                Architecture::X86 => 8,
                Architecture::X64 => 16,
            }
        })
}

fn junk_form(architecture: Architecture, raw: &RawInstruction) -> Option<&'static str> {
    let canonical = match raw.code() {
        Code::Clc if raw.op_count() == 0 => RawInstruction::with(Code::Clc),
        Code::Stc if raw.op_count() == 0 => RawInstruction::with(Code::Stc),
        Code::Cmc if raw.op_count() == 0 => RawInstruction::with(Code::Cmc),
        Code::Mov_r32_imm32
            if raw.op_count() == 2
                && raw.op0_kind() == OpKind::Register
                && raw.op1_kind() == OpKind::Immediate32
                && legal_junk_register(architecture, raw.op0_register(), 4) =>
        {
            RawInstruction::with2(Code::Mov_r32_imm32, raw.op0_register(), raw.immediate32())
                .ok()?
        }
        Code::Mov_r64_imm64
            if architecture == Architecture::X64
                && raw.op_count() == 2
                && raw.op0_kind() == OpKind::Register
                && raw.op1_kind() == OpKind::Immediate64
                && legal_junk_register(architecture, raw.op0_register(), 8) =>
        {
            RawInstruction::with2(Code::Mov_r64_imm64, raw.op0_register(), raw.immediate64())
                .ok()?
        }
        Code::Not_rm32
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(architecture, raw.op0_register(), 4) =>
        {
            RawInstruction::with1(Code::Not_rm32, raw.op0_register()).ok()?
        }
        Code::Not_rm64
            if architecture == Architecture::X64
                && raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(architecture, raw.op0_register(), 8) =>
        {
            RawInstruction::with1(Code::Not_rm64, raw.op0_register()).ok()?
        }
        Code::Bswap_r32
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(architecture, raw.op0_register(), 4) =>
        {
            RawInstruction::with1(Code::Bswap_r32, raw.op0_register()).ok()?
        }
        Code::Bswap_r64
            if architecture == Architecture::X64
                && raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(architecture, raw.op0_register(), 8) =>
        {
            RawInstruction::with1(Code::Bswap_r64, raw.op0_register()).ok()?
        }
        _ => return None,
    };
    if canonical != *raw {
        return None;
    }
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    let mut encoder = Encoder::new(bitness);
    if !encoder
        .encode(&canonical, raw.ip())
        .is_ok_and(|length| length == raw.len())
    {
        return None;
    }
    match raw.code() {
        Code::Clc => Some("junk-clc"),
        Code::Stc => Some("junk-stc"),
        Code::Cmc => Some("junk-cmc"),
        Code::Mov_r32_imm32 => Some("junk-mov-imm32"),
        Code::Mov_r64_imm64 => Some("junk-mov-imm64"),
        Code::Not_rm32 => Some("junk-not32"),
        Code::Not_rm64 => Some("junk-not64"),
        Code::Bswap_r32 => Some("junk-bswap32"),
        Code::Bswap_r64 => Some("junk-bswap64"),
        _ => None,
    }
}

fn junk_is_safe(raw: &RawInstruction, dead: DeadState) -> bool {
    if matches!(raw.code(), Code::Clc | Code::Stc | Code::Cmc) {
        return dead.flags & RflagsBits::CF != 0;
    }
    register_slot(raw.op0_register()).is_some_and(|slot| dead.registers & (1 << slot) != 0)
}

#[derive(Clone)]
struct Alignment {
    aligned: Vec<(RawInstruction, RawInstruction, bool)>,
    applied: BTreeMap<&'static str, usize>,
}

fn increment(applied: &mut BTreeMap<&'static str, usize>, name: &'static str) {
    *applied.entry(name).or_default() += 1;
}

fn applied_totals(applied: &BTreeMap<&'static str, usize>) -> (usize, usize) {
    let inserted = applied
        .iter()
        .filter(|(name, _)| name.starts_with("junk-"))
        .map(|(_, count)| *count)
        .sum();
    (applied.values().sum::<usize>() - inserted, inserted)
}

fn anchor_shape_matches(before: RawInstruction, after: RawInstruction) -> bool {
    let mut expected = before;
    let mut actual = after;
    if matches!(
        expected.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        expected.set_near_branch64(0);
        actual.set_near_branch64(0);
    }
    expected.as_near_branch();
    actual.as_near_branch();
    expected == actual
}

#[allow(clippy::too_many_arguments)]
fn enumerate_alignments(
    architecture: Architecture,
    dead_after: &BTreeMap<u64, DeadState>,
    before: &[RawInstruction],
    after: &[RawInstruction],
    i: usize,
    j: usize,
    candidate: Alignment,
    solutions: &mut Vec<Alignment>,
) {
    if solutions.len() == 2 {
        return;
    }
    if i == before.len() && j == after.len() {
        solutions.push(candidate);
        return;
    }
    if i < before.len() && j < after.len() && anchor_shape_matches(before[i], after[j]) {
        let mut next = candidate.clone();
        next.aligned.push((before[i], after[j], false));
        enumerate_alignments(
            architecture,
            dead_after,
            before,
            after,
            i + 1,
            j + 1,
            next,
            solutions,
        );
    }
    if i < before.len() && j < after.len() {
        let dead_flags = dead_after.get(&before[i].ip()).map_or(0, |dead| dead.flags);
        if let Some((name, length)) = rewrite_len(architecture, dead_flags, before[i], &after[j..])
        {
            let mut next = candidate.clone();
            next.aligned.push((before[i], after[j], true));
            increment(&mut next.applied, name);
            enumerate_alignments(
                architecture,
                dead_after,
                before,
                after,
                i + 1,
                j + length,
                next,
                solutions,
            );
        }
    }
    if i > 0 && j < after.len() {
        let Some(name) = junk_form(architecture, &after[j]) else {
            return;
        };
        let anchor = before[i - 1];
        if dead_after
            .get(&anchor.ip())
            .is_some_and(|dead| junk_is_safe(&after[j], *dead))
        {
            let mut next = candidate;
            increment(&mut next.applied, name);
            enumerate_alignments(
                architecture,
                dead_after,
                before,
                after,
                i,
                j + 1,
                next,
                solutions,
            );
        }
    }
}

fn align(
    before: &[RawInstruction],
    after: &[RawInstruction],
    at: Rva,
) -> (BTreeMap<&'static str, usize>, BTreeMap<u64, u64>) {
    let dead_after = before
        .iter()
        .map(|raw| {
            (
                raw.ip(),
                DeadState {
                    registers: 0xffef,
                    flags: u32::MAX,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    align_with_context(Architecture::X64, &dead_after, before, after, at)
}

fn align_with_context(
    architecture: Architecture,
    dead_after: &BTreeMap<u64, DeadState>,
    before: &[RawInstruction],
    after: &[RawInstruction],
    at: Rva,
) -> (BTreeMap<&'static str, usize>, BTreeMap<u64, u64>) {
    let initial = Alignment {
        aligned: Vec::with_capacity(before.len()),
        applied: BTreeMap::new(),
    };
    let mut solutions = Vec::with_capacity(2);
    enumerate_alignments(
        architecture,
        dead_after,
        before,
        after,
        0,
        0,
        initial,
        &mut solutions,
    );
    assert!(
        !solutions.is_empty(),
        "no complete alignment for the copy at {at}"
    );
    assert_eq!(
        solutions.len(),
        1,
        "ambiguous alignment for the copy at {at}"
    );
    let solution = solutions.pop().expect("exactly one solution");
    let (_, inserted) = applied_totals(&solution.applied);
    let rewrite_expansion = solution
        .applied
        .get("indirect-jump-to-push-ret")
        .copied()
        .unwrap_or_default();
    assert_eq!(
        after.len() - before.len(),
        inserted + rewrite_expansion,
        "the physical instruction increase in the copy at {at} is unexplained"
    );

    let moved: BTreeMap<u64, u64> = solution
        .aligned
        .iter()
        .map(|(before, after, _)| (before.ip(), after.ip()))
        .collect();
    for (before, after, is_rewrite) in solution.aligned {
        if !is_rewrite {
            assert!(
                same_semantics(before, after, &moved),
                "unexpected semantic change in the copy at {at}: {before:?} -> {after:?}"
            );
        }
    }

    (solution.applied, moved)
}

fn zeroing_sub_code(raw: &RawInstruction) -> Option<Code> {
    if raw.op0_kind() != OpKind::Register
        || raw.op1_kind() != OpKind::Register
        || raw.op0_register() != raw.op1_register()
    {
        return None;
    }

    match raw.code() {
        Code::Xor_rm8_r8 => Some(Code::Sub_rm8_r8),
        Code::Xor_r8_rm8 => Some(Code::Sub_r8_rm8),
        Code::Xor_rm16_r16 => Some(Code::Sub_rm16_r16),
        Code::Xor_r16_rm16 => Some(Code::Sub_r16_rm16),
        Code::Xor_rm32_r32 => Some(Code::Sub_rm32_r32),
        Code::Xor_r32_rm32 => Some(Code::Sub_r32_rm32),
        Code::Xor_rm64_r64 => Some(Code::Sub_rm64_r64),
        Code::Xor_r64_rm64 => Some(Code::Sub_r64_rm64),
        _ => None,
    }
}

fn rewrite_len(
    architecture: Architecture,
    dead_flags: u32,
    before: RawInstruction,
    after: &[RawInstruction],
) -> Option<(&'static str, usize)> {
    let first = *after.first()?;
    if let Some((name, expected)) =
        expected_single_instruction_rewrite(architecture, dead_flags, before)
    {
        return exact_physical_instruction(architecture, expected, first).then_some((name, 1));
    }
    match (before.mnemonic(), first.mnemonic()) {
        (Mnemonic::Jmp, Mnemonic::Push) => {
            let ret = after.get(1)?;
            canonical_jump_rewrite(architecture, before, first, *ret)
                .then_some(("indirect-jump-to-push-ret", 2))
        }
        _ => None,
    }
}

fn validate_rewrite(before: RawInstruction, after: &[RawInstruction], at: Rva) -> usize {
    validate_rewrite_with_context(Architecture::X64, u32::MAX, before, after, at)
}

fn validate_rewrite_with_context(
    architecture: Architecture,
    dead_flags: u32,
    before: RawInstruction,
    after: &[RawInstruction],
    at: Rva,
) -> usize {
    let first = after[0];
    if let Some((_, expected)) =
        expected_single_instruction_rewrite(architecture, dead_flags, before)
    {
        assert!(
            exact_physical_instruction(architecture, expected, first),
            "the rewrite in the copy at {at} is not the exact physical replacement"
        );
        return 1;
    }
    match (before.mnemonic(), first.mnemonic()) {
        (Mnemonic::Jmp, Mnemonic::Push) => {
            assert!(
                equivalent_indirect_push(before, first),
                "the rewrite source in the copy at {at} is not a supported indirect jump"
            );
            assert!(
                canonical_instruction(architecture, first),
                "the jump rewrite in the copy at {at} used a noncanonical push"
            );
            let ret = after
                .get(1)
                .unwrap_or_else(|| panic!("the jump rewrite in the copy at {at} lost its ret"));
            let expected = match architecture {
                Architecture::X86 => Code::Retnd,
                Architecture::X64 => Code::Retnq,
            };
            assert!(
                ret.code() == expected
                    && ret.op_count() == 0
                    && canonical_instruction(architecture, *ret),
                "the jump rewrite in the copy at {at} is not followed by the exact near return"
            );
            2
        }
        pair => panic!("unexpected substitution in the copy at {at}: {pair:?}, after={first:?}"),
    }
}

fn expected_single_instruction_rewrite(
    architecture: Architecture,
    dead_flags: u32,
    before: RawInstruction,
) -> Option<(&'static str, RawInstruction)> {
    if let Some(code) = zeroing_sub_code(&before) {
        let mut expected = before;
        expected.set_code(code);
        return Some(("zeroing-xor-to-sub", expected));
    }

    let clobbered = before.rflags_written()
        | before.rflags_set()
        | before.rflags_cleared()
        | before.rflags_undefined();
    if before.op0_kind() != OpKind::Register || dead_flags & clobbered != clobbered {
        return None;
    }

    let destination = before.op0_register();
    let (lea_code, stack) = match architecture {
        Architecture::X86 => (Code::Lea_r32_m, Register::ESP),
        Architecture::X64 => (Code::Lea_r64_m, Register::RSP),
    };
    if destination == stack {
        return None;
    }

    let mut expected = before;
    expected.set_code(lea_code);
    expected.set_op1_kind(OpKind::Memory);
    expected.set_memory_base(destination);
    expected.set_memory_index(Register::None);
    expected.set_memory_index_scale(1);
    expected.set_memory_displacement64(0);
    expected.set_memory_displ_size(0);

    let name = match (architecture, before.code(), before.op1_kind()) {
        (Architecture::X64, Code::Add_rm64_r64 | Code::Add_r64_rm64, OpKind::Register)
        | (Architecture::X86, Code::Add_rm32_r32 | Code::Add_r32_rm32, OpKind::Register) => {
            let source = before.op1_register();
            if source == stack {
                return None;
            }
            expected.set_memory_index(source);
            "add-to-lea"
        }
        (
            Architecture::X86,
            Code::Add_EAX_imm32 | Code::Add_rm32_imm32 | Code::Add_rm32_imm8,
            OpKind::Immediate32 | OpKind::Immediate8to32,
        ) if before.mnemonic() == Mnemonic::Add => {
            let immediate = match before.op1_kind() {
                OpKind::Immediate32 => before.immediate32(),
                OpKind::Immediate8to32 => before.immediate8to32() as u32,
                _ => return None,
            };
            expected.set_memory_displacement32(immediate);
            expected.set_memory_displ_size(4);
            "add-to-lea"
        }
        (
            Architecture::X86,
            Code::Sub_EAX_imm32 | Code::Sub_rm32_imm32 | Code::Sub_rm32_imm8,
            OpKind::Immediate32 | OpKind::Immediate8to32,
        ) if before.mnemonic() == Mnemonic::Sub => {
            let immediate = match before.op1_kind() {
                OpKind::Immediate32 => before.immediate32(),
                OpKind::Immediate8to32 => before.immediate8to32() as u32,
                _ => return None,
            };
            expected.set_memory_displacement32(0u32.wrapping_sub(immediate));
            expected.set_memory_displ_size(4);
            "sub-to-lea"
        }
        _ => return None,
    };
    Some((name, expected))
}

fn exact_physical_instruction(
    architecture: Architecture,
    mut expected: RawInstruction,
    actual: RawInstruction,
) -> bool {
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    expected.set_ip(actual.ip());
    let mut encoder = Encoder::new(bitness);
    let Ok(length) = encoder.encode(&expected, actual.ip()) else {
        return false;
    };
    if actual.len() != length {
        return false;
    }
    let bytes = encoder.take_buffer();
    let mut decoder = Decoder::with_ip(bitness, &bytes, actual.ip(), DecoderOptions::NONE);
    let decoded = decoder.decode();
    !decoder.can_decode() && decoded.len() == length && decoded == actual
}

fn equivalent_arithmetic_lea(
    architecture: Architecture,
    before: RawInstruction,
    after: RawInstruction,
    dead_flags: u32,
) -> bool {
    expected_single_instruction_rewrite(architecture, dead_flags, before)
        .is_some_and(|(_, expected)| exact_physical_instruction(architecture, expected, after))
}

fn canonical_instruction(architecture: Architecture, raw: RawInstruction) -> bool {
    let mut canonical = raw;
    canonical.set_has_lock_prefix(false);
    canonical.set_has_rep_prefix(false);
    canonical.set_has_repne_prefix(false);
    if raw.op_count() == 0 || raw.op0_kind() != OpKind::Memory {
        canonical.set_segment_prefix(Register::None);
    }
    if canonical != raw {
        return false;
    }

    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    let mut encoder = Encoder::new(bitness);
    let Ok(length) = encoder.encode(&canonical, raw.ip()) else {
        return false;
    };
    if length != raw.len() {
        return false;
    }
    let bytes = encoder.take_buffer();
    let mut decoder = Decoder::with_ip(bitness, &bytes, raw.ip(), DecoderOptions::NONE);
    let decoded = decoder.decode();
    !decoder.can_decode() && decoded.len() == length && decoded == canonical
}

fn canonical_jump_rewrite(
    architecture: Architecture,
    before: RawInstruction,
    push: RawInstruction,
    ret: RawInstruction,
) -> bool {
    let expected_ret = match architecture {
        Architecture::X86 => Code::Retnd,
        Architecture::X64 => Code::Retnq,
    };
    equivalent_indirect_push(before, push)
        && push.segment_prefix() == Register::None
        && canonical_instruction(architecture, push)
        && ret.code() == expected_ret
        && ret.op_count() == 0
        && canonical_instruction(architecture, ret)
}

fn equivalent_indirect_push(before: RawInstruction, after: RawInstruction) -> bool {
    let codes_match = matches!(
        (before.code(), after.code()),
        (Code::Jmp_rm32, Code::Push_rm32) | (Code::Jmp_rm64, Code::Push_rm64)
    );
    if !codes_match
        || before.op_count() != 1
        || after.op_count() != 1
        || before.op0_kind() != after.op0_kind()
    {
        return false;
    }
    match before.op0_kind() {
        OpKind::Register => before.op0_register() == after.op0_register(),
        OpKind::Memory => {
            before.memory_base() == after.memory_base()
                && before.memory_index() == after.memory_index()
                && before.memory_index_scale() == after.memory_index_scale()
                && before.memory_segment() == after.memory_segment()
                && if before.is_ip_rel_memory_operand() {
                    after.is_ip_rel_memory_operand()
                        && before.ip_rel_memory_address() == after.ip_rel_memory_address()
                } else {
                    before.memory_displacement64() == after.memory_displacement64()
                }
        }
        _ => false,
    }
}

fn same_semantics(
    before: RawInstruction,
    after: RawInstruction,
    moved: &BTreeMap<u64, u64>,
) -> bool {
    let mut expected = before;
    let mut actual = after;

    if matches!(
        expected.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        let target = expected.near_branch_target();
        expected.set_near_branch64(moved.get(&target).copied().unwrap_or(target));
    }
    expected.as_near_branch();
    actual.as_near_branch();

    expected == actual
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_matching_mnemonic_with_a_changed_immediate() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        vec![decoder.decode()]
    };

    align(
        &decode(&[0xb8, 0x01, 0x00, 0x00, 0x00]),
        &decode(&[0xb8, 0x02, 0x00, 0x00, 0x00]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "ambiguous alignment")]
fn align_rejects_an_inserted_duplicate_of_a_common_original_mov() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    let before = decode(&[0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3]);
    let after = decode(&[0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3]);
    align(&before, &after, Rva(0x1000));
}

#[test]
#[should_panic(expected = "ambiguous alignment")]
fn align_rejects_a_non_adjacent_inserted_duplicate_of_an_original_mov() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    // Original MOV, then a duplicate that could be either junk or the anchor,
    // a distinct valid junk instruction, and the real original MOV.
    let before = decode(&[0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3]);
    let after = decode(&[
        0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3,
    ]);
    align(&before, &after, Rva(0x1000));
}

#[test]
fn junk_classifier_rejects_noncanonical_prefixes() {
    let decode = |bytes: &[u8]| Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE).decode();

    assert_eq!(junk_form(Architecture::X64, &decode(&[0xf3, 0xf8])), None);
    assert_eq!(
        junk_form(Architecture::X64, &decode(&[0x40, 0xb8, 1, 0, 0, 0]),),
        None
    );
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn alignment_rejects_mov_to_an_independently_live_register() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    let before = decode(&[0x90, 0xc3]);
    let after = decode(&[0x90, 0xb8, 1, 0, 0, 0, 0xc3]);
    let dead = [(before[0].ip(), DeadState::default())]
        .into_iter()
        .collect();
    align_with_context(Architecture::X64, &dead, &before, &after, Rva(0x1000));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn alignment_rejects_clc_while_cf_is_independently_live() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    let before = decode(&[0x90, 0xc3]);
    let after = decode(&[0x90, 0xf8, 0xc3]);
    let dead = [(before[0].ip(), DeadState::default())]
        .into_iter()
        .collect();
    align_with_context(Architecture::X64, &dead, &before, &after, Rva(0x1000));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_an_inserted_unknown_instruction() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    align(
        &decode(&[0x31, 0xc0, 0xc3]),
        &decode(&[0x31, 0xc0, 0x90, 0xc3]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_non_zeroing_xor_to_substitution() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        vec![decoder.decode()]
    };

    align(&decode(&[0x31, 0xd8]), &decode(&[0x29, 0xd8]), Rva(0x1000));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_memory_xor_to_substitution() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        vec![decoder.decode()]
    };

    align(
        &decode(&[0x83, 0x30, 0x01]),
        &decode(&[0x83, 0x28, 0x01]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn alignment_rejects_a_redundantly_prefixed_zeroing_sub() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        vec![decoder.decode()]
    };

    align(
        &decode(&[0x31, 0xc0]),
        &decode(&[0xf3, 0x29, 0xc0]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "exact physical replacement")]
fn direct_validation_rejects_a_segment_prefixed_add_lea() {
    let decode = |bytes: &[u8]| Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE).decode();
    let before = decode(&[0x83, 0xc0, 0x01]);
    let after = [decode(&[0x2e, 0x8d, 0x80, 0x01, 0x00, 0x00, 0x00])];

    validate_rewrite_with_context(Architecture::X86, u32::MAX, before, &after, Rva(0x1000));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_an_add_to_lea_with_a_changed_index() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        vec![decoder.decode()]
    };

    // add rax, rbx must not be reported as lea rax, [rax + rcx].
    align(
        &decode(&[0x48, 0x01, 0xd8]),
        &decode(&[0x48, 0x8d, 0x04, 0x08]),
        Rva(0x1000),
    );
}

#[test]
fn arithmetic_lea_oracle_checks_architecture_and_dead_flags() {
    let decode = |bitness, bytes: &[u8]| {
        Decoder::with_ip(bitness, bytes, 0x1000, DecoderOptions::NONE).decode()
    };
    let all_arithmetic = RflagsBits::CF
        | RflagsBits::PF
        | RflagsBits::AF
        | RflagsBits::ZF
        | RflagsBits::SF
        | RflagsBits::OF;

    // add eax, 1 -> lea eax, [eax + 1] is a supported x86-only form.
    // Production requests a disp32, rather than the shorter equivalent disp8.
    let before = decode(32, &[0x83, 0xc0, 0x01]);
    let after = decode(32, &[0x8d, 0x80, 0x01, 0x00, 0x00, 0x00]);
    assert!(equivalent_arithmetic_lea(
        Architecture::X86,
        before,
        after,
        all_arithmetic,
    ));
    assert!(!equivalent_arithmetic_lea(
        Architecture::X64,
        before,
        after,
        all_arithmetic,
    ));
    assert!(!equivalent_arithmetic_lea(
        Architecture::X86,
        before,
        after,
        all_arithmetic & !RflagsBits::CF,
    ));

    // The same independent builder covers SUB's negated disp32.
    let before = decode(32, &[0x83, 0xe8, 0x01]);
    let after = decode(32, &[0x8d, 0x80, 0xff, 0xff, 0xff, 0xff]);
    assert!(equivalent_arithmetic_lea(
        Architecture::X86,
        before,
        after,
        all_arithmetic,
    ));

    // Prefix state carried by the source is preserved by the clone policy.
    let before = decode(32, &[0x2e, 0x83, 0xc0, 0x01]);
    let after = decode(32, &[0x2e, 0x8d, 0x80, 0x01, 0x00, 0x00, 0x00]);
    assert!(equivalent_arithmetic_lea(
        Architecture::X86,
        before,
        after,
        all_arithmetic,
    ));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_an_indirect_jump_rewrite_without_ret() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };

    // Keep the ModRM form emitted by the production rewrite so validation
    // reaches the missing-RET check rather than rejecting a different PUSH
    // encoding first.
    align(&decode(&[0xff, 0xe0]), &decode(&[0xff, 0xf0]), Rva(0x1000));
}

#[test]
#[should_panic(expected = "not followed by the exact near return")]
fn jump_oracle_rejects_ret_with_stack_adjustment() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };
    let before = decode(&[0xff, 0xe0]);
    let after = decode(&[0xff, 0xf0, 0xc2, 0x08, 0x00]);
    validate_rewrite(before[0], &after, Rva(0x1000));
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_redundantly_prefixed_ret_in_a_jump_rewrite() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };

    align(
        &decode(&[0xff, 0xe0]),
        &decode(&[0xff, 0xf0, 0xf3, 0xc3]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_redundantly_prefixed_push_in_a_jump_rewrite() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };

    align(
        &decode(&[0xff, 0xe0]),
        &decode(&[0xf3, 0xff, 0xf0, 0xc3]),
        Rva(0x1000),
    );
}

#[test]
#[should_panic(expected = "no complete alignment")]
fn align_rejects_a_segment_prefixed_memory_push_in_a_jump_rewrite() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };

    align(
        &decode(&[0xff, 0x20]),
        &decode(&[0x3e, 0xff, 0x30, 0xc3]),
        Rva(0x1000),
    );
}

#[test]
fn align_accepts_an_unprefixed_memory_push_in_a_jump_rewrite() {
    let decode = |bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            decoded.push(decoder.decode());
        }
        decoded
    };

    align(
        &decode(&[0xff, 0x20]),
        &decode(&[0xff, 0x30, 0xc3]),
        Rva(0x1000),
    );
}

fn assert_applied_matches(
    observed: &BTreeMap<&'static str, usize>,
    reported: &BTreeMap<&'static str, usize>,
    context: &str,
) {
    assert_eq!(
        observed, reported,
        "{context} does not match reported transforms"
    );
}

#[test]
#[should_panic(expected = "does not match reported transforms")]
fn applied_comparison_rejects_swapped_equal_count_junk_labels() {
    let observed = BTreeMap::from([("junk-mov-imm32", 1)]);
    let reported = BTreeMap::from([("junk-not32", 1)]);
    assert_applied_matches(&observed, &reported, "junk counterexample");
}

#[test]
#[should_panic(expected = "does not match reported transforms")]
fn applied_comparison_rejects_swapped_equal_count_rewrite_labels() {
    let observed = BTreeMap::from([("add-to-lea", 1), ("sub-to-lea", 1)]);
    let reported = BTreeMap::from([("zeroing-xor-to-sub", 1), ("indirect-jump-to-push-ret", 1)]);
    assert_applied_matches(&observed, &reported, "rewrite counterexample");
}

fn raws(function: &vmp_ir::Function) -> Vec<RawInstruction> {
    function.instructions().map(|i| *i.raw()).collect()
}

const TRACKED_FLAGS: u32 = RflagsBits::CF
    | RflagsBits::PF
    | RflagsBits::AF
    | RflagsBits::ZF
    | RflagsBits::SF
    | RflagsBits::OF
    | RflagsBits::DF
    | RflagsBits::IF
    | RflagsBits::AC
    | RflagsBits::UIF
    | RflagsBits::C0
    | RflagsBits::C1
    | RflagsBits::C2
    | RflagsBits::C3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LiveState {
    registers: u16,
    flags: u32,
}

fn architecture_registers(architecture: Architecture) -> u16 {
    match architecture {
        Architecture::X86 => 0x00ff,
        Architecture::X64 => 0xffff,
    }
}

fn all_live(architecture: Architecture) -> LiveState {
    LiveState {
        registers: architecture_registers(architecture),
        flags: TRACKED_FLAGS,
    }
}

fn live_union(left: LiveState, right: LiveState) -> LiveState {
    LiveState {
        registers: left.registers | right.registers,
        flags: left.flags | right.flags,
    }
}

fn opaque(raw: &RawInstruction) -> bool {
    matches!(
        raw.flow_control(),
        FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend
    )
}

fn access_reads(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn flag_writes_are_conditional(raw: &RawInstruction) -> bool {
    let count_operand = match raw.mnemonic() {
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
    if count_operand >= raw.op_count() {
        return true;
    }
    match raw.op_kind(count_operand) {
        OpKind::Immediate8 => raw.immediate8() & 0x1f == 0,
        _ => true,
    }
}

fn transfer_live(
    mut live: LiveState,
    raw: &RawInstruction,
    factory: &mut InstructionInfoFactory,
    architecture: Architecture,
) -> LiveState {
    if opaque(raw) {
        return all_live(architecture);
    }
    let info = factory.info(raw);
    for used in info.used_registers() {
        if used.access() == OpAccess::Write
            && used.register().is_gpr()
            && used.register().size() >= 4
        {
            if let Some(slot) = register_slot(used.register()) {
                live.registers &= !(1 << slot);
            }
        }
    }
    for used in info.used_registers() {
        if access_reads(used.access()) {
            if let Some(slot) = register_slot(used.register()) {
                live.registers |= 1 << slot;
            }
        }
    }
    if let Some(slot) = register_slot(Register::RSP) {
        live.registers |= 1 << slot;
    }

    let written = if flag_writes_are_conditional(raw) {
        0
    } else {
        raw.rflags_written() | raw.rflags_cleared() | raw.rflags_set()
    };
    live.flags = (live.flags & !written) | raw.rflags_read();
    live.flags &= TRACKED_FLAGS;
    live
}

fn block_escapes(block: &vmp_ir::BasicBlock) -> bool {
    block.successors.is_empty()
        || block
            .successors
            .iter()
            .any(|edge| matches!(edge.target, EdgeTarget::External(_)))
        || matches!(
            block.terminator,
            Terminator::Return
                | Terminator::IndirectJump
                | Terminator::ImportTailCall
                | Terminator::Halt
                | Terminator::Data
        )
}

fn independent_dead_after(function: &Function) -> BTreeMap<u64, DeadState> {
    let boundary = all_live(function.architecture);
    let mut live_in = vec![LiveState::default(); function.blocks.len()];
    let mut factory = InstructionInfoFactory::new();
    let mut converged = false;
    for _ in 0..512 {
        let mut changed = false;
        for block in function.blocks.iter().rev() {
            let mut live = if block_escapes(block) {
                boundary
            } else {
                let mut joined = LiveState::default();
                let mut valid = true;
                for edge in &block.successors {
                    if let EdgeTarget::Block(id) = edge.target {
                        if let Some(successor) = live_in.get(id.index()) {
                            joined = live_union(joined, *successor);
                        } else {
                            valid = false;
                        }
                    }
                }
                if valid {
                    joined
                } else {
                    boundary
                }
            };
            for instruction in block.instructions.iter().rev() {
                live = transfer_live(live, instruction.raw(), &mut factory, function.architecture);
            }
            let Some(slot) = live_in.get_mut(block.id.index()) else {
                return function
                    .instructions()
                    .filter_map(|instruction| instruction.rva())
                    .map(|rva| (u64::from(rva.get()), DeadState::default()))
                    .collect();
            };
            if *slot != live {
                *slot = live;
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        live_in.fill(boundary);
    }

    let mut result = BTreeMap::new();
    for block in &function.blocks {
        let mut live = if !converged || block_escapes(block) {
            boundary
        } else {
            let mut joined = LiveState::default();
            for edge in &block.successors {
                if let EdgeTarget::Block(id) = edge.target {
                    joined =
                        live_union(joined, live_in.get(id.index()).copied().unwrap_or(boundary));
                }
            }
            joined
        };
        for instruction in block.instructions.iter().rev() {
            if let Some(rva) = instruction.rva() {
                result.insert(
                    u64::from(rva.get()),
                    DeadState {
                        registers: !live.registers & architecture_registers(function.architecture),
                        flags: !live.flags & TRACKED_FLAGS,
                    },
                );
            }
            live = transfer_live(live, instruction.raw(), &mut factory, function.architecture);
        }
    }
    result
}

#[test]
fn each_copy_decodes_to_the_same_instruction_sequence_modulo_the_transforms() {
    let Some(data) = read(FIXTURE) else { return };
    let image = PeImage::from_bytes(data).expect("fixture parses");
    let entries = entry_points(image.pe());
    let original_data = image.bytes().to_vec();
    let original_pe = PeFile::parse(&original_data).expect("parses");
    let (output, outcome) = protect(image, &entries, &Options::default()).expect("protects");

    let protected_data = output.bytes().to_vec();
    let protected_pe = PeFile::parse(&protected_data).expect("parses");

    for protected in &outcome.protected {
        let before = decode_function(Image::new(&original_pe, &original_data), protected.original)
            .expect("the original decoded once already");
        let after = decode_function(
            Image::new(&protected_pe, &protected_data),
            protected.relocated,
        )
        .unwrap_or_else(|error| panic!("the copy at {} must decode: {error}", protected.relocated));

        let (observed, moved) = align_with_context(
            before.architecture,
            &independent_dead_after(&before),
            &raws(&before),
            &raws(&after),
            protected.relocated,
        );
        assert_eq!(moved.len(), before.instruction_count());
        assert_applied_matches(
            &observed,
            &protected.report.applied,
            &format!("the copy at {}", protected.relocated),
        );
    }
}

#[test]
fn junk_only_changes_copies_exactly_where_the_report_claims() {
    let Some(data) = read(FIXTURE) else { return };
    let original_pe = PeFile::parse(&data).expect("parses");
    let entries = entry_points(&original_pe);
    let options = Options {
        seed: vmp_mutation::Seed::new(7),
        mutation: vmp_mutation::Options {
            rewrites: false,
            junk: true,
        },
        ..Options::default()
    };
    let image = PeImage::from_bytes(data.clone()).expect("parses");
    let (output, outcome) = protect(image, &entries, &options).expect("junk protects something");
    let protected_data = output.bytes().to_vec();
    let protected_pe = PeFile::parse(&protected_data).expect("the output reparses");
    let mut total_junk = 0usize;

    for protected in &outcome.protected {
        let before = decode_function(Image::new(&original_pe, &data), protected.original)
            .expect("the original decoded once already");
        let after = decode_function(
            Image::new(&protected_pe, &protected_data),
            protected.relocated,
        )
        .unwrap_or_else(|error| panic!("the copy at {} must decode: {error}", protected.relocated));
        let (observed, moved) = align_with_context(
            before.architecture,
            &independent_dead_after(&before),
            &raws(&before),
            &raws(&after),
            protected.relocated,
        );
        assert_eq!(moved.len(), before.instruction_count());
        let (rewritten, inserted) = applied_totals(&observed);

        assert_eq!(rewritten, 0, "rewrites are disabled");
        assert!(inserted > 0, "a protected function must contain junk");
        assert_applied_matches(
            &observed,
            &protected.report.applied,
            &format!("the copy at {}", protected.relocated),
        );
        total_junk += inserted;
    }

    assert!(
        total_junk > 0,
        "the fixed seed must exercise the junk-only path"
    );
}

#[test]
fn the_same_seed_produces_the_same_image() {
    let Some(data) = read(FIXTURE) else { return };
    let entries = entry_points(&PeFile::parse(&data).expect("parses"));

    let run = |seed: u64| {
        let options = Options {
            seed: vmp_mutation::Seed::new(seed),
            ..Options::default()
        };
        let image = PeImage::from_bytes(data.clone()).expect("parses");
        protect(image, &entries, &options)
            .expect("protects")
            .0
            .into_bytes()
    };

    assert_eq!(run(7), run(7), "the same seed must be reproducible");
    assert_ne!(
        run(7),
        run(8),
        "a different seed must produce a different image"
    );
}

/// The core safety property, over many seeds rather than one.
///
/// A fixed seed exercises one path through the coin flips; the catalogue is
/// only sound if *every* path is. Each difference between an original and its
/// copy must be either a rewrite the report claims, on the same register, or an
/// insertion the report claims — and nothing else may move.
#[test]
fn every_seed_produces_copies_that_differ_only_where_the_report_says() {
    let Some(data) = read(FIXTURE) else { return };
    let original_pe = PeFile::parse(&data).expect("parses");
    let entries = entry_points(&original_pe);

    let mut total_rewrites = 0usize;
    let mut total_junk = 0usize;
    let mut seeds_with_work = 0usize;

    for seed in 0..24u64 {
        let options = Options {
            seed: vmp_mutation::Seed::new(seed),
            ..Options::default()
        };
        let image = PeImage::from_bytes(data.clone()).expect("parses");
        let (output, outcome) = protect(image, &entries, &options)
            .unwrap_or_else(|error| panic!("seed {seed}: protecting failed: {error}"));

        let protected_data = output.bytes().to_vec();
        let protected_pe = PeFile::parse(&protected_data).expect("the output reparses");

        for protected in &outcome.protected {
            let before = decode_function(Image::new(&original_pe, &data), protected.original)
                .expect("the original decoded once already");
            let after = decode_function(
                Image::new(&protected_pe, &protected_data),
                protected.relocated,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "seed {seed}: the copy at {} must decode: {error}",
                    protected.relocated
                )
            });

            let (observed, moved) = align_with_context(
                before.architecture,
                &independent_dead_after(&before),
                &raws(&before),
                &raws(&after),
                protected.relocated,
            );
            assert_eq!(moved.len(), before.instruction_count());
            assert_applied_matches(
                &observed,
                &protected.report.applied,
                &format!("seed {seed}: the copy at {}", protected.relocated),
            );
            let (rewritten, inserted) = applied_totals(&observed);
            total_rewrites += rewritten;
            total_junk += inserted;
        }

        if !outcome.protected.is_empty() {
            seeds_with_work += 1;
        }
    }

    assert_eq!(seeds_with_work, 24, "every seed must protect something");
    // A sweep that rewrote almost nothing would pass every assertion above
    // while proving almost nothing
    assert!(
        total_rewrites > 500,
        "only {total_rewrites} rewrites across 24 seeds; the sweep is too thin to \
         be evidence"
    );
    assert!(
        total_junk > 5_000,
        "only {total_junk} insertions across 24 seeds; the sweep is too thin to \
         be evidence"
    );
}
