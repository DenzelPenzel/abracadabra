//! Decoding every function entry discoverable in the committed PE corpus.
//!
//! PE32+ entries come from `.pdata`. Stripped PE32 has no equivalent function
//! table, so its sweep starts from EntryPoint, exports and TLS callbacks, then
//! follows exact near calls like production SDK discovery. Each test pins values
//! that belong to one specific binary, so the fixtures live next to `vmp-pe` and
//! run in every checkout.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use iced_x86::{Code, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use vmp_ir::{DecodeIssue, EdgeTarget, Function};
use vmp_pe::{exports::ExportTarget, PeFile};
use vmp_types::{Architecture, Rva};
use vmp_x86::{
    analyze_liveness, decode_function, epilogues, relocate,
    sdk_markers::discover_direct_api_markers, Image,
};

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

/// The address of an instruction that must have one.
///
/// Every function in the corpus is freshly decoded, so nothing here was
/// produced by a transform. Saying so loudly beats threading an `Option` through
/// a checker whose own `Option` already means "found a violation".
fn decoded_rva(instruction: &vmp_ir::Instruction) -> Rva {
    instruction
        .rva()
        .expect("a decoded function has an address for every instruction")
}

/// Every `.pdata` entry of a fixture, decoded.
struct Sweep {
    decoded: Vec<Function>,
    failed: Vec<(Rva, String)>,
}

impl Sweep {
    fn run(pe: &PeFile, data: &[u8]) -> Sweep {
        let image = Image::new(pe, data);
        let entries: Vec<Rva> = pe
            .exception_table
            .as_ref()
            .expect("fixture must have an exception directory")
            .functions()
            .map(|function| function.begin)
            .collect();

        let mut decoded = Vec::new();
        let mut failed = Vec::new();
        for entry in entries {
            match decode_function(image, entry) {
                Ok(function) => decoded.push(function),
                Err(error) => failed.push((entry, error.to_string())),
            }
        }
        Sweep { decoded, failed }
    }

    fn complete(&self) -> impl Iterator<Item = &Function> {
        self.decoded
            .iter()
            .filter(|function| function.is_complete())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pe32EntrySource {
    EntryPoint,
    Export,
    TlsCallback,
    DirectCall { caller: Rva },
}

fn enqueue_pe32_entry(
    queue: &mut VecDeque<Rva>,
    entries: &mut BTreeMap<Rva, Vec<Pe32EntrySource>>,
    entry: Rva,
    source: Pe32EntrySource,
) {
    let is_new = !entries.contains_key(&entry);
    if is_new {
        assert!(entries.len() < 4_096, "PE32 function-entry limit exceeded");
        queue.push_back(entry);
    }
    let sources = entries.entry(entry).or_default();
    if !sources.contains(&source) {
        sources.push(source);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Pe32Summary {
    fixture: &'static str,
    entry_roots: usize,
    export_roots: usize,
    tls_roots: usize,
    recursive_entries: usize,
    entries: usize,
    complete: usize,
    issue_entries: usize,
    indirect_jump_issues: usize,
    other_issues: usize,
    decode_failures: usize,
    sdk_markers: usize,
}

fn sweep_pe32(fixture: &'static str, data: &[u8]) -> Pe32Summary {
    let pe = PeFile::parse(data).expect("PE32 corpus fixture must parse");
    assert_eq!(pe.architecture, Architecture::X86, "{fixture}");
    let image = Image::new(&pe, data);
    let mut queue = VecDeque::new();
    let mut entries = BTreeMap::new();

    let entry = pe.entry_point();
    if image.is_executable(entry) {
        enqueue_pe32_entry(&mut queue, &mut entries, entry, Pe32EntrySource::EntryPoint);
    }
    if let Some(exports) = pe.exports.as_ref() {
        for export in &exports.entries {
            let ExportTarget::Code(target) = export.target else {
                continue;
            };
            if image.is_executable(target) {
                enqueue_pe32_entry(&mut queue, &mut entries, target, Pe32EntrySource::Export);
            }
        }
    }
    if let Some(tls) = pe.tls.as_ref() {
        for &callback in &tls.callbacks {
            if image.is_executable(callback) {
                enqueue_pe32_entry(
                    &mut queue,
                    &mut entries,
                    callback,
                    Pe32EntrySource::TlsCallback,
                );
            }
        }
    }

    let mut complete = 0usize;
    let mut issue_entries = 0usize;
    let mut indirect_jump_issues = 0usize;
    let mut other_issues = 0usize;
    let mut decode_failures = Vec::new();
    while let Some(function_entry) = queue.pop_front() {
        let function = match decode_function(image, function_entry) {
            Ok(function) => function,
            Err(error) => {
                decode_failures.push((function_entry, error.to_string()));
                continue;
            }
        };
        if function.issues.is_empty() {
            complete += 1;
        } else {
            issue_entries += 1;
            for issue in &function.issues {
                match issue {
                    DecodeIssue::IndirectJump { .. } => indirect_jump_issues += 1,
                    _ => other_issues += 1,
                }
            }
            eprintln!(
                "{fixture}: {function_entry} from {:?} is fail-closed: {:?}",
                entries
                    .get(&function_entry)
                    .expect("entry source is retained"),
                function.issues
            );
        }
        for instruction in function.instructions() {
            let raw = instruction.raw();
            if !matches!(raw.code(), Code::Call_rel16 | Code::Call_rel32_32) {
                continue;
            }
            let Ok(target) = u32::try_from(raw.near_branch_target()) else {
                continue;
            };
            let target = Rva(target);
            if image.is_executable(target) {
                enqueue_pe32_entry(
                    &mut queue,
                    &mut entries,
                    target,
                    Pe32EntrySource::DirectCall {
                        caller: function_entry,
                    },
                );
            }
        }
    }

    assert!(
        decode_failures.is_empty(),
        "{fixture}: every discovered entry must decode or carry DecodeIssue: {decode_failures:?}"
    );
    assert_eq!(
        complete + issue_entries + decode_failures.len(),
        entries.len(),
        "every discovered entry must have an explicit classification"
    );
    let source_count = |source: Pe32EntrySource| {
        entries
            .values()
            .filter(|sources| sources.contains(&source))
            .count()
    };
    let recursive_entries = entries
        .values()
        .filter(|sources| {
            sources
                .iter()
                .any(|source| matches!(source, Pe32EntrySource::DirectCall { .. }))
        })
        .count();
    let sdk_markers = discover_direct_api_markers(image)
        .unwrap_or_else(|error| panic!("{fixture}: production SDK traversal failed: {error}"))
        .len();
    Pe32Summary {
        fixture,
        entry_roots: source_count(Pe32EntrySource::EntryPoint),
        export_roots: source_count(Pe32EntrySource::Export),
        tls_roots: source_count(Pe32EntrySource::TlsCallback),
        recursive_entries,
        entries: entries.len(),
        complete,
        issue_entries,
        indirect_jump_issues,
        other_issues,
        decode_failures: decode_failures.len(),
        sdk_markers,
    }
}

#[test]
fn every_discovered_pe32_function_entry_is_classified() {
    let fixtures = [
        "win32-app-delphi-i386",
        "win32-app-test1-i386",
        "win32-dll-test1-i386",
        "seh-x86",
    ];
    let summaries: Vec<_> = fixtures
        .into_iter()
        .map(|fixture| {
            let data = read(fixture).expect("the required PE32 corpus fixture must exist");
            sweep_pe32(fixture, &data)
        })
        .collect();

    assert_eq!(
        summaries,
        [
            Pe32Summary {
                fixture: "win32-app-delphi-i386",
                entry_roots: 1,
                export_roots: 0,
                tls_roots: 0,
                recursive_entries: 298,
                entries: 299,
                complete: 293,
                issue_entries: 6,
                indirect_jump_issues: 6,
                other_issues: 0,
                decode_failures: 0,
                sdk_markers: 0,
            },
            Pe32Summary {
                fixture: "win32-app-test1-i386",
                entry_roots: 1,
                export_roots: 0,
                tls_roots: 0,
                recursive_entries: 7,
                entries: 8,
                complete: 8,
                issue_entries: 0,
                indirect_jump_issues: 0,
                other_issues: 0,
                decode_failures: 0,
                sdk_markers: 0,
            },
            Pe32Summary {
                fixture: "win32-dll-test1-i386",
                entry_roots: 1,
                export_roots: 0,
                tls_roots: 0,
                recursive_entries: 3,
                entries: 4,
                complete: 4,
                issue_entries: 0,
                indirect_jump_issues: 0,
                other_issues: 0,
                decode_failures: 0,
                sdk_markers: 0,
            },
            Pe32Summary {
                fixture: "seh-x86",
                entry_roots: 1,
                export_roots: 0,
                tls_roots: 0,
                recursive_entries: 1,
                entries: 2,
                complete: 2,
                issue_entries: 0,
                indirect_jump_issues: 0,
                other_issues: 0,
                decode_failures: 0,
                sdk_markers: 0,
            },
        ]
    );
}

#[test]
fn decodes_every_pdata_function_of_the_win64_fixture() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    assert!(
        sweep.failed.is_empty(),
        "every .pdata entry must decode: {:?}",
        sweep.failed
    );
    assert_eq!(
        sweep.decoded.len(),
        115,
        "the fixture declares 115 functions"
    );

    let complete = sweep.complete().count();
    // The remainder are the jump-table dispatchers the C++ original recovers
    // with switch analysis, which this stage deliberately leaves fail-closed
    assert_eq!(
        complete, 115,
        "every function decodes without issues; got {complete}"
    );
}

#[test]
fn every_internal_branch_resolves_to_a_block() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    for function in sweep.complete() {
        let unwind = function
            .unwind
            .expect("a .pdata entry covers its own start");
        for block in &function.blocks {
            for edge in &block.successors {
                let EdgeTarget::External(target) = edge.target else {
                    continue;
                };
                // An unresolved edge is only acceptable when it genuinely leaves
                // the range `.pdata` gave for this function
                assert!(
                    !unwind.contains(target),
                    "function {} has an unresolved edge to {target}, inside its own .pdata range",
                    function.entry
                );
            }
        }
    }
}

#[test]
fn blocks_tile_their_instructions_without_gaps_or_overlap() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    for function in &sweep.decoded {
        let mut ranges: Vec<(Rva, Rva)> = function
            .blocks
            .iter()
            .map(|block| (block.start, block.end))
            .collect();
        ranges.sort_unstable();
        for window in ranges.windows(2) {
            assert!(
                window[0].1 <= window[1].0,
                "blocks {:?} and {:?} of function {} overlap",
                window[0],
                window[1],
                function.entry
            );
        }

        for block in &function.blocks {
            assert!(!block.instructions.is_empty(), "no block may be empty");
            let mut cursor = block.start;
            for instruction in &block.instructions {
                assert_eq!(
                    instruction.rva(),
                    Some(cursor),
                    "instructions must be contiguous"
                );
                cursor = instruction.next_rva().expect("no RVA overflow");
            }
            assert_eq!(
                cursor, block.end,
                "block end must follow its last instruction"
            );
        }
    }
}

#[test]
fn predecessors_mirror_successors() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    for function in &sweep.decoded {
        for block in &function.blocks {
            for edge in &block.successors {
                let EdgeTarget::Block(target) = edge.target else {
                    continue;
                };
                let successor = function.block(target).expect("edge must name a real block");
                assert!(
                    successor.predecessors.contains(&block.id),
                    "block {:?} lists {:?} as a successor but not the reverse",
                    block.id,
                    target
                );
            }
        }
    }
}

#[test]
fn re_encoding_in_place_preserves_behaviour() {
    check_round_trip(None);
}

#[test]
fn moving_a_function_preserves_behaviour() {
    // Far enough that every relative displacement has to be recomputed rather
    // than happening to stay valid
    check_round_trip(Some(Rva(0x20_0000)));
}

/// Re-encodes every complete function and checks that behaviour survives.
///
/// Bytes deliberately are not compared: iced normalises encodings — it drops
/// MSVC's redundant `REX` prefix on `push rbx` and rewrites a near branch as a
/// short one when it fits. What must hold is that the instruction sequence is
/// the same and that every branch still reaches the instruction it did before.
fn check_round_trip(destination: Option<Rva>) {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    let mut functions = 0;
    let mut branches = 0;

    for function in sweep.complete() {
        // Contiguous functions only: re-encoding one whose blocks are scattered
        // packs the gaps out, which is a layout change rather than a round trip
        if !is_contiguous(function) {
            continue;
        }
        let target = destination.unwrap_or(function.entry);
        let encoded = relocate(function, target).expect("a complete function must re-encode");
        let originals: Vec<_> = function.instructions().collect();

        assert_eq!(
            encoded.moved.len(),
            originals.len(),
            "function {} had instructions rewritten into several",
            function.entry
        );

        let reencoded = decode_all(&encoded.bytes, target);
        assert_eq!(
            reencoded.len(),
            originals.len(),
            "function {} changed instruction count",
            function.entry
        );

        for (original, new) in originals.iter().zip(reencoded.iter()) {
            let expected_branch = original
                .branch_target()
                .map(|target| encoded.new_rva(target).unwrap_or(target));
            assert!(
                same_semantics(original.raw(), new, expected_branch),
                "instruction at {:?} in function {} changed semantics: {:?} -> {:?}",
                original.rva(),
                function.entry,
                original.raw(),
                new
            );
            if expected_branch.is_some() {
                branches += 1;
            }
        }
        functions += 1;
    }

    assert!(functions > 50, "only {functions} functions were checked");
    assert!(branches > 100, "only {branches} branches were checked");
}

/// Whether the function's blocks cover one uninterrupted address range.
fn is_contiguous(function: &Function) -> bool {
    let mut ranges: Vec<(Rva, Rva)> = function
        .blocks
        .iter()
        .map(|block| (block.start, block.end))
        .collect();
    ranges.sort_unstable();
    ranges.windows(2).all(|pair| pair[0].1 == pair[1].0)
}

/// Decodes a freshly encoded buffer back into instructions.
fn decode_all(bytes: &[u8], rva: Rva) -> Vec<iced_x86::Instruction> {
    let mut decoder = iced_x86::Decoder::with_ip(
        64,
        bytes,
        u64::from(rva.get()),
        iced_x86::DecoderOptions::NONE,
    );
    let mut out = Vec::new();
    while decoder.can_decode() {
        out.push(decoder.decode());
    }
    out
}

/// Whether re-encoding preserved every decoded operand and semantic modifier.
///
/// `Instruction` equality deliberately ignores IP and encoded length, which
/// permits harmless encoding normalization while still comparing registers,
/// immediates, memory addressing, prefixes and condition codes. The only value
/// relocation may change is a direct branch target, supplied explicitly here;
/// short and near forms are normalized because the block encoder may promote a
/// branch whose old displacement no longer reaches.
fn same_semantics(
    original: &iced_x86::Instruction,
    reencoded: &iced_x86::Instruction,
    expected_branch: Option<Rva>,
) -> bool {
    let mut expected = *original;
    if let Some(target) = expected_branch {
        expected.set_near_branch64(u64::from(target.get()));
    }
    expected.as_near_branch();
    let mut actual = *reencoded;
    actual.as_near_branch();
    expected == actual
}

#[test]
fn semantic_oracle_rejects_an_immediate_change() {
    let original = decode_all(&[0xb8, 0x01, 0x00, 0x00, 0x00], Rva(0x1000));
    let changed = decode_all(&[0xb8, 0x02, 0x00, 0x00, 0x00], Rva(0x2000));

    assert!(!same_semantics(&original[0], &changed[0], None));
}

#[test]
fn semantic_oracle_accepts_a_promoted_direct_branch() {
    // jne short 0x1007 -> jne near 0x3007. Relocation may widen the encoding,
    // but the condition and the caller-supplied semantic target must agree.
    let original = decode_all(&[0x75, 0x05], Rva(0x1000));
    let promoted = decode_all(&[0x0f, 0x85, 0x01, 0x10, 0x00, 0x00], Rva(0x2000));

    assert!(same_semantics(
        &original[0],
        &promoted[0],
        Some(Rva(0x3007))
    ));
}

#[test]
fn semantic_oracle_compares_the_rip_relative_target_not_the_displacement() {
    // Both first loads reach 0x2000 despite carrying different displacements;
    // the third keeps the old displacement after moving and reaches 0x3000.
    let original = decode_all(&[0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00], Rva(0x1000));
    let preserved = decode_all(&[0x8b, 0x05, 0xfa, 0xff, 0xff, 0xff], Rva(0x2000));
    let changed = decode_all(&[0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00], Rva(0x2000));

    assert!(same_semantics(&original[0], &preserved[0], None));
    assert!(!same_semantics(&original[0], &changed[0], None));
}

/// Pins the encoding normalisation that the round-trip tests tolerate.
///
/// MSVC emits `push rbx` with an empty `REX` prefix; iced re-encodes it without
/// one. Nothing downstream may assume that re-encoding an untouched instruction
/// reproduces its original bytes.
#[test]
fn re_encoding_drops_a_redundant_rex_prefix() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let image = Image::new(&pe, &data);

    let function = decode_function(image, Rva(0x1184)).expect("function must decode");
    let first = function
        .instructions()
        .next()
        .expect("the function has instructions");
    assert_eq!(first.bytes(), [0x40, 0x53], "MSVC pads `push rbx` with REX");

    let encoded = relocate(&function, function.entry).expect("must re-encode");
    assert_eq!(&encoded.bytes[..1], [0x53], "iced drops the empty prefix");
}

/// The operand holding the count of a shift or rotate, or `None` for anything
/// else.
///
/// Duplicated from the analysis on purpose: a checker that calls the code under
/// test cannot disagree with it.
fn shift_count_operand(raw: &iced_x86::Instruction) -> Option<u32> {
    match raw.mnemonic() {
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Sal
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr => Some(1),
        Mnemonic::Shld | Mnemonic::Shrd => Some(2),
        _ => None,
    }
}

/// Liveness over every completely decoded function of the fixture.
///
/// The invariants are what a wrong answer would break, and they are checked
/// against `iced` directly rather than against the analysis' own bookkeeping:
/// a register or flag an instruction reads has to be in use before it, or some
/// mutation would be free to overwrite a value that is about to be read.
#[test]
fn liveness_holds_its_invariants_on_the_corpus() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let sweep = Sweep::run(&pe, &data);

    let mut factory = InstructionInfoFactory::new();
    let mut functions = 0usize;
    let mut instructions = 0usize;
    let mut with_dead_register = 0usize;
    let mut with_dead_flag = 0usize;
    let mut dead_registers = 0usize;
    let mut dead_flags = 0usize;
    let mut rounds = 0usize;
    // What the corpus does and does not exercise, reported so a rule with no
    // cover here is visible rather than assumed covered
    let mut shifts_by_cl = 0usize;
    let mut shifts_by_immediate = 0usize;
    let mut calls = 0usize;

    for function in sweep.complete() {
        functions += 1;
        let liveness = analyze_liveness(function);
        assert!(
            !liveness.saturated(),
            "the fixpoint must converge for the function at {}",
            function.entry
        );
        rounds = rounds.max(liveness.rounds());

        for block in &function.blocks {
            for (index, instruction) in block.instructions.iter().enumerate() {
                let rva = instruction.rva().expect("a decoded function has addresses");
                let raw = instruction.raw();
                let before = liveness
                    .live_before(rva)
                    .expect("every instruction has an answer");
                let after = liveness
                    .live_after(rva)
                    .expect("every instruction has an answer");

                assert!(
                    before.registers.contains(Register::RSP)
                        && after.registers.contains(Register::RSP),
                    "the stack pointer is never free, at {rva}"
                );

                match shift_count_operand(raw) {
                    Some(operand)
                        if operand < raw.op_count()
                            && raw.op_kind(operand) == OpKind::Immediate8 =>
                    {
                        shifts_by_immediate += 1;
                    }
                    Some(_) => shifts_by_cl += 1,
                    None => {}
                }
                if matches!(
                    raw.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ) {
                    calls += 1;
                }

                // Whatever the instruction reads must be in use on the way in
                let info = factory.info(raw);
                for used in info.used_registers() {
                    let reads = matches!(
                        used.access(),
                        OpAccess::Read
                            | OpAccess::CondRead
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    );
                    assert!(
                        !reads || before.registers.contains(used.register()),
                        "{rva} reads {:?} but it is not live before it",
                        used.register()
                    );
                }
                assert!(
                    before.flags.contains_all(raw.rflags_read()),
                    "{rva} reads flags that are not live before it"
                );

                // The state after one instruction is the state before the next
                if let Some(next) = block.instructions.get(index + 1) {
                    assert_eq!(
                        after,
                        liveness
                            .live_before(decoded_rva(next))
                            .expect("every instruction has an answer"),
                        "the state between {rva} and {} disagrees",
                        decoded_rva(next)
                    );
                }

                // A call runs code the analysis has not seen
                if matches!(
                    raw.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ) {
                    let dead = liveness
                        .dead_before(rva)
                        .expect("every instruction has an answer");
                    assert!(
                        dead.registers.is_empty() && dead.flags.is_empty(),
                        "nothing may be overwritten before the call at {rva}"
                    );
                }

                // Returning leaves the function, so the boundary applies
                if raw.flow_control() == FlowControl::Return {
                    let dead = liveness
                        .dead_after(rva)
                        .expect("every instruction has an answer");
                    assert!(
                        dead.registers.is_empty() && dead.flags.is_empty(),
                        "nothing is provably free after the return at {rva}"
                    );
                }

                let dead = liveness
                    .dead_after(rva)
                    .expect("every instruction has an answer");
                instructions += 1;
                if !dead.registers.is_empty() {
                    with_dead_register += 1;
                }
                if !dead.flags.is_empty() {
                    with_dead_flag += 1;
                }
                dead_registers += dead.registers.len() as usize;
                dead_flags += dead.flags.len() as usize;
            }
        }
    }

    assert!(functions > 0, "the fixture must contribute functions");
    let percent = |part: usize| (part as f64) * 100.0 / (instructions as f64);
    eprintln!(
        "liveness: {functions} functions, {instructions} instructions, at most {rounds} rounds\n  \
         insertion points with a dead register: {with_dead_register} ({:.1}%), \
         {:.2} dead registers each on average\n  \
         insertion points with a dead flag:     {with_dead_flag} ({:.1}%), \
         {:.2} dead flags each on average\n  \
         exercised here: {calls} calls, {shifts_by_immediate} shifts by an immediate, \
         {shifts_by_cl} by CL",
        percent(with_dead_register),
        (dead_registers as f64) / (instructions as f64),
        percent(with_dead_flag),
        (dead_flags as f64) / (instructions as f64),
    );

    // MSVC emitted no variable-count shift here, so the rule that such a shift
    // kills no flag has no cover in this corpus and rests on the unit test alone.
    // Printed above rather than asserted: a fixture that gains one is an
    // improvement, not a regression.
    assert_eq!(shifts_by_cl, 0, "the note above needs revisiting");

    // The measurement is the point of this test, but a run that proves nothing
    // dead anywhere would pass every assertion above while being useless
    assert!(
        with_dead_register > instructions / 10,
        "only {with_dead_register} of {instructions} points have a dead register"
    );
}

/// An independent check of the claim that actually matters.
///
/// The invariants above check the safe direction: what an instruction reads is
/// in use before it. A defect that kills *too much* — reporting a register free
/// that a later block still reads — passes every one of them, and that is the
/// direction that corrupts a binary.
///
/// So this verifies the property directly, and with a different algorithm: a
/// forward reachability search per (point, register) pair, where the analysis is
/// a backward set-based dataflow. For each register reported free after a point,
/// every path forward has to overwrite it before reading it. Reaching a call, a
/// function exit, or an unresolved edge first counts as a read, because what
/// happens beyond is unknown.
mod free_means_free {
    use super::*;
    use iced_x86::Instruction as RawInstruction;
    use vmp_ir::BasicBlock;

    /// A point in the function: the instruction about to run.
    type Position = (usize, usize);

    /// What a register is called at a point in the search.
    enum Fate {
        /// Read before any overwrite, so it was in use after all.
        Read,
        /// Overwritten without being read, which is what "free" promises.
        Killed,
        /// Neither, so the search continues past this instruction.
        Untouched,
    }

    /// Whether an instruction leaves code the search cannot follow.
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

    fn register_fate(
        raw: &RawInstruction,
        register: Register,
        factory: &mut InstructionInfoFactory,
    ) -> Fate {
        let info = factory.info(raw);
        let mut killed = false;
        for used in info.used_registers() {
            if used.register().full_register() != register {
                continue;
            }
            match used.access() {
                OpAccess::Read
                | OpAccess::CondRead
                | OpAccess::ReadWrite
                | OpAccess::ReadCondWrite => return Fate::Read,
                // Only an unconditional write of at least four bytes replaces the
                // whole value; anything narrower leaves part of it readable
                OpAccess::Write if used.register().size() >= 4 => killed = true,
                _ => {}
            }
        }
        if killed {
            Fate::Killed
        } else {
            Fate::Untouched
        }
    }

    fn flag_fate(raw: &RawInstruction, flag: u32) -> Fate {
        if raw.rflags_read() & flag != 0 {
            return Fate::Read;
        }
        // Cleared and set are definite writes; `undefined` is not a write at all,
        // so it leaves the previous value readable
        let definite = raw.rflags_written() | raw.rflags_cleared() | raw.rflags_set();
        if definite & flag != 0 && !may_not_write_flags(raw) {
            Fate::Killed
        } else {
            Fate::Untouched
        }
    }

    /// The shift and rotate family writes no flag when the count is zero.
    fn may_not_write_flags(raw: &RawInstruction) -> bool {
        use iced_x86::{Mnemonic, OpKind};
        let count = match raw.mnemonic() {
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
        if count >= raw.op_count() {
            return true;
        }
        match raw.op_kind(count) {
            OpKind::Immediate8 => raw.immediate8() & 0x1f == 0,
            _ => true,
        }
    }

    /// Every position control can be at after the instruction at `from`.
    ///
    /// `None` means control can leave the function here, which the search treats
    /// as a read of everything.
    fn successors(blocks: &[BasicBlock], from: Position) -> Option<Vec<Position>> {
        let (block_index, instruction_index) = from;
        let block = &blocks[block_index];
        if instruction_index + 1 < block.instructions.len() {
            return Some(vec![(block_index, instruction_index + 1)]);
        }
        if block.successors.is_empty() {
            return None;
        }
        let mut next = Vec::new();
        for edge in &block.successors {
            match edge.target {
                EdgeTarget::Block(id) => next.push((id.index(), 0)),
                EdgeTarget::External(_) => return None,
            }
        }
        Some(next)
    }

    /// Searches forward for a read of `subject` that no overwrite precedes.
    ///
    /// Returns the address of the offending read, or `None` when every path
    /// overwrites it first.
    fn find_a_read(
        blocks: &[BasicBlock],
        start: Position,
        factory: &mut InstructionInfoFactory,
        fate: &mut dyn FnMut(&RawInstruction, &mut InstructionInfoFactory) -> Fate,
    ) -> Option<Rva> {
        let mut seen = vec![false; blocks.iter().map(|block| block.instructions.len()).sum()];
        let offset = |position: Position| -> usize {
            blocks[..position.0]
                .iter()
                .map(|block| block.instructions.len())
                .sum::<usize>()
                + position.1
        };

        let Some(entries) = successors(blocks, start) else {
            // Control leaves the function right here
            return Some(decoded_rva(&blocks[start.0].instructions[start.1]));
        };
        let mut worklist = entries;
        while let Some(position) = worklist.pop() {
            let index = offset(position);
            if seen[index] {
                continue;
            }
            seen[index] = true;

            let instruction = &blocks[position.0].instructions[position.1];
            let raw = instruction.raw();
            if opaque(raw) {
                return Some(decoded_rva(instruction));
            }
            match fate(raw, factory) {
                Fate::Read => return Some(decoded_rva(instruction)),
                Fate::Killed => continue,
                Fate::Untouched => match successors(blocks, position) {
                    Some(next) => worklist.extend(next),
                    None => return Some(decoded_rva(instruction)),
                },
            }
        }
        None
    }

    #[test]
    fn nothing_reported_free_is_read_before_it_is_overwritten() {
        let Some(data) = read("win64-app-msvc-amd64") else {
            return;
        };
        let pe = PeFile::parse(&data).expect("fixture must parse");
        let sweep = Sweep::run(&pe, &data);

        let mut factory = InstructionInfoFactory::new();
        let mut register_claims = 0usize;
        let mut flag_claims = 0usize;

        for function in sweep.complete() {
            let liveness = analyze_liveness(function);
            let blocks = &function.blocks;

            for block_index in 0..blocks.len() {
                for instruction_index in 0..blocks[block_index].instructions.len() {
                    let position = (block_index, instruction_index);
                    let rva = decoded_rva(&blocks[block_index].instructions[instruction_index]);
                    let dead = liveness
                        .dead_after(rva)
                        .expect("every instruction has an answer");

                    for register in dead.registers.iter() {
                        register_claims += 1;
                        let offender =
                            find_a_read(blocks, position, &mut factory, &mut |raw, f| {
                                register_fate(raw, register, f)
                            });
                        assert!(
                            offender.is_none(),
                            "{rva} reports {register:?} free, but {} reads it first",
                            offender.expect("just checked")
                        );
                    }

                    for name in dead.flags.iter_names() {
                        let flag = flag_bit(name);
                        flag_claims += 1;
                        let offender =
                            find_a_read(blocks, position, &mut factory, &mut |raw, _| {
                                flag_fate(raw, flag)
                            });
                        assert!(
                            offender.is_none(),
                            "{rva} reports {name} free, but {} reads it first",
                            offender.expect("just checked")
                        );
                    }
                }
            }
        }

        eprintln!(
            "verified independently: {register_claims} register claims, {flag_claims} flag claims"
        );
        assert!(
            register_claims > 1000 && flag_claims > 1000,
            "too few claims to have verified anything: {register_claims} / {flag_claims}"
        );
    }

    fn flag_bit(name: &str) -> u32 {
        use iced_x86::RflagsBits;
        match name {
            "cf" => RflagsBits::CF,
            "pf" => RflagsBits::PF,
            "af" => RflagsBits::AF,
            "zf" => RflagsBits::ZF,
            "sf" => RflagsBits::SF,
            "of" => RflagsBits::OF,
            "df" => RflagsBits::DF,
            "if" => RflagsBits::IF,
            "ac" => RflagsBits::AC,
            "uif" => RflagsBits::UIF,
            "c0" => RflagsBits::C0,
            "c1" => RflagsBits::C1,
            "c2" => RflagsBits::C2,
            "c3" => RflagsBits::C3,
            other => panic!("unknown flag name {other}"),
        }
    }
}

/// The analysis' answers on one real function, checked by hand.
///
/// The invariant and verifier tests above prove the analysis is self-consistent
/// and sound. They cannot tell whether it is *useful*: an analysis that reports
/// almost nothing free satisfies both. These are the answers for
/// `win64-app-msvc-amd64` at `0x1184`, each with the instruction that justifies
/// it, so a change in what the model proves shows up as a diff here.
#[test]
fn liveness_answers_are_pinned_for_one_real_function() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("fixture must parse");
    let image = Image::new(&pe, &data);
    let function = decode_function(image, Rva(0x1184)).expect("function must decode");
    let liveness = analyze_liveness(&function);

    let free = |rva: u32| {
        liveness
            .dead_after(Rva(rva))
            .expect("the address must name an instruction")
    };

    // 0x1184  push rbx
    //
    // RBX is free despite being pushed: the copy is on the stack and `mov rbx,
    // rdx` at 0x118d replaces the register before anything reads it. R11, R9 and
    // R10 are free for the same reason — 0x118a, 0x1190 and 0x119b overwrite
    // them. RCX, RDX and R8 are not: 0x1190, 0x118d and 0x118a read them.
    let after_push = free(0x1184);
    for register in [Register::RBX, Register::R9, Register::R10, Register::R11] {
        assert!(
            after_push.registers.contains(register),
            "{register:?} is overwritten before it is read"
        );
    }
    for register in [Register::RCX, Register::RDX, Register::R8, Register::RSP] {
        assert!(
            !after_push.registers.contains(register),
            "{register:?} is still needed at 0x1184"
        );
    }
    // Every flag is free here, and not because nothing writes them: `sub rsp,
    // 20h` at 0x1186 definitely writes all six. Without that this would be a
    // shorter list, because the `and` at 0x1193 and the `test` at 0x1197 both
    // leave AF undefined and so cannot kill it.
    assert_eq!(
        after_push.flags.iter_names().collect::<Vec<_>>(),
        ["cf", "pf", "af", "zf", "sf", "of"]
    );

    // 0x118a  mov r11d, [r8]
    //
    // R11 now holds a value `and r11d, 0fffffff8h` at 0x1193 reads, so it stops
    // being free the moment it is written. RBX is still free — 0x118d is further
    // on but nothing reads RBX before it.
    let after_load = free(0x118a);
    assert!(!after_load.registers.contains(Register::R11));
    assert!(after_load.registers.contains(Register::RBX));

    // 0x118d  mov rbx, rdx — the two swap roles
    let after_move = free(0x118d);
    assert!(!after_move.registers.contains(Register::RBX));
    assert!(after_move.registers.contains(Register::RDX));

    // 0x1197  test byte ptr [r8], 4 — ZF is the one flag the `je` at 0x119e reads
    assert_eq!(
        free(0x1197).flags.iter_names().collect::<Vec<_>>(),
        ["cf", "pf", "af", "sf", "of"],
        "ZF is consumed by the branch that follows"
    );

    // 0x119e  je — and once consumed it is free again
    assert_eq!(
        free(0x119e).flags.iter_names().collect::<Vec<_>>(),
        ["cf", "pf", "af", "zf", "sf", "of"]
    );
}

/// Everything the epilogue recogniser has to get right, checked from outside.
///
/// [`epilogues`] scans backwards over instructions that write `RSP`. This
/// module instead matches the instruction pattern the x64 ABI prescribes, which
/// is a different algorithm reaching the same places, so a defect in one does
/// not hide in the other. The direction that matters is under-recognition:
/// every epilogue the ABI describes must lie inside a reported range, because
/// a run left unprotected is a corrupted binary, while a range that reaches too
/// far only costs insertion sites.
mod abi_pattern {
    use super::*;

    /// Index of the first instruction of the ABI epilogue ending `block`, or
    /// `None` when the block does not end in one.
    ///
    /// "It must consist of either an `add RSP,constant` or `lea
    /// RSP,constant[FPReg]`, followed by a series of zero or more 8-byte
    /// register pops and a `return` or a `jmp`."
    fn epilogue_start(block: &vmp_ir::BasicBlock) -> Option<usize> {
        let last = block.instructions.len().checked_sub(1)?;
        let terminator = block.instructions[last].raw();
        let ends_epilogue = match terminator.mnemonic() {
            Mnemonic::Ret => true,
            Mnemonic::Jmp => terminator.op0_kind() == OpKind::Memory,
            _ => false,
        };
        if !ends_epilogue {
            return None;
        }

        let mut start = last;
        while start > 0 && is_pop(block.instructions[start - 1].raw()) {
            start -= 1;
        }
        if start > 0 && adjusts_stack(block.instructions[start - 1].raw()) {
            start -= 1;
        }
        Some(start)
    }

    fn is_pop(instruction: &iced_x86::Instruction) -> bool {
        instruction.mnemonic() == Mnemonic::Pop
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().size() == 8
    }

    fn adjusts_stack(instruction: &iced_x86::Instruction) -> bool {
        if instruction.op0_kind() != OpKind::Register || instruction.op0_register() != Register::RSP
        {
            return false;
        }
        match instruction.mnemonic() {
            Mnemonic::Add => instruction.op1_kind() != OpKind::Register,
            Mnemonic::Lea => true,
            _ => false,
        }
    }

    #[test]
    fn every_abi_epilogue_lies_inside_a_reported_range() {
        let Some(data) = read("win64-app-msvc-amd64") else {
            return;
        };
        let pe = PeFile::parse(&data).expect("fixture must parse");
        let sweep = Sweep::run(&pe, &data);

        let mut matched = 0usize;
        let mut instructions = 0usize;
        let mut forbidden = 0usize;

        for function in sweep.complete() {
            let reported = epilogues(function);
            for range in &reported {
                assert!(
                    range.begin < range.end,
                    "{range:?} of {} is empty or reversed",
                    function.entry
                );
            }
            // Ranges end at block boundaries and blocks do not overlap, so
            // neither do these
            let mut sorted = reported.clone();
            sorted.sort();
            for pair in sorted.windows(2) {
                // Strictly less: two ranges that merely touch would leave the
                // address between them interior to neither, which is the one
                // spot inside a split epilogue an insertion could still reach
                assert!(
                    pair[0].end < pair[1].begin,
                    "{:?} and {:?} of {} were not joined",
                    pair[0],
                    pair[1],
                    function.entry
                );
            }

            for block in &function.blocks {
                instructions += block.instructions.len();
                let Some(start) = epilogue_start(block) else {
                    continue;
                };
                let last = block.instructions.len() - 1;
                if start == last {
                    // A bare terminator: nothing has moved the stack, so there
                    // is nothing to protect and nothing to find
                    continue;
                }
                matched += 1;

                let begin = decoded_rva(&block.instructions[start]);
                let covering = reported
                    .iter()
                    .find(|range| range.begin <= begin && range.end >= block.end)
                    .unwrap_or_else(|| {
                        panic!(
                            "the ABI epilogue at {begin} of {} is not covered by {reported:?}",
                            function.entry
                        )
                    });
                assert!(
                    covering.begin <= begin,
                    "{covering:?} starts after the ABI epilogue at {begin}"
                );
            }

            for range in &reported {
                let covered = function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .filter(|instruction| {
                        let rva = decoded_rva(instruction);
                        rva >= range.begin && rva < range.end
                    })
                    .count();
                forbidden += covered - 1;
            }
        }

        println!("instructions          {instructions}");
        println!("ABI epilogues matched {matched}");
        println!("insertion points lost {forbidden}");

        assert!(
            matched > 50,
            "the fixture must exercise this: only {matched} epilogues matched"
        );
        assert_eq!(
            forbidden, 223,
            "the cost of freezing epilogues moved; the plan's budget is stated in terms of it"
        );
    }
}
