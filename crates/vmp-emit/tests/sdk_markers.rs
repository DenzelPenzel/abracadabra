//! End-to-end direct SDK marker mutation on the required x64 corpus.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iced_x86::{
    Code, Encoder, FlowControl, Instruction as RawInstruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register, RflagsBits,
};
use vmp_emit::sdk::protect_direct_sdk_mutation;
use vmp_emit::{EmitError, Options};
use vmp_ir::{BasicBlock, BlockId, CompileStage, EdgeTarget, Function, Terminator};
use vmp_mutation::{Options as MutationOptions, Seed};
use vmp_pe::{PeFile, PeImage};
use vmp_types::{Architecture, Rva};
use vmp_x86::sdk_markers::SdkApi;

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

fn legal_junk_register(register: Register, width: usize) -> bool {
    let full = register.full_register();
    register.size() == width
        && full != Register::RSP
        && register_slot(full).is_some_and(|slot| slot < 16)
}

fn junk_form(raw: &RawInstruction) -> Option<&'static str> {
    let canonical = match raw.code() {
        Code::Clc if raw.op_count() == 0 => RawInstruction::with(Code::Clc),
        Code::Stc if raw.op_count() == 0 => RawInstruction::with(Code::Stc),
        Code::Cmc if raw.op_count() == 0 => RawInstruction::with(Code::Cmc),
        Code::Mov_r32_imm32
            if raw.op_count() == 2
                && raw.op0_kind() == OpKind::Register
                && raw.op1_kind() == OpKind::Immediate32
                && legal_junk_register(raw.op0_register(), 4) =>
        {
            RawInstruction::with2(Code::Mov_r32_imm32, raw.op0_register(), raw.immediate32())
                .ok()?
        }
        Code::Mov_r64_imm64
            if raw.op_count() == 2
                && raw.op0_kind() == OpKind::Register
                && raw.op1_kind() == OpKind::Immediate64
                && legal_junk_register(raw.op0_register(), 8) =>
        {
            RawInstruction::with2(Code::Mov_r64_imm64, raw.op0_register(), raw.immediate64())
                .ok()?
        }
        Code::Not_rm32
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(raw.op0_register(), 4) =>
        {
            RawInstruction::with1(Code::Not_rm32, raw.op0_register()).ok()?
        }
        Code::Not_rm64
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(raw.op0_register(), 8) =>
        {
            RawInstruction::with1(Code::Not_rm64, raw.op0_register()).ok()?
        }
        Code::Bswap_r32
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(raw.op0_register(), 4) =>
        {
            RawInstruction::with1(Code::Bswap_r32, raw.op0_register()).ok()?
        }
        Code::Bswap_r64
            if raw.op_count() == 1
                && raw.op0_kind() == OpKind::Register
                && legal_junk_register(raw.op0_register(), 8) =>
        {
            RawInstruction::with1(Code::Bswap_r64, raw.op0_register()).ok()?
        }
        _ => return None,
    };
    if canonical != *raw {
        return None;
    }
    let mut encoder = Encoder::new(64);
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

fn anchor_shape_matches(mut original: RawInstruction, mut relocated: RawInstruction) -> bool {
    if matches!(
        original.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        original.set_near_branch64(0);
        relocated.set_near_branch64(0);
    }
    original.as_near_branch();
    relocated.as_near_branch();
    original == relocated
}

fn anchor_semantics_match(
    mut original: RawInstruction,
    mut relocated: RawInstruction,
    moved: &BTreeMap<u64, u64>,
) -> bool {
    if matches!(
        original.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        let target = original.near_branch_target();
        original.set_near_branch64(moved.get(&target).copied().unwrap_or(target));
    }
    original.as_near_branch();
    relocated.as_near_branch();
    original == relocated
}

fn junk_is_safe(raw: &RawInstruction, dead: DeadState) -> bool {
    if matches!(raw.code(), Code::Clc | Code::Stc | Code::Cmc) {
        return dead.flags & RflagsBits::CF != 0;
    }
    register_slot(raw.op0_register()).is_some_and(|slot| dead.registers & (1 << slot) != 0)
}

#[derive(Clone, Debug)]
struct JunkObservation {
    form: &'static str,
    preceding_original: u64,
}

#[derive(Clone, Debug, Default)]
struct Alignment {
    anchors: Vec<(RawInstruction, RawInstruction)>,
    junk: Vec<JunkObservation>,
    moved: BTreeMap<u64, u64>,
}

#[allow(clippy::too_many_arguments)]
fn enumerate_junk_alignments(
    before: &[RawInstruction],
    after: &[RawInstruction],
    dead_after: &BTreeMap<u64, DeadState>,
    i: usize,
    j: usize,
    candidate: Alignment,
    solutions: &mut Vec<Alignment>,
) {
    if solutions.len() == 2 {
        return;
    }
    if i == before.len() && j == after.len() {
        let moved = candidate
            .anchors
            .iter()
            .map(|(original, relocated)| (original.ip(), relocated.ip()))
            .collect();
        if candidate
            .anchors
            .iter()
            .all(|(original, relocated)| anchor_semantics_match(*original, *relocated, &moved))
        {
            let mut candidate = candidate;
            candidate.moved = moved;
            solutions.push(candidate);
        }
        return;
    }
    if i < before.len() && j < after.len() && anchor_shape_matches(before[i], after[j]) {
        let mut next = candidate.clone();
        next.anchors.push((before[i], after[j]));
        enumerate_junk_alignments(before, after, dead_after, i + 1, j + 1, next, solutions);
    }
    if i > 0 && j < after.len() {
        if let Some(form) = junk_form(&after[j]) {
            let preceding = before[i - 1].ip();
            if dead_after
                .get(&preceding)
                .is_some_and(|dead| junk_is_safe(&after[j], *dead))
            {
                let mut next = candidate;
                next.junk.push(JunkObservation {
                    form,
                    preceding_original: preceding,
                });
                enumerate_junk_alignments(before, after, dead_after, i, j + 1, next, solutions);
            }
        }
    }
}

fn unique_junk_alignment(
    before: &[RawInstruction],
    after: &[RawInstruction],
    dead_after: &BTreeMap<u64, DeadState>,
) -> Result<Alignment, &'static str> {
    let mut solutions = Vec::with_capacity(2);
    enumerate_junk_alignments(
        before,
        after,
        dead_after,
        0,
        0,
        Alignment::default(),
        &mut solutions,
    );
    match solutions.len() {
        0 => Err("no complete alignment"),
        1 => Ok(solutions.pop().expect("one solution")),
        _ => Err("ambiguous alignment"),
    }
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

fn all_live() -> LiveState {
    LiveState {
        registers: u16::MAX,
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
) -> LiveState {
    if opaque(raw) {
        return all_live();
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
    live.flags = ((live.flags & !written) | raw.rflags_read()) & TRACKED_FLAGS;
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
    assert_eq!(function.architecture, Architecture::X64);
    let boundary = all_live();
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
                live = transfer_live(live, instruction.raw(), &mut factory);
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
                        registers: !live.registers,
                        flags: !live.flags & TRACKED_FLAGS,
                    },
                );
            }
            live = transfer_live(live, instruction.raw(), &mut factory);
        }
    }
    result
}

fn is_sdk_marker_call(image: vmp_x86::Image<'_>, instruction: &vmp_ir::Instruction) -> bool {
    if instruction.raw().flow_control() != iced_x86::FlowControl::IndirectCall {
        return false;
    }
    let Ok(target) = u32::try_from(instruction.raw().ip_rel_memory_address()) else {
        return false;
    };
    image
        .import_thunk(Rva(target))
        .is_some_and(|(_, name)| match name {
            vmp_x86::ImportName::Name(name) => {
                name.starts_with("VMProtectBegin") || name == "VMProtectEnd"
            }
            vmp_x86::ImportName::Ordinal(_) => false,
        })
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("vmp-pe")
        .join("test-corpus")
        .join("win64-app-msvc-amd64")
}

fn required_fixture() -> Vec<u8> {
    let path = fixture_path();
    let mut data = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()));
    let pe = PeFile::parse(&data).expect("required fixture parses before adaptation");
    let unwind_rva = pe
        .exception_table
        .as_ref()
        .expect("fixture has exception data")
        .functions()
        .find(|function| function.begin == Rva(0x1000))
        .expect("fixture marker function has a runtime entry")
        .unwind_info;
    let offset = pe
        .rva_to_offset(unwind_rva)
        .expect("unwind info is file-backed")
        .get() as usize;
    // The committed C++ corpus function has a language-specific handler. Stage
    // 4 deliberately refuses to relocate those functions, so this structural
    // fixture clears only the UNW_FLAG_* bits. The real Windows gate builds a
    // handlerless SDK probe and exercises the resulting image on the loader/CPU.
    data[offset] &= 0x07;
    data
}

fn register_begin_fixture() -> Vec<u8> {
    let mut data = required_fixture();
    let pe = PeFile::parse(&data).expect("required fixture parses before adaptation");
    let thunk = pe
        .imports
        .as_ref()
        .expect("fixture has imports")
        .descriptors
        .iter()
        .find(|library| library.name == "VMProtectSDK64.dll")
        .expect("fixture imports the x64 SDK")
        .functions
        .iter()
        .find_map(|function| match &function.target {
            vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                Some(function.thunk_rva)
            }
            _ => None,
        })
        .expect("fixture imports the Begin marker");
    // Replace `mov rsi,r8; mov ebx,edx; call [IAT]` (11 bytes) with an
    // equal-extent register marker and restore `mov ebx,edx` after the call.
    let load = Rva(0x102e);
    let call = Rva(0x1035);
    let displacement = i64::from(thunk.get()) - i64::from(call.get());
    let displacement = i32::try_from(displacement)
        .expect("fixture RIP displacement fits")
        .to_le_bytes();
    let offset = pe
        .rva_to_offset(load)
        .expect("Begin site is file-backed")
        .get() as usize;
    data[offset..offset + 11].copy_from_slice(&[
        0x48,
        0x8b,
        0x05,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
        0xff,
        0xd0,
        0x89,
        0xd3,
    ]);
    let end_thunk = pe
        .imports
        .as_ref()
        .expect("fixture has imports")
        .descriptors
        .iter()
        .flat_map(|library| &library.functions)
        .find_map(|function| match &function.target {
            vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectEnd" => {
                Some(function.thunk_rva)
            }
            _ => None,
        })
        .expect("fixture imports the End marker");
    let end_offset = pe
        .rva_to_offset(Rva(0x103f))
        .expect("safe End site is file-backed")
        .get() as usize;
    let end_displacement = i32::try_from(i64::from(end_thunk.get()) - i64::from(0x1045))
        .expect("End displacement fits")
        .to_le_bytes();
    data[end_offset..end_offset + 6].copy_from_slice(&[
        0xff,
        0x15,
        end_displacement[0],
        end_displacement[1],
        end_displacement[2],
        end_displacement[3],
    ]);
    let tail_offset = pe
        .rva_to_offset(Rva(0x1045))
        .expect("safe continuation is file-backed")
        .get() as usize;
    data[tail_offset..tail_offset + 5].copy_from_slice(&[0xe9, 0x11, 0, 0, 0]);
    data
}

fn non_adjacent_register_begin_fixture() -> Vec<u8> {
    let mut data = required_fixture();
    let pe = PeFile::parse(&data).expect("required fixture parses before adaptation");
    let thunk = pe
        .imports
        .as_ref()
        .expect("fixture has imports")
        .descriptors
        .iter()
        .find(|library| library.name == "VMProtectSDK64.dll")
        .expect("fixture imports the x64 SDK")
        .functions
        .iter()
        .find_map(|function| match &function.target {
            vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                Some(function.thunk_rva)
            }
            _ => None,
        })
        .expect("fixture imports the Begin marker");
    let load = Rva(0x1027);
    let load_next = load.checked_add(7).expect("fixture load end fits RVA");
    let displacement = i32::try_from(i64::from(thunk.get()) - i64::from(load_next.get()))
        .expect("fixture RIP displacement fits")
        .to_le_bytes();
    let offset = pe
        .rva_to_offset(load)
        .expect("Begin site is file-backed")
        .get() as usize;
    data[offset..offset + 18].copy_from_slice(&[
        0x48,
        0x8b,
        0x05,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
        0x90,
        0x90,
        0x90,
        0x90,
        0x90,
        0xff,
        0xd0,
        0x90,
        0x90,
        0x90,
        0x90,
    ]);
    data
}

fn static_marker_fixture() -> Vec<u8> {
    let mut data = required_fixture();
    let pe = PeFile::parse(&data).expect("required fixture parses before adaptation");
    let begin_offset = pe
        .rva_to_offset(Rva(0x1027))
        .expect("static Begin site is file-backed")
        .get() as usize;
    let end_offset = pe
        .rva_to_offset(Rva(0x103f))
        .expect("static End site is file-backed")
        .get() as usize;
    data[begin_offset..begin_offset + 18].copy_from_slice(b"\xeb\x10VMProtect begin\x02");
    data[end_offset..end_offset + 16].copy_from_slice(b"\xeb\x0eVMProtect end\0");
    data
}

fn static_marker_fixture_with_unreached_end() -> Vec<u8> {
    let mut data = static_marker_fixture();
    let pe = PeFile::parse(&data).expect("static fixture parses");
    let offset = pe
        .rva_to_offset(Rva(0x1170))
        .expect("unreached static End site is file-backed")
        .get() as usize;
    data[offset..offset + 16].copy_from_slice(b"\xeb\x0eVMProtect end\0");
    data
}

fn fixture_with_runtime_free_sdk_api(name: &str) -> Vec<u8> {
    let mut data = static_marker_fixture();
    let pe = PeFile::parse(&data).expect("static API fixture parses");
    let thunk = pe
        .imports
        .as_ref()
        .expect("fixture has imports")
        .descriptors
        .iter()
        .flat_map(|library| &library.functions)
        .find_map(|function| match &function.target {
            vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectDecryptStringA" => {
                Some(function.thunk_rva)
            }
            _ => None,
        })
        .expect("fixture imports the DecryptStringA API");
    let call_offset = pe
        .rva_to_offset(Rva(0x1039))
        .expect("runtime-free call site is file-backed")
        .get() as usize;
    let displacement = i32::try_from(i64::from(thunk.get()) - i64::from(0x103f))
        .expect("runtime-free IAT displacement fits")
        .to_le_bytes();
    data[call_offset..call_offset + 6].copy_from_slice(&[
        0xff,
        0x15,
        displacement[0],
        displacement[1],
        displacement[2],
        displacement[3],
    ]);
    let mutation_offset = pe
        .rva_to_offset(Rva(0x103f))
        .expect("runtime-free mutation site is file-backed")
        .get() as usize;
    data[mutation_offset..mutation_offset + 6].copy_from_slice(&[0x81, 0xeb, 0x10, 0x01, 0, 0]);
    let end_thunk = pe
        .imports
        .as_ref()
        .expect("fixture has imports")
        .descriptors
        .iter()
        .flat_map(|library| &library.functions)
        .find_map(|function| match &function.target {
            vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectEnd" => {
                Some(function.thunk_rva)
            }
            _ => None,
        })
        .expect("fixture imports the End marker");
    let end_displacement = i32::try_from(i64::from(end_thunk.get()) - i64::from(0x104b))
        .expect("End displacement fits")
        .to_le_bytes();
    let end_offset = pe
        .rva_to_offset(Rva(0x1045))
        .expect("runtime-free End is file-backed")
        .get() as usize;
    data[end_offset..end_offset + 6].copy_from_slice(&[
        0xff,
        0x15,
        end_displacement[0],
        end_displacement[1],
        end_displacement[2],
        end_displacement[3],
    ]);
    let tail_offset = pe
        .rva_to_offset(Rva(0x104b))
        .expect("runtime-free continuation is file-backed")
        .get() as usize;
    data[tail_offset..tail_offset + 5].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]);
    let original = b"VMProtectDecryptStringA\0";
    let offset = data
        .windows(original.len())
        .position(|window| window == original)
        .expect("fixture import name is present exactly as bytes");
    assert!(name.len() < original.len());
    data[offset..offset + original.len()].fill(0);
    data[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    data
}

#[test]
fn emits_exact_cpp_fallback_bytes_for_each_runtime_free_sdk_api() {
    let cases: &[(&str, SdkApi, &[u8])] = &[
        (
            "VMProtectIsProtected",
            SdkApi::IsProtected,
            &[0xb8, 1, 0, 0, 0, 0xc3],
        ),
        (
            "VMProtectDecryptStringA",
            SdkApi::DecryptStringA,
            &[0x48, 0x89, 0xc8, 0xc3],
        ),
        (
            "VMProtectDecryptStringW",
            SdkApi::DecryptStringW,
            &[0x48, 0x89, 0xc8, 0xc3],
        ),
        (
            "VMProtectFreeString",
            SdkApi::FreeString,
            &[0x31, 0xc0, 0xc3],
        ),
    ];
    for (name, api, expected) in cases {
        let input = fixture_with_runtime_free_sdk_api(name);
        let (output, outcome) = protect_direct_sdk_mutation(
            PeImage::from_bytes(input).expect("API fixture parses"),
            &Options {
                seed: Seed::new(1),
                ..Options::default()
            },
        )
        .unwrap_or_else(|error| panic!("{name} protection failed: {error}"));
        let stub = outcome[0]
            .sdk_stubs
            .iter()
            .find(|stub| stub.api == *api)
            .unwrap_or_else(|| panic!("{name} fallback stub was not emitted"));
        let pe = PeFile::parse(output.bytes()).expect("protected API fixture reparses");
        assert_eq!(
            pe.mapped_range(
                output.bytes(),
                stub.rva,
                u32::try_from(expected.len()).expect("stub length fits PE RVA width"),
            )
            .expect("fallback stub is mapped"),
            *expected,
            "{name} must match the exact C++ fallback semantics"
        );
    }
}

#[test]
fn protects_static_cpp_marker_signatures_through_the_sdk_path() {
    let input = static_marker_fixture();
    let image = PeImage::from_bytes(input).expect("static fixture parses");
    let options = Options {
        seed: Seed::new(1),
        mutation: MutationOptions {
            rewrites: true,
            junk: true,
        },
        ..Options::default()
    };
    let (output, outcome) = protect_direct_sdk_mutation(image, &options)
        .expect("static SDK marker protection succeeds");
    assert_eq!(outcome.len(), 1);
    assert_eq!(outcome[0].begin, Rva(0x1027));
    assert_eq!(outcome[0].reached_ends, vec![Rva(0x103f)]);
    assert!(!outcome[0].report.is_noop());
    let pe = PeFile::parse(output.bytes()).expect("protected static output reparses");
    let begin_patch = pe
        .mapped_range(output.bytes(), Rva(0x1027), 18)
        .expect("static Begin span remains mapped");
    assert_eq!(begin_patch[0], 0xe9);
    assert!(begin_patch[5..].iter().all(|byte| *byte == 0x90));
    let original_end = pe
        .mapped_range(output.bytes(), Rva(0x103f), 16)
        .expect("static End span remains mapped");
    assert_eq!(&original_end[..2], &[0xeb, 0x0e]);
    assert!(
        original_end[2..].iter().all(|byte| *byte == 0),
        "the C++ path clears the original static End payload"
    );
    let bytes = pe
        .mapped_range(output.bytes(), outcome[0].relocated, outcome[0].length)
        .expect("relocated static function is mapped");
    assert!(!bytes.windows(15).any(|window| window == b"VMProtect begin"));
    assert!(!bytes.windows(13).any(|window| window == b"VMProtect end"));
}

#[test]
fn clears_a_discovered_static_end_that_the_selected_begin_does_not_reach() {
    let input = static_marker_fixture_with_unreached_end();
    let (output, outcome) = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("static fixture parses"),
        &Options {
            seed: Seed::new(1),
            ..Options::default()
        },
    )
    .expect("safe static region protects");
    assert_eq!(outcome[0].reached_ends, vec![Rva(0x103f)]);
    let pe = PeFile::parse(output.bytes()).expect("output reparses");
    let original_end = pe
        .mapped_range(output.bytes(), Rva(0x1170), 16)
        .expect("unreached End remains mapped");
    assert_eq!(&original_end[..2], &[0xeb, 0x0e]);
    assert!(original_end[2..].iter().all(|byte| *byte == 0));
}

#[test]
fn adjacent_register_marker_redirects_from_its_load_to_the_region_slice() {
    let input = register_begin_fixture();
    let original = PeFile::parse(&input).expect("adapted fixture parses");
    let original_entry = original
        .mapped_range(&input, Rva(0x1000), 5)
        .expect("covering entry is mapped")
        .to_vec();
    let markers =
        vmp_x86::sdk_markers::discover_direct_api_markers(vmp_x86::Image::new(&original, &input))
            .expect("register marker discovery succeeds");
    assert!(markers.iter().any(|marker| matches!(
        marker,
        vmp_x86::sdk_markers::ApiMarker::Begin {
            load_rva: Some(Rva(0x102e)),
            call_rva: Rva(0x1035),
            ..
        }
    )));

    let options = Options {
        seed: Seed::new(1),
        mutation: MutationOptions {
            rewrites: false,
            junk: true,
        },
        ..Options::default()
    };
    let (output, outcome) = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("adapted fixture loads"),
        &options,
    )
    .expect("register SDK marker protection succeeds");
    assert_eq!(outcome.len(), 1);
    assert_eq!(outcome[0].begin, Rva(0x1035));

    let parsed = PeFile::parse(output.bytes()).expect("protected output reparses");
    assert_eq!(
        parsed
            .mapped_range(output.bytes(), Rva(0x1000), 5)
            .expect("covering entry stays mapped"),
        original_entry
    );
    let patch = parsed
        .mapped_range(output.bytes(), Rva(0x102e), 9)
        .expect("register load patch is mapped");
    assert_eq!(patch[0], 0xe9);
    assert!(patch[5..].iter().all(|byte| *byte == 0x90));
    let displacement = i32::from_le_bytes(patch[1..5].try_into().expect("rel32 is four bytes"));
    assert_eq!(
        i64::from(0x1033) + i64::from(displacement),
        i64::from(outcome[0].relocated.get())
    );
    let image = vmp_x86::Image::new(&parsed, output.bytes());
    let relocated = vmp_x86::decode_function(image, outcome[0].relocated)
        .expect("relocated register-marker function decodes");
    let instructions: Vec<_> = relocated.instructions().collect();
    let restored_mov = instructions
        .iter()
        .position(|instruction| {
            let raw = instruction.raw();
            raw.code() == Code::Mov_rm32_r32
                && raw.op0_kind() == OpKind::Register
                && raw.op0_register() == Register::EBX
                && raw.op1_kind() == OpKind::Register
                && raw.op1_register() == Register::EDX
        })
        .expect("the instruction after the register marker remains present");
    assert_eq!(restored_mov, 0, "slice starts after the register call");
    assert!(relocated
        .instructions()
        .all(|instruction| !is_sdk_marker_call(image, instruction)));
    assert!(
        parsed
            .mapped_range(output.bytes(), Rva(0x103f), 6)
            .expect("original direct End remains mapped")
            .iter()
            .all(|byte| *byte == 0x90),
        "the original API End call must be neutralized"
    );
}

#[test]
fn rejects_a_non_adjacent_register_begin_load() {
    let input = non_adjacent_register_begin_fixture();
    let error = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("non-adjacent register fixture parses"),
        &Options::default(),
    )
    .expect_err("skipping instructions between the load and call must fail closed");
    assert!(
        matches!(error, EmitError::SdkMarker(ref reason) if reason == "SDK register marker load at 0x00001027 and call at 0x00001033 are not one straight-line span"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_language_specific_unwind_handlers() {
    let input = std::fs::read(fixture_path()).expect("required C++ corpus fixture is readable");
    let error = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("unmodified corpus fixture parses"),
        &Options::default(),
    )
    .expect_err("handler-bearing regions require language metadata remapping");
    assert!(
        matches!(error, EmitError::SdkMarker(ref reason) if reason == "covering function has language-specific unwind handlers"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_a_cpp_sdk_region_with_post_end_reentry() {
    let input = required_fixture();
    let original = PeFile::parse(&input).expect("fixture parses");
    let original_entry = original
        .mapped_range(&input, Rva(0x1000), 5)
        .expect("original entry is mapped")
        .to_vec();
    let original_runtime: Vec<_> = original
        .exception_table
        .as_ref()
        .expect("fixture has exception table")
        .functions()
        .collect();
    let original_function =
        vmp_x86::decode_function(vmp_x86::Image::new(&original, &input), Rva(0x1000))
            .expect("original marker function decodes");
    let region = vmp_x86::marker_region::recover_marker_region(
        &original_function,
        Rva(0x1033),
        &[Rva(0x10f9), Rva(0x1143)],
    )
    .expect("fixture marker region is recoverable");
    let mut neutralized = original_function.clone();
    let reached_end_sites: Vec<_> = region
        .reached_ends
        .iter()
        .copied()
        .map(|rva| (rva, None))
        .collect();
    vmp_x86::marker_region::neutralize_marker_calls(
        &mut neutralized,
        Rva(0x1033),
        None,
        &reached_end_sites,
    )
    .expect("fixture marker calls neutralize");

    let image = PeImage::from_bytes(input.clone()).expect("fixture parses");
    let options = Options {
        seed: Seed::new(1),
        mutation: MutationOptions {
            rewrites: false,
            junk: true,
        },
        ..Options::default()
    };
    let (output, outcome) = match protect_direct_sdk_mutation(image, &options) {
        Err(EmitError::SdkMarker(reason))
            if reason.contains("without passing its Begin marker") =>
        {
            return;
        }
        Err(error) => panic!("unexpected SDK rejection: {error}"),
        Ok(result) => result,
    };
    assert_eq!(outcome.len(), 1);
    assert_eq!(outcome[0].begin, Rva(0x1033));
    assert_eq!(outcome[0].function, Rva(0x1000));
    assert_eq!(outcome[0].reached_ends, vec![Rva(0x10f9), Rva(0x1143)]);
    assert!(
        !outcome[0].report.is_noop(),
        "the selected SDK region must be physically mutated"
    );
    assert_ne!(outcome[0].relocated, outcome[0].function);
    assert!(outcome[0].length > 0);

    let parsed = PeFile::parse(output.bytes()).expect("output reparses");
    assert_eq!(
        parsed
            .mapped_range(output.bytes(), Rva(0x1000), 5)
            .expect("output entry is mapped"),
        original_entry,
        "region-only excision must not redirect the covering function entry"
    );
    let begin_patch = parsed
        .mapped_range(output.bytes(), Rva(0x1033), 6)
        .expect("Begin patch is mapped");
    assert_eq!(begin_patch[0], 0xe9, "Begin itself redirects to the slice");
    assert_eq!(
        begin_patch[5], 0x90,
        "the whole Begin call span is consumed"
    );
    let begin_displacement = i32::from_le_bytes(
        begin_patch[1..5]
            .try_into()
            .expect("rel32 occupies four bytes"),
    );
    assert_eq!(
        i64::from(0x1038) + i64::from(begin_displacement),
        i64::from(outcome[0].relocated.get())
    );
    let runtime: Vec<_> = parsed
        .exception_table
        .as_ref()
        .expect("exception table remains present")
        .functions()
        .collect();
    assert!(runtime.starts_with(&original_runtime));
    assert!(runtime.iter().any(|entry| {
        entry.begin == outcome[0].relocated
            && entry.end
                == outcome[0]
                    .relocated
                    .checked_add(outcome[0].length)
                    .expect("range fits")
    }));
    assert_eq!(
        parsed.optional.checksum,
        parsed
            .compute_checksum(output.bytes())
            .expect("checksum computes")
    );
    let image = vmp_x86::Image::new(&parsed, output.bytes());
    let relocated = vmp_x86::decode_function(image, outcome[0].relocated)
        .expect("relocated SDK function decodes");
    assert!(relocated.is_complete());
    let continuation_targets: Vec<_> = relocated
        .instructions()
        .filter_map(|instruction| {
            matches!(
                instruction.raw().flow_control(),
                FlowControl::UnconditionalBranch
            )
            .then(|| u32::try_from(instruction.raw().near_branch_target()).ok())
            .flatten()
            .map(Rva)
        })
        .filter(|target| matches!(target.get(), 0x10ff | 0x1149))
        .collect();
    assert_eq!(continuation_targets, vec![Rva(0x10ff), Rva(0x1149)]);
    let slice_runtime = parsed
        .exception_table
        .as_ref()
        .expect("slice has exception metadata")
        .functions()
        .find(|entry| entry.begin == outcome[0].relocated)
        .expect("slice runtime entry exists");
    let slice_unwind =
        vmp_pe::UnwindInfo::parse(&parsed, output.bytes(), slice_runtime.unwind_info)
            .expect("slice chained unwind parses");
    assert_eq!(
        slice_unwind.chained.map(|chain| (chain.begin, chain.end)),
        Some((Rva(0x1000), Rva(0x1150)))
    );
    assert_eq!(outcome[0].sdk_stubs.len(), 1);
    let decrypt_stub = &outcome[0].sdk_stubs[0];
    assert_eq!(decrypt_stub.api, SdkApi::DecryptStringA);
    assert_eq!(
        &image.bytes_from(decrypt_stub.rva).expect("stub is mapped")[..4],
        &[0x48, 0x89, 0xc8, 0xc3],
        "MS x64 decrypt fallback is exactly mov rax,rcx; ret"
    );
    assert_eq!(
        relocated
            .instructions()
            .filter(|instruction| {
                instruction.raw().flow_control() == FlowControl::Call
                    && instruction.raw().near_branch_target() == u64::from(decrypt_stub.rva.get())
            })
            .count(),
        2,
        "both physical decrypt calls target the shared local stub"
    );
    let reported_forms: BTreeMap<&str, usize> = outcome[0]
        .report
        .applied
        .iter()
        .filter(|(name, _)| name.starts_with("junk-"))
        .map(|(name, count)| (*name, *count))
        .collect();
    let reported_junk: usize = reported_forms.values().sum();
    assert!(reported_junk > 0, "the fixed seed must insert real junk");
    let sdk_calls = vmp_x86::sdk_markers::discover_sdk_api_calls(
        vmp_x86::Image::new(&original, &input),
        &original_function,
    )
    .expect("runtime-free SDK calls are discoverable before relocation");
    let mut originals: Vec<(Rva, RawInstruction)> = original_function
        .instructions()
        .filter_map(|instruction| {
            let rva = instruction.rva()?;
            region
                .instructions
                .binary_search(&rva)
                .is_ok()
                .then_some((rva, *instruction.raw()))
        })
        .collect();
    let markers =
        vmp_x86::sdk_markers::discover_direct_api_markers(vmp_x86::Image::new(&original, &input))
            .expect("fixture SDK markers scan");
    for reached in &region.reached_ends {
        let continuation = markers
            .iter()
            .find_map(|marker| match marker {
                vmp_x86::sdk_markers::ApiMarker::End {
                    call_rva, next_rva, ..
                } if call_rva == reached => Some(*next_rva),
                _ => None,
            })
            .expect("each reached End has its own continuation");
        let mut bridge =
            RawInstruction::with_branch(Code::Jmp_rel32_64, u64::from(continuation.get()))
                .expect("an End bridge is constructible");
        bridge.set_ip(u64::from(reached.get()));
        originals.push((*reached, bridge));
    }
    originals.sort_by_key(|(rva, _)| *rva);
    let mut before = originals.iter().map(|(_, raw)| *raw).collect::<Vec<_>>();
    for call in sdk_calls {
        let index = originals
            .iter()
            .position(|(rva, _)| *rva == call.call_rva)
            .expect("discovered SDK call belongs to the selected region");
        let target = outcome[0]
            .sdk_stubs
            .iter()
            .find(|stub| stub.api == call.api)
            .expect("each discovered SDK API has one emitted stub")
            .rva;
        let mut direct = RawInstruction::with_branch(Code::Call_rel32_64, u64::from(target.get()))
            .expect("a direct x64 call is constructible");
        direct.set_ip(u64::from(call.call_rva.get()));
        before[index] = direct;
    }
    let after = relocated
        .instructions()
        .map(|instruction| *instruction.raw())
        .collect::<Vec<_>>();
    let sdk_padding: Vec<usize> = after
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            (pair[0].flow_control() == FlowControl::Call
                && outcome[0]
                    .sdk_stubs
                    .iter()
                    .any(|stub| pair[0].near_branch_target() == u64::from(stub.rva.get()))
                && pair[1].code() == Code::Nopd)
                .then_some(index + 1)
        })
        .collect();
    let after_for_mutation: Vec<_> = after
        .iter()
        .enumerate()
        .filter_map(|(index, raw)| (!sdk_padding.contains(&index)).then_some(*raw))
        .collect();
    let physical_increase = after_for_mutation
        .len()
        .checked_sub(before.len())
        .expect("junk-only relocation cannot lose originals");
    assert_eq!(
        physical_increase, reported_junk,
        "physical instruction increase must exactly equal the junk report"
    );
    let alignment = unique_junk_alignment(
        &before,
        &after_for_mutation,
        &independent_dead_after(&neutralized),
    )
    .unwrap_or_else(|reason| panic!("SDK copy has {reason}"));
    assert_eq!(
        alignment.moved.len(),
        before.len(),
        "relocation lost original anchors"
    );
    let mut observed_forms = BTreeMap::new();
    for junk in &alignment.junk {
        let insertion_after = Rva(u32::try_from(junk.preceding_original)
            .expect("original SDK instruction RVA fits in u32"));
        assert!(
            region.instructions.binary_search(&insertion_after).is_ok(),
            "reported junk was physically emitted outside the selected SDK region after {insertion_after}"
        );
        *observed_forms.entry(junk.form).or_default() += 1;
    }
    assert_eq!(alignment.junk.len(), reported_junk);
    assert_eq!(
        observed_forms, reported_forms,
        "each physical junk form must exactly match its report count"
    );
    assert!(
        relocated
            .instructions()
            .all(|instruction| !is_sdk_marker_call(image, instruction)),
        "the relocated execution path must not call SDK Begin/End imports"
    );
    assert_ne!(
        output.bytes(),
        input.as_slice(),
        "SDK calls must be removed"
    );
}

#[test]
fn rejects_a_marker_call_that_would_shorten_the_unwind_prologue() {
    let mut input = required_fixture();
    let pe = PeFile::parse(&input).expect("adapted fixture parses");
    let unwind_rva = pe
        .exception_table
        .as_ref()
        .expect("fixture has exception data")
        .functions()
        .find(|function| function.begin == Rva(0x1000))
        .expect("fixture marker function has a runtime entry")
        .unwind_info;
    let offset = pe
        .rva_to_offset(unwind_rva)
        .expect("unwind info is file-backed")
        .get() as usize;
    // Begin occupies 0x1033..0x1039, so it becomes the final prologue
    // instruction. Replacing it with a one-byte NOP must invalidate reuse of a
    // SizeOfProlog that still declares the original six-byte extent.
    input[offset + 1] = 0x39;

    let error = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("fixture parses"),
        &Options {
            seed: Seed::new(1),
            ..Options::default()
        },
    )
    .expect_err("shortened prologue must fail closed");
    assert!(
        matches!(error, EmitError::SdkMarker(ref reason) if reason == "SDK Begin marker intersects the covering prologue"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_an_original_prologue_boundary_inside_a_marker_call() {
    let mut input = required_fixture();
    let pe = PeFile::parse(&input).expect("adapted fixture parses");
    let unwind_rva = pe
        .exception_table
        .as_ref()
        .expect("fixture has exception data")
        .functions()
        .find(|function| function.begin == Rva(0x1000))
        .expect("fixture marker function has a runtime entry")
        .unwind_info;
    let offset = pe
        .rva_to_offset(unwind_rva)
        .expect("unwind info is file-backed")
        .get() as usize;
    // The original six-byte Begin call occupies 0x1033..0x1039. A boundary at
    // 0x1034 is invalid even though neutralizing the call would leave a one-byte
    // NOP ending exactly there.
    input[offset + 1] = 0x34;

    let error = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("fixture parses"),
        &Options {
            seed: Seed::new(1),
            ..Options::default()
        },
    )
    .expect_err("an original prologue boundary inside an instruction must fail closed");
    assert!(
        matches!(error, EmitError::SdkMarker(ref reason) if reason == "SDK Begin marker intersects the covering prologue"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_an_original_prologue_boundary_inside_an_earlier_instruction() {
    let mut input = required_fixture();
    let pe = PeFile::parse(&input).expect("adapted fixture parses");
    let unwind_rva = pe
        .exception_table
        .as_ref()
        .expect("fixture has exception data")
        .functions()
        .find(|function| function.begin == Rva(0x1000))
        .expect("fixture marker function has a runtime entry")
        .unwind_info;
    let offset = pe
        .rva_to_offset(unwind_rva)
        .expect("unwind info is file-backed")
        .get() as usize;
    input[offset + 1] = 1;

    let error = protect_direct_sdk_mutation(
        PeImage::from_bytes(input).expect("fixture parses"),
        &Options {
            seed: Seed::new(1),
            ..Options::default()
        },
    )
    .expect_err("an earlier split prologue instruction must fail closed");
    assert!(
        matches!(error, EmitError::SdkMarker(ref reason) if reason == "covering unwind prologue ends inside an instruction"),
        "unexpected error: {error}"
    );
}

fn decode_raws(bytes: &[u8], ip: u64) -> Vec<iced_x86::Instruction> {
    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
    let mut decoded = Vec::new();
    while decoder.can_decode() {
        decoded.push(decoder.decode());
    }
    decoded
}

fn linear_function(raws: &[RawInstruction]) -> Function {
    let instructions = raws
        .iter()
        .map(|raw| {
            let mut encoder = Encoder::new(64);
            encoder
                .encode(raw, raw.ip())
                .expect("test instruction encodes");
            vmp_ir::Instruction::decoded(
                Rva(u32::try_from(raw.ip()).expect("test RVA fits")),
                *raw,
                &encoder.take_buffer(),
            )
        })
        .collect();
    let start = Rva(u32::try_from(raws[0].ip()).expect("test RVA fits"));
    let end = Rva(
        u32::try_from(raws.last().expect("nonempty test function").next_ip())
            .expect("test end fits"),
    );
    Function {
        architecture: Architecture::X64,
        entry: start,
        blocks: vec![BasicBlock {
            id: BlockId(0),
            start,
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
    }
}

#[test]
fn sdk_junk_classifier_rejects_redundant_prefixes() {
    assert_eq!(junk_form(&decode_raws(&[0xf3, 0xf8], 0x1000)[0]), None);
    assert_eq!(
        junk_form(&decode_raws(&[0x40, 0xb8, 1, 0, 0, 0], 0x1000)[0]),
        None
    );
}

#[test]
fn sdk_alignment_rejects_non_adjacent_common_mov_ambiguity() {
    let before = decode_raws(&[0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3], 0x1000);
    let after = decode_raws(
        &[
            0xb8, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3,
        ],
        0x2000,
    );
    let dead = before
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
        .collect();

    assert_eq!(
        unique_junk_alignment(&before, &after, &dead)
            .expect_err("duplicate MOV alignment must be ambiguous"),
        "ambiguous alignment"
    );
}

#[test]
fn sdk_alignment_rejects_junk_that_clobbers_independently_live_state() {
    let before = decode_raws(&[0x90, 0x13, 0xc0, 0xc3], 0x1000);
    let live_register_after = decode_raws(&[0x90, 0xb8, 1, 0, 0, 0, 0x13, 0xc0, 0xc3], 0x2000);
    let live_cf_after = decode_raws(&[0x90, 0xf8, 0x13, 0xc0, 0xc3], 0x3000);
    let function = linear_function(&before);
    let dead = independent_dead_after(&function);

    assert_eq!(
        unique_junk_alignment(&before, &live_register_after, &dead)
            .expect_err("live EAX must reject MOV junk"),
        "no complete alignment"
    );
    assert_eq!(
        unique_junk_alignment(&before, &live_cf_after, &dead)
            .expect_err("live CF must reject CLC junk"),
        "no complete alignment"
    );
}

#[test]
fn sdk_anchor_semantics_requires_exact_internal_and_external_branch_targets() {
    let internal_before = decode_raws(&[0xeb, 0x00, 0xc3], 0x1000);
    let internal_wrong = decode_raws(&[0xeb, 0x00, 0x90, 0xc3], 0x2000);
    let internal_map = [(0x1000, 0x2000), (0x1002, 0x2003)].into_iter().collect();
    assert!(!anchor_semantics_match(
        internal_before[0],
        internal_wrong[0],
        &internal_map
    ));

    let external_before = decode_raws(&[0xe9, 0xfb, 0x0f, 0x00, 0x00], 0x1000);
    let external_changed = decode_raws(&[0xe9, 0xfa, 0x0f, 0x00, 0x00], 0x2000);
    let external_map = [(0x1000, 0x2000)].into_iter().collect();
    assert!(!anchor_semantics_match(
        external_before[0],
        external_changed[0],
        &external_map
    ));
}
