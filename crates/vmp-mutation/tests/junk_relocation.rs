use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction as RawInstruction, OpKind, Register,
};
use vmp_ir::{BasicBlock, BlockId, CompileStage, Function, Instruction, Terminator};
use vmp_mutation::{mutate, Frozen, Options, Report, Seed};
use vmp_types::{Architecture, Rva};
use vmp_x86::{relocate, Relocated};

const ENTRY: Rva = Rva(0x1000);
const TARGET: Rva = Rva(0x20_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JunkForm {
    Clc,
    Stc,
    Cmc,
    Mov32,
    Mov64,
    Not32,
    Not64,
    Bswap32,
    Bswap64,
}

impl JunkForm {
    fn report_name(self) -> &'static str {
        match self {
            Self::Clc => "junk-clc",
            Self::Stc => "junk-stc",
            Self::Cmc => "junk-cmc",
            Self::Mov32 => "junk-mov-imm32",
            Self::Mov64 => "junk-mov-imm64",
            Self::Not32 => "junk-not32",
            Self::Not64 => "junk-not64",
            Self::Bswap32 => "junk-bswap32",
            Self::Bswap64 => "junk-bswap64",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Projection {
    dead_registers: BTreeSet<Register>,
    cf_dead: bool,
}

impl Projection {
    fn only_rax_dead_cf_live() -> Self {
        Self {
            dead_registers: BTreeSet::from([Register::RAX]),
            cf_dead: false,
        }
    }

    fn only_cf_dead() -> Self {
        Self {
            dead_registers: BTreeSet::new(),
            cf_dead: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Model {
    registers: [u64; 16],
    cf: bool,
}

impl Model {
    fn sample() -> Self {
        Self {
            registers: std::array::from_fn(|index| {
                0x1020_3040_5060_7080u64.wrapping_add(index as u64 * 0x0101_0101)
            }),
            cf: true,
        }
    }

    fn apply(&mut self, form: JunkForm, raw: &RawInstruction) {
        match form {
            JunkForm::Clc => self.cf = false,
            JunkForm::Stc => self.cf = true,
            JunkForm::Cmc => self.cf = !self.cf,
            JunkForm::Mov32 => {
                self.registers[register_index(raw.op0_register())] = u64::from(raw.immediate32());
            }
            JunkForm::Mov64 => {
                self.registers[register_index(raw.op0_register())] = raw.immediate64();
            }
            JunkForm::Not32 => {
                let slot = &mut self.registers[register_index(raw.op0_register())];
                *slot = u64::from(!(*slot as u32));
            }
            JunkForm::Not64 => {
                let slot = &mut self.registers[register_index(raw.op0_register())];
                *slot = !*slot;
            }
            JunkForm::Bswap32 => {
                let slot = &mut self.registers[register_index(raw.op0_register())];
                *slot = u64::from((*slot as u32).swap_bytes());
            }
            JunkForm::Bswap64 => {
                let slot = &mut self.registers[register_index(raw.op0_register())];
                *slot = slot.swap_bytes();
            }
        }
    }

    fn live_projection(self, dead: &Projection) -> (Vec<u64>, Option<bool>) {
        let registers = x64_registers()
            .iter()
            .enumerate()
            .filter(|(_, register)| !dead.dead_registers.contains(register))
            .map(|(index, _)| self.registers[index])
            .collect();
        (registers, (!dead.cf_dead).then_some(self.cf))
    }
}

fn register_index(register: Register) -> usize {
    x64_registers()
        .iter()
        .position(|candidate| *candidate == register.full_register())
        .expect("classifier admits only modelled GPRs")
}

fn x64_registers() -> &'static [Register; 16] {
    &[
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
    ]
}

fn legal_gpr(register: Register, architecture: Architecture, width64: bool) -> bool {
    let full = register.full_register();
    if matches!(full, Register::None | Register::RSP) {
        return false;
    }
    match architecture {
        Architecture::X86 => {
            !width64
                && matches!(
                    full,
                    Register::RAX
                        | Register::RCX
                        | Register::RDX
                        | Register::RBX
                        | Register::RBP
                        | Register::RSI
                        | Register::RDI
                )
        }
        Architecture::X64 => x64_registers().contains(&full),
    }
}

fn classify(raw: &RawInstruction, architecture: Architecture) -> Option<JunkForm> {
    let form = if raw.op_count() == 0 {
        match raw.code() {
            Code::Clc => Some(JunkForm::Clc),
            Code::Stc => Some(JunkForm::Stc),
            Code::Cmc => Some(JunkForm::Cmc),
            _ => None,
        }
    } else if raw.op0_kind() == OpKind::Register {
        match raw.code() {
            Code::Mov_r32_imm32 if raw.op_count() == 2 && raw.op1_kind() == OpKind::Immediate32 => {
                Some(JunkForm::Mov32)
            }
            Code::Mov_r64_imm64 if raw.op_count() == 2 && raw.op1_kind() == OpKind::Immediate64 => {
                Some(JunkForm::Mov64)
            }
            Code::Not_rm32 if raw.op_count() == 1 => Some(JunkForm::Not32),
            Code::Not_rm64 if raw.op_count() == 1 => Some(JunkForm::Not64),
            Code::Bswap_r32 if raw.op_count() == 1 => Some(JunkForm::Bswap32),
            Code::Bswap_r64 if raw.op_count() == 1 => Some(JunkForm::Bswap64),
            _ => None,
        }
    } else {
        None
    }?;
    let width64 = matches!(form, JunkForm::Mov64 | JunkForm::Not64 | JunkForm::Bswap64);
    if !matches!(form, JunkForm::Clc | JunkForm::Stc | JunkForm::Cmc)
        && !legal_gpr(raw.op0_register(), architecture, width64)
    {
        return None;
    }
    canonical_len(form, raw, architecture)
        .is_some_and(|canonical| canonical == raw.len())
        .then_some(form)
}

fn canonical_len(
    form: JunkForm,
    raw: &RawInstruction,
    architecture: Architecture,
) -> Option<usize> {
    let canonical = match form {
        JunkForm::Clc => RawInstruction::with(Code::Clc),
        JunkForm::Stc => RawInstruction::with(Code::Stc),
        JunkForm::Cmc => RawInstruction::with(Code::Cmc),
        JunkForm::Mov32 => {
            RawInstruction::with2(Code::Mov_r32_imm32, raw.op0_register(), raw.immediate32())
                .ok()?
        }
        JunkForm::Mov64 => {
            RawInstruction::with2(Code::Mov_r64_imm64, raw.op0_register(), raw.immediate64())
                .ok()?
        }
        JunkForm::Not32 => RawInstruction::with1(Code::Not_rm32, raw.op0_register()).ok()?,
        JunkForm::Not64 => RawInstruction::with1(Code::Not_rm64, raw.op0_register()).ok()?,
        JunkForm::Bswap32 => RawInstruction::with1(Code::Bswap_r32, raw.op0_register()).ok()?,
        JunkForm::Bswap64 => RawInstruction::with1(Code::Bswap_r64, raw.op0_register()).ok()?,
    };
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    Encoder::new(bitness).encode(&canonical, raw.ip()).ok()
}

fn same_original(original: RawInstruction, mut relocated: RawInstruction) -> bool {
    relocated.set_ip(original.ip());
    original == relocated
}

fn decode_one(architecture: Architecture, bytes: &[u8], ip: u64) -> Result<RawInstruction, String> {
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    let raw = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE).decode();
    if raw.is_invalid() || raw.len() == 0 {
        Err(format!("invalid instruction at {ip:#x}"))
    } else {
        Ok(raw)
    }
}

fn relocation_gap_oracle(
    architecture: Architecture,
    originals: &[RawInstruction],
    relocated: &Relocated,
    projections: &BTreeMap<Rva, Projection>,
    report: &Report,
) -> Result<BTreeMap<&'static str, usize>, String> {
    if relocated.moved.len() != originals.len() {
        return Err(format!(
            "move map has {} entries for {} originals",
            relocated.moved.len(),
            originals.len()
        ));
    }

    let mut mapped = Vec::with_capacity(originals.len());
    for &original in originals {
        let old = Rva(u32::try_from(original.ip()).map_err(|_| "original IP is not an RVA")?);
        let new = relocated
            .new_rva(old)
            .ok_or_else(|| format!("original at {old} has no relocation mapping"))?;
        let offset = usize::try_from(
            new.get()
                .checked_sub(relocated.rva.get())
                .ok_or("mapped instruction precedes relocated bytes")?,
        )
        .map_err(|_| "mapped offset does not fit usize")?;
        let raw = decode_one(
            architecture,
            relocated
                .bytes
                .get(offset..)
                .ok_or("mapped instruction lies outside relocated bytes")?,
            u64::from(new.get()),
        )?;
        if !same_original(original, raw) {
            return Err(format!("mapped original changed: {original:?} -> {raw:?}"));
        }
        mapped.push((old, offset, raw.len()));
    }
    mapped.sort_by_key(|(_, offset, _)| *offset);

    let mut observed = BTreeMap::new();
    let mut cursor = 0usize;
    let mut preceding = None;
    for (old, offset, len) in mapped {
        if offset < cursor {
            return Err("mapped original extents overlap".to_owned());
        }
        decode_gap(
            architecture,
            &relocated.bytes[cursor..offset],
            relocated.rva.get() as usize + cursor,
            preceding.and_then(|rva| projections.get(&rva)),
            &mut observed,
        )?;
        cursor = offset.checked_add(len).ok_or("mapped extent overflow")?;
        preceding = Some(old);
    }
    decode_gap(
        architecture,
        relocated
            .bytes
            .get(cursor..)
            .ok_or("final mapped extent exceeds relocated bytes")?,
        relocated.rva.get() as usize + cursor,
        preceding.and_then(|rva| projections.get(&rva)),
        &mut observed,
    )?;

    let claimed = report
        .applied
        .iter()
        .filter(|(name, _)| name.starts_with("junk-"))
        .map(|(name, count)| (*name, *count))
        .collect::<BTreeMap<_, _>>();
    if observed != claimed {
        return Err(format!("observed {observed:?}, report claims {claimed:?}"));
    }
    if observed.values().sum::<usize>() == 0 {
        return Err("oracle observed no inserted junk".to_owned());
    }
    Ok(observed)
}

fn decode_gap(
    architecture: Architecture,
    bytes: &[u8],
    ip: usize,
    projection: Option<&Projection>,
    observed: &mut BTreeMap<&'static str, usize>,
) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    let projection =
        projection.ok_or_else(|| "junk appeared without a declared preceding state".to_owned())?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let raw = decode_one(architecture, &bytes[offset..], (ip + offset) as u64)?;
        let form = classify(&raw, architecture).ok_or_else(|| {
            format!("unrecognized gap instruction or non-canonical junk encoding: {raw:?}")
        })?;
        match form {
            JunkForm::Clc | JunkForm::Stc | JunkForm::Cmc if !projection.cf_dead => {
                return Err(format!("{form:?} changes declared-live CF"));
            }
            JunkForm::Mov32
            | JunkForm::Mov64
            | JunkForm::Not32
            | JunkForm::Not64
            | JunkForm::Bswap32
            | JunkForm::Bswap64
                if !projection
                    .dead_registers
                    .contains(&raw.op0_register().full_register()) =>
            {
                return Err(format!(
                    "{form:?} changes declared-live {:?}",
                    raw.op0_register().full_register()
                ));
            }
            _ => {}
        }
        let before = Model::sample();
        let mut after = before;
        after.apply(form, &raw);
        if before.live_projection(projection) != after.live_projection(projection) {
            return Err(format!(
                "{form:?} changed the handwritten live-state projection"
            ));
        }
        *observed.entry(form.report_name()).or_default() += 1;
        offset += raw.len();
    }
    Ok(())
}

fn straight_line(bytes: &[u8]) -> Function {
    let mut decoder = Decoder::with_ip(64, bytes, u64::from(ENTRY.get()), DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let raw = decoder.decode();
        let offset = usize::try_from(raw.ip() - u64::from(ENTRY.get())).expect("small fixture");
        instructions.push(Instruction::decoded(
            Rva(u32::try_from(raw.ip()).expect("fixture RVA")),
            raw,
            &bytes[offset..offset + raw.len()],
        ));
    }
    let end = instructions
        .last()
        .and_then(Instruction::next_rva)
        .expect("fixture is nonempty");
    Function {
        architecture: Architecture::X64,
        entry: ENTRY,
        blocks: vec![BasicBlock {
            id: BlockId(0),
            start: ENTRY,
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

fn synthetic_gap(
    original_bytes: &[u8],
    gap: &[u8],
    projection: Projection,
) -> (Vec<RawInstruction>, Relocated, BTreeMap<Rva, Projection>) {
    let function = straight_line(original_bytes);
    let originals = function
        .instructions()
        .map(|instruction| *instruction.raw())
        .collect::<Vec<_>>();
    assert_eq!(
        originals.len(),
        2,
        "synthetic helper expects one instruction and ret"
    );
    let first_len = originals[0].len();
    let mut bytes = original_bytes[..first_len].to_vec();
    bytes.extend_from_slice(gap);
    bytes.extend_from_slice(&original_bytes[first_len..]);
    let moved = vec![
        (ENTRY, TARGET),
        (
            Rva(u32::try_from(originals[1].ip()).expect("RVA")),
            TARGET
                .checked_add(u32::try_from(first_len + gap.len()).expect("small gap"))
                .expect("RVA"),
        ),
    ];
    let projections = BTreeMap::from([(ENTRY, projection)]);
    (
        originals,
        Relocated {
            rva: TARGET,
            bytes,
            moved,
        },
        projections,
    )
}

fn report_for(name: &'static str) -> Report {
    Report {
        applied: BTreeMap::from([(name, 1)]),
        ..Report::default()
    }
}

#[test]
fn relocation_gap_oracle_matches_junk_only_mutation_per_form() {
    // nop / mov eax, 1 / adc ecx, edx / ret. At the point after NOP, only
    // RAX is dead while CF is live. This declaration is intentionally
    // handwritten instead of borrowed from the production liveness engine.
    let bytes = [0x90, 0xb8, 1, 0, 0, 0, 0x11, 0xd1, 0xc3];
    let originals = straight_line(&bytes)
        .instructions()
        .map(|instruction| *instruction.raw())
        .collect::<Vec<_>>();
    let projections = BTreeMap::from([(ENTRY, Projection::only_rax_dead_cf_live())]);
    let options = Options {
        rewrites: false,
        junk: true,
    };
    let mut totals = BTreeMap::<&'static str, usize>::new();

    for seed in 0..4096 {
        let mut function = straight_line(&bytes);
        let report = mutate(&mut function, &Frozen::new(), Seed::new(seed), &options)
            .expect("controlled function mutates");
        if report.is_noop() {
            continue;
        }
        let relocated = relocate(&function, TARGET).expect("mutated function relocates");
        let observed = relocation_gap_oracle(
            Architecture::X64,
            &originals,
            &relocated,
            &projections,
            &report,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        for (name, count) in observed {
            *totals.entry(name).or_default() += count;
        }
        if [
            "junk-mov-imm32",
            "junk-mov-imm64",
            "junk-not32",
            "junk-not64",
            "junk-bswap32",
            "junk-bswap64",
        ]
        .iter()
        .all(|name| totals.contains_key(name))
        {
            break;
        }
    }

    assert_eq!(
        totals.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "junk-bswap32",
            "junk-bswap64",
            "junk-mov-imm32",
            "junk-mov-imm64",
            "junk-not32",
            "junk-not64",
        ]),
        "seed sweep must exercise all six register forms and no CF form"
    );
}

#[test]
fn separate_flag_fixture_is_checked_by_the_same_oracle() {
    // mov eax, 1 / add ecx, edx / ret: ADD overwrites CF, so CF is explicitly
    // dead after MOV while no register is declared dead.
    let bytes = [0xb8, 1, 0, 0, 0, 0x01, 0xd1, 0xc3];
    let originals = straight_line(&bytes)
        .instructions()
        .map(|instruction| *instruction.raw())
        .collect::<Vec<_>>();
    let projections = BTreeMap::from([(ENTRY, Projection::only_cf_dead())]);
    let options = Options {
        rewrites: false,
        junk: true,
    };
    let mut forms = BTreeSet::new();
    for seed in 0..1024 {
        let mut function = straight_line(&bytes);
        let report =
            mutate(&mut function, &Frozen::new(), Seed::new(seed), &options).expect("mutates");
        if report.is_noop() {
            continue;
        }
        let relocated = relocate(&function, TARGET).expect("relocates");
        let observed = relocation_gap_oracle(
            Architecture::X64,
            &originals,
            &relocated,
            &projections,
            &report,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        forms.extend(observed.keys().copied());
        if forms.len() == 3 {
            break;
        }
    }
    assert_eq!(forms, BTreeSet::from(["junk-clc", "junk-cmc", "junk-stc"]));
}

#[test]
fn oracle_rejects_unrecognized_gap_even_beside_a_common_original_mov() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0xb8, 1, 0, 0, 0, 0xc3],
        &[0x90],
        Projection::only_rax_dead_cf_live(),
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-mov-imm32"),
    )
    .expect_err("NOP is not catalogue junk");
    assert!(error.contains("unrecognized gap instruction"), "{error}");
}

#[test]
fn oracle_rejects_memory_not() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0x31, 0xc0, 0xc3],
        &[0x48, 0xf7, 0x10],
        Projection::only_rax_dead_cf_live(),
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-not64"),
    )
    .expect_err("memory NOT is not register junk");
    assert!(error.contains("unrecognized gap instruction"), "{error}");
}

#[test]
fn oracle_rejects_mov_to_a_declared_live_register() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0x31, 0xc0, 0xc3],
        &[0xb9, 7, 0, 0, 0],
        Projection::only_rax_dead_cf_live(),
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-mov-imm32"),
    )
    .expect_err("RCX is declared live");
    assert!(error.contains("declared-live RCX"), "{error}");
}

#[test]
fn oracle_rejects_clc_when_cf_is_declared_live() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0x31, 0xc0, 0xc3],
        &[0xf8],
        Projection::only_rax_dead_cf_live(),
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-clc"),
    )
    .expect_err("CF is declared live");
    assert!(error.contains("declared-live CF"), "{error}");
}

#[test]
fn oracle_rejects_redundantly_prefixed_clc() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0xb8, 1, 0, 0, 0, 0xc3],
        &[0x66, 0xf8],
        Projection::only_cf_dead(),
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-clc"),
    )
    .expect_err("redundantly prefixed CLC is not canonical junk");
    assert!(error.contains("non-canonical junk encoding"), "{error}");
}

#[test]
fn oracle_rejects_redundantly_prefixed_register_form() {
    let (originals, relocated, projections) = synthetic_gap(
        &[0x90, 0xc3],
        &[0x40, 0xb8, 7, 0, 0, 0],
        Projection {
            dead_registers: BTreeSet::from([Register::RAX]),
            cf_dead: false,
        },
    );
    let error = relocation_gap_oracle(
        Architecture::X64,
        &originals,
        &relocated,
        &projections,
        &report_for("junk-mov-imm32"),
    )
    .expect_err("redundantly prefixed MOV is not canonical junk");
    assert!(error.contains("non-canonical junk encoding"), "{error}");
}
