//! The stable, versioned `disasm` report.
//!
//! Like the `inspect` contract, the DTO is decoupled from the internal IR:
//! `vmp-ir` may change shape, this JSON may not.

use serde::Serialize;
use vmp_ir::{
    BasicBlock, Edge, EdgeKind, EdgeTarget, Function, Instruction, OperandRef, Terminator,
};
use vmp_x86::{Image, Liveness, TextFormatter};

/// JSON schema version. Bumped on incompatible changes to the contract.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Serialize)]
pub struct DisasmReport {
    pub schema_version: &'static str,
    pub file: FileInfo,
    pub architecture: String,
    pub image_base: String,
    pub function: FunctionInfo,
    pub blocks: Vec<BlockEntry>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct FunctionInfo {
    pub entry: String,
    /// Whether the function is safe to protect: no issues were recorded.
    pub complete: bool,
    pub block_count: usize,
    pub instruction_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwind: Option<UnwindEntry>,
    /// Addresses outside the function that control can reach.
    pub external_targets: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Serialize)]
pub struct UnwindEntry {
    pub begin: String,
    pub end: String,
    pub unwind_info: String,
}

#[derive(Serialize)]
pub struct BlockEntry {
    pub id: u32,
    pub start: String,
    pub end: String,
    pub terminator: &'static str,
    pub predecessors: Vec<u32>,
    pub successors: Vec<EdgeEntry>,
    pub instructions: Vec<InstructionEntry>,
}

#[derive(Serialize)]
pub struct EdgeEntry {
    pub kind: &'static str,
    /// Set when the edge stays inside the function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<u32>,
    /// Set when the edge leaves the function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external: Option<String>,
}

#[derive(Serialize)]
pub struct InstructionEntry {
    pub rva: Option<String>,
    pub bytes: String,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<RefEntry>,
    /// Present only when liveness was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_after: Option<DeadEntry>,
}

/// What may be overwritten immediately after an instruction.
///
/// The complement of what is in use, because that is the question a mutation
/// asks. An empty pair of lists means nothing there is provably free.
#[derive(Serialize)]
pub struct DeadEntry {
    pub registers: Vec<String>,
    pub flags: Vec<String>,
}

#[derive(Serialize)]
pub struct RefEntry {
    pub kind: &'static str,
    /// Offset and size of the encoded field this reference occupies.
    pub field_offset: u8,
    pub field_size: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<&'static str>,
    /// Set for a branch: what kind of transfer it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<&'static str>,
    /// Set for an absolute address: the virtual address as encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<String>,
    /// Set for an absolute address: the relocated width in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u8>,
    /// Set when the target is an import thunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
}

impl DisasmReport {
    pub fn build(
        path: &str,
        size: u64,
        image: &Image<'_>,
        function: &Function,
        liveness: bool,
    ) -> DisasmReport {
        let mut formatter = TextFormatter::new();
        let mut blocks: Vec<&BasicBlock> = function.blocks.iter().collect();
        blocks.sort_by_key(|block| block.start); // should be sorted
        let liveness = liveness.then(|| vmp_x86::analyze_liveness(function));

        DisasmReport {
            schema_version: SCHEMA_VERSION,
            file: FileInfo {
                path: path.to_owned(),
                size,
            },
            architecture: function.architecture.to_string(),
            image_base: image.image_base().to_string(),
            function: FunctionInfo {
                entry: function.entry.to_string(),
                complete: function.is_complete(),
                block_count: function.blocks.len(),
                instruction_count: function.instruction_count(),
                unwind: function.unwind.map(|range| UnwindEntry {
                    begin: range.begin.to_string(),
                    end: range.end.to_string(),
                    unwind_info: range.unwind_info.to_string(),
                }),
                external_targets: function
                    .external_targets()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                issues: function.issues.iter().map(ToString::to_string).collect(),
            },
            blocks: blocks
                .into_iter()
                .map(|block| block_entry(block, image, &mut formatter, liveness.as_ref()))
                .collect(),
        }
    }
}

fn block_entry(
    block: &BasicBlock,
    image: &Image<'_>,
    formatter: &mut TextFormatter,
    liveness: Option<&Liveness>,
) -> BlockEntry {
    BlockEntry {
        id: block.id.0,
        start: block.start.to_string(),
        end: block.end.to_string(),
        terminator: terminator_name(block.terminator),
        predecessors: block.predecessors.iter().map(|id| id.0).collect(),
        successors: block.successors.iter().map(edge_entry).collect(),
        instructions: block
            .instructions
            .iter()
            .map(|instruction| instruction_entry(instruction, image, formatter, liveness))
            .collect(),
    }
}

fn instruction_entry(
    instruction: &Instruction,
    image: &Image<'_>,
    formatter: &mut TextFormatter,
    liveness: Option<&Liveness>,
) -> InstructionEntry {
    InstructionEntry {
        rva: instruction.rva().map(|rva| rva.to_string()),
        bytes: hex(instruction.bytes()),
        text: formatter.format(instruction),
        refs: instruction
            .refs()
            .iter()
            .map(|reference| ref_entry(reference, image))
            .collect(),
        dead_after: liveness
            .zip(instruction.rva())
            .and_then(|(liveness, rva)| liveness.dead_after(rva))
            .map(|dead| DeadEntry {
                registers: dead
                    .registers
                    .iter()
                    .map(|register| format!("{register:?}"))
                    .collect(),
                flags: dead.flags.iter_names().map(ToOwned::to_owned).collect(),
            }),
    }
}

fn ref_entry(reference: &OperandRef, image: &Image<'_>) -> RefEntry {
    let field = reference.field();
    let base = RefEntry {
        kind: "",
        field_offset: field.offset,
        field_size: field.size,
        target: None,
        target_kind: None,
        branch: None,
        va: None,
        width: None,
        import: None,
    };

    match reference {
        OperandRef::Branch { target, kind, .. } => RefEntry {
            kind: "branch",
            target: Some(target.to_string()),
            branch: Some(match kind {
                vmp_ir::BranchKind::Call => "call",
                vmp_ir::BranchKind::Jump => "jump",
                vmp_ir::BranchKind::Conditional => "conditional",
            }),
            ..base
        },
        OperandRef::RipRelative {
            target,
            target_kind,
            ..
        } => RefEntry {
            kind: "rip_relative",
            target: Some(target.to_string()),
            target_kind: Some(target_kind_name(*target_kind)),
            import: import_name(image, *target),
            ..base
        },
        OperandRef::Absolute {
            va,
            target,
            width,
            target_kind,
            ..
        } => RefEntry {
            kind: "absolute",
            va: Some(va.to_string()),
            target: target.map(|rva| rva.to_string()),
            target_kind: Some(target_kind_name(*target_kind)),
            width: Some(width.byte_len() * 8),
            import: target.and_then(|rva| import_name(image, rva)),
            ..base
        },
    }
}

fn import_name(image: &Image<'_>, rva: vmp_types::Rva) -> Option<String> {
    image
        .import_thunk(rva)
        .map(|(library, function)| format!("{library}!{function}"))
}

fn edge_entry(edge: &Edge) -> EdgeEntry {
    let (block, external) = match edge.target {
        EdgeTarget::Block(id) => (Some(id.0), None),
        EdgeTarget::External(rva) => (None, Some(rva.to_string())),
    };
    EdgeEntry {
        kind: match edge.kind {
            EdgeKind::FallThrough => "fall_through",
            EdgeKind::Taken => "taken",
            EdgeKind::NotTaken => "not_taken",
            EdgeKind::Jump => "jump",
        },
        block,
        external,
    }
}

fn terminator_name(terminator: Terminator) -> &'static str {
    match terminator {
        Terminator::FallThrough => "fall_through",
        Terminator::Jump => "jump",
        Terminator::Conditional => "conditional",
        Terminator::Return => "return",
        Terminator::IndirectJump => "indirect_jump",
        Terminator::ImportTailCall => "import_tail_call",
        Terminator::Halt => "halt",
        Terminator::Data => "data",
    }
}

fn target_kind_name(kind: vmp_ir::TargetKind) -> &'static str {
    match kind {
        vmp_ir::TargetKind::Code => "code",
        vmp_ir::TargetKind::Data => "data",
        vmp_ir::TargetKind::ImportThunk => "import_thunk",
        vmp_ir::TargetKind::Unmapped => "unmapped",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Prints the function as a readable listing.
pub fn print_text(report: &DisasmReport) {
    println!(
        "File:            {} ({} bytes)",
        report.file.path, report.file.size
    );
    println!("Architecture:    {}", report.architecture);
    println!("Image base:      {}", report.image_base);
    println!(
        "Function:        entry {}, {} block(s), {} instruction(s)",
        report.function.entry, report.function.block_count, report.function.instruction_count
    );
    match &report.function.unwind {
        Some(unwind) => println!(
            "Unwind (.pdata): {}..{} info {}",
            unwind.begin, unwind.end, unwind.unwind_info
        ),
        None => println!("Unwind (.pdata): none"),
    }
    println!(
        "Protectable:     {}",
        if report.function.complete {
            "yes"
        } else {
            "no"
        }
    );

    for block in &report.blocks {
        println!("\nblock {} {}..{}", block.id, block.start, block.end);
        if !block.predecessors.is_empty() {
            let preds: Vec<String> = block.predecessors.iter().map(u32::to_string).collect();
            println!("  preds: {}", preds.join(", "));
        }
        for instruction in &block.instructions {
            let refs = describe_refs(&instruction.refs);
            let rva = instruction.rva.as_deref().unwrap_or("  (inserted)");
            println!(
                "  {}  {:<24} {}{}",
                rva, instruction.bytes, instruction.text, refs
            );
            if let Some(dead) = &instruction.dead_after {
                println!(
                    "                                  free: regs[{}] flags[{}]",
                    describe_set(&dead.registers),
                    describe_set(&dead.flags)
                );
            }
        }
        println!(
            "  -> {} {}",
            block.terminator,
            describe_edges(&block.successors)
        );
    }

    if !report.function.external_targets.is_empty() {
        println!("\nExternal targets:");
        for target in &report.function.external_targets {
            println!("  {target}");
        }
    }
    if !report.function.issues.is_empty() {
        println!("\nIssues (function cannot be protected):");
        for issue in &report.function.issues {
            println!("  ! {issue}");
        }
    }
}

/// Renders a set for the listing, with a dash for the empty one so that a line
/// with nothing free is still readable as an answer.
fn describe_set(names: &[String]) -> String {
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join(" ")
    }
}

fn describe_refs(refs: &[RefEntry]) -> String {
    if refs.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = refs
        .iter()
        .map(|reference| match (&reference.import, &reference.target) {
            (Some(import), _) => format!("{} -> {import}", reference.kind),
            (None, Some(target)) => format!("{} -> {target}", reference.kind),
            (None, None) => reference.kind.to_owned(),
        })
        .collect();
    format!("    ; {}", parts.join(", "))
}

fn describe_edges(edges: &[EdgeEntry]) -> String {
    let parts: Vec<String> = edges
        .iter()
        .map(|edge| match (edge.block, &edge.external) {
            (Some(block), _) => format!("{}=block {block}", edge.kind),
            (None, Some(external)) => format!("{}={external} (external)", edge.kind),
            (None, None) => edge.kind.to_owned(),
        })
        .collect();
    parts.join(", ")
}
