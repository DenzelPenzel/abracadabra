//! Scalar leaf selection, known-entry validation and generated VM emission.
//!
//! Entry discovery covers PE roots, relocated code pointers and decoded references.
//! It is not a proof that arbitrary computed addresses cannot enter the function.
//! Executable targets of address-taking and relocated absolute references are
//! conservatively decoded as potential code, so ambiguous code/data layouts may
//! be refused. Ordinary RIP-relative memory accesses do not introduce code roots.

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use vmp_ir::{Instruction, OperandRef, TargetKind};
use vmp_pe::{ExportTarget, PeFile};
use vmp_types::{Architecture, Rva};
use vmp_x86::{decode_function_with, DecodeOptions, Image};

const MAX_ROOTS: usize = 4096;
const DECODE_BUDGET: usize = 4096;

/// One explicitly selected complete leaf and any additional known code entries.
pub struct Request {
    pub image: Vec<u8>,
    pub rva: Rva,
    pub external_entries: Vec<Rva>,
    pub seed: u64,
}

/// Fully serialized output; no filesystem publication has happened yet.
pub struct Product {
    pub image: Vec<u8>,
    pub original: Rva,
    pub entry: Rva,
    pub instance: Rva,
    pub source_length: u32,
    pub seed: u64,
    pub variant: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("loading the PE failed: {0}")]
    Pe(#[from] vmp_pe::PeError),
    #[error("decoding a known code entry failed: {0}")]
    Decode(#[from] vmp_x86::X86Error),
    #[error("virtualization requires an x64 scalar leaf ending in RET")]
    Leaf,
    #[error("known entry {target} targets the replaced interior of {entry}")]
    InteriorEntry { entry: Rva, target: Rva },
    #[error("known instruction at {rva} overlaps the selected leaf with incompatible boundaries")]
    OverlappingCode { rva: Rva },
    #[error("unresolved control flow at known code entry {rva}")]
    UnresolvedControlFlow { rva: Rva },
    #[error("known-entry analysis exceeded its bounded budget")]
    Budget,
    #[error("allocation failed while preparing virtualization")]
    Allocation,
    #[error("generating the VM failed: {0}")]
    Emit(#[from] vmp_emit::vm::VmEmbeddingError),
    #[error("lowering the selected instruction failed: {0}")]
    Lower(#[from] vmp_vm::logical::LogicalError),
}

/// Protects one leaf after checking all discovered entries and references.
pub fn protect_virtualization(request: Request) -> Result<Product, Error> {
    let pe = PeFile::parse(&request.image)?;
    if pe.architecture != Architecture::X64 {
        return Err(Error::Leaf);
    }
    let view = Image::new(&pe, &request.image);
    let function = decode_function_with(
        view,
        request.rva,
        DecodeOptions {
            budget: DECODE_BUDGET,
        },
    )?;
    if !function.is_complete() || function.blocks.len() != 1 || function.unwind.is_some() {
        return Err(Error::Leaf);
    }
    let instructions = &function.blocks[0].instructions;
    let (ret, body) = instructions.split_last().ok_or(Error::Leaf)?;
    if ret.bytes() != [0xc3] || body.is_empty() {
        return Err(Error::Leaf);
    }
    let end = ret.rva().ok_or(Error::Leaf)?;
    let source_length = end
        .get()
        .checked_sub(request.rva.get())
        .ok_or(Error::Leaf)?;
    validate_entries(
        view,
        &request.image,
        request.rva,
        end,
        &request.external_entries,
        body,
    )?;

    // The native decoder uses RVA coordinates; generated shadows require VA coordinates
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(body.len())
        .map_err(|_| Error::Allocation)?;
    for instruction in body {
        let rva = instruction.rva().ok_or(Error::Leaf)?;
        let va = rva.to_va(pe.optional.image_base).ok_or(Error::Leaf)?;
        let raw = Decoder::with_ip(64, instruction.bytes(), va.0, DecoderOptions::NONE).decode();
        sources.push(Instruction::decoded(rva, raw, instruction.bytes()));
    }
    let mut bodies = Vec::new();
    bodies
        .try_reserve_exact(sources.len())
        .map_err(|_| Error::Allocation)?;
    for instruction in &sources {
        bodies.push(vmp_vm::logical::lower_instruction(
            Architecture::X64,
            instruction,
        )?);
    }
    let variant = request.seed.to_le_bytes()[0];
    let artifact = vmp_emit::vm::redirect_leaf_vm_instance(request.image, &bodies, variant)?;
    Ok(Product {
        original: request.rva,
        entry: artifact.placement().entry_rva(),
        instance: artifact.placement().rva(),
        source_length,
        image: artifact.into_bytes(),
        seed: request.seed,
        variant,
    })
}

fn validate_entries(
    image: Image<'_>,
    data: &[u8],
    entry: Rva,
    end: Rva,
    declared: &[Rva],
    selected: &[Instruction],
) -> Result<(), Error> {
    let mut roots = Vec::new();
    let mut add = |target| add_root(image, &mut roots, entry, end, target);
    add(entry)?;
    if image.pe().entry_point().get() != 0 {
        add(image.pe().entry_point())?;
    }
    for &target in declared {
        if !image.is_executable(target) {
            return Err(Error::UnresolvedControlFlow { rva: target });
        }
        add(target)?;
    }
    if let Some(exports) = &image.pe().exports {
        for export in &exports.entries {
            match export.target {
                ExportTarget::Code(target) => add(target)?,
                ExportTarget::Forwarder(_) => {}
            }
        }
    }
    if let Some(tls) = &image.pe().tls {
        for &target in &tls.callbacks {
            add(target)?;
        }
    }
    if let Some(table) = &image.pe().exception_table {
        for function in table.functions() {
            add(function.begin)?;
            let mut next = Some(function.unwind_info);
            for _ in 0..16 {
                let Some(rva) = next else { break };
                let unwind = vmp_pe::UnwindInfo::parse(image.pe(), data, rva)?;
                if let Some(handler) = unwind.handler {
                    add(handler)?;
                }
                next = match unwind.chained {
                    Some(chained) => {
                        add(chained.begin)?;
                        Some(chained.unwind_info)
                    }
                    None => None,
                };
            }
            if next.is_some() {
                return Err(Error::Budget);
            }
        }
    }
    if let Some(relocations) = &image.pe().base_relocations {
        for fixup in relocations.fixups() {
            let bytes = image
                .pe()
                .mapped_range(data, fixup.rva, fixup.kind.width())?;
            let mut address = [0; 8];
            address[..bytes.len()].copy_from_slice(bytes);
            if let Some(target) = u64::from_le_bytes(address)
                .checked_sub(image.image_base().get())
                .and_then(|value| u32::try_from(value).ok())
            {
                add(Rva(target))?;
            }
        }
    }
    let mut cursor = 0;
    while cursor < roots.len() {
        let root = roots[cursor];
        cursor += 1;
        let function = decode_function_with(
            image,
            root,
            DecodeOptions {
                budget: DECODE_BUDGET,
            },
        )?;
        if !function.is_complete() {
            return Err(Error::UnresolvedControlFlow { rva: root });
        }
        for block in &function.blocks {
            for instruction in &block.instructions {
                let rva = instruction.rva().ok_or(Error::Leaf)?;
                let instruction_end = rva
                    .checked_add(instruction.len() as u32)
                    .ok_or(Error::Leaf)?;
                if rva < end
                    && instruction_end > entry
                    && !selected.iter().any(|original| {
                        original.rva() == Some(rva) && original.len() == instruction.len()
                    })
                {
                    return Err(Error::OverlappingCode { rva });
                }
                if matches!(
                    instruction.raw().flow_control(),
                    FlowControl::IndirectCall | FlowControl::IndirectBranch
                ) && !instruction.refs().iter().any(|reference| {
                    matches!(
                        reference,
                        OperandRef::RipRelative {
                            target_kind: TargetKind::ImportThunk,
                            ..
                        } | OperandRef::Absolute {
                            target_kind: TargetKind::ImportThunk,
                            ..
                        }
                    )
                }) {
                    return Err(Error::UnresolvedControlFlow {
                        rva: instruction.rva().ok_or(Error::Leaf)?,
                    });
                }
                for reference in instruction.refs() {
                    let target = match reference {
                        OperandRef::Branch { target, .. }
                        | OperandRef::RipRelative { target, .. } => Some(*target),
                        OperandRef::Absolute { target, .. } => *target,
                    };
                    if let Some(target) = target {
                        check_interior(entry, end, target)?;
                        if !matches!(reference, OperandRef::RipRelative { .. })
                            || instruction.raw().mnemonic() == iced_x86::Mnemonic::Lea
                        {
                            add_root(image, &mut roots, entry, end, target)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn add_root(
    image: Image<'_>,
    roots: &mut Vec<Rva>,
    entry: Rva,
    end: Rva,
    target: Rva,
) -> Result<(), Error> {
    check_interior(entry, end, target)?;
    if image.is_executable(target) && !roots.contains(&target) {
        if roots.len() == MAX_ROOTS {
            return Err(Error::Budget);
        }
        roots.try_reserve(1).map_err(|_| Error::Allocation)?;
        roots.push(target);
    }
    Ok(())
}

fn check_interior(entry: Rva, end: Rva, target: Rva) -> Result<(), Error> {
    if target > entry && target < end {
        return Err(Error::InteriorEntry { entry, target });
    }
    Ok(())
}
