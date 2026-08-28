//! Relocation and mutation of direct SDK marker regions.

use iced_x86::{Code, Decoder, DecoderOptions, Instruction as RawInstruction};
use vmp_ir::{BasicBlock, BlockId, CompileStage, Function, Instruction, Terminator};
use vmp_mutation::{mutate_scoped, Frozen, MutationScope, Report};
use vmp_pe::markers::{discover_asm_markers, MarkerCompilationType, SdkMarker};
use vmp_pe::{
    NewFunction, NewSection, PeFile, PeImage, RuntimeFunction, UnwindInfo, UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER,
};
use vmp_types::Rva;
use vmp_x86::marker_region::{neutralize_marker_calls, recover_marker_region_from};
use vmp_x86::sdk_markers::{
    discover_direct_api_markers, discover_sdk_api_calls, ApiMarker, SdkApi, SdkApiCall,
};
use vmp_x86::{decode_function, epilogues, relocate, Image, Relocated};

use crate::stub::Stub;
use crate::{
    has_absolute_fixups, pad_to, prologue_has_valid_boundary, EmitError, Options, Protected, Ready,
    CODE_SECTION, FUNCTION_ALIGNMENT, STUB_LEN,
};

const MAX_SDK_NAME_LEN: usize = 4_096;

#[derive(Debug, Clone)]
pub struct SdkMutation {
    pub begin: Rva,
    pub function: Rva,
    pub relocated: Rva,
    pub length: u32,
    pub reached_ends: Vec<Rva>,
    pub sdk_stubs: Vec<SdkStub>,
    pub report: Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkStub {
    pub api: SdkApi,
    pub rva: Rva,
}

#[derive(Debug, Clone, Copy)]
struct MarkerSite {
    call: Rva,
    next: Rva,
    load: Option<Rva>,
    static_marker: bool,
}

impl MarkerSite {
    fn start(self) -> Rva {
        self.load.unwrap_or(self.call)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndPatch {
    StaticPayload { rva: Rva, length: u32 },
    ApiSpan { rva: Rva, length: u32 },
}

/// Mutates direct-IAT SDK regions, moves each covering function, and redirects
/// its original entry to the relocated copy.
pub fn protect_direct_sdk_mutation(
    image: PeImage,
    options: &Options,
) -> Result<(PeImage, Vec<SdkMutation>), EmitError> {
    let code_rva = image.next_section_rva()?;
    let data = image.into_bytes();
    let pe = PeFile::parse(&data)?;
    let view = Image::new(&pe, &data);
    let markers = discover_direct_api_markers(view)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    let asm_markers = discover_asm_markers(&pe, &data)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    let marker_count = markers
        .len()
        .checked_add(asm_markers.len())
        .ok_or_else(allocation_error)?;
    let mut ends = Vec::new();
    let mut begins = Vec::new();
    let mut names_to_erase = Vec::new();
    let mut marker_name_references = Vec::new();
    ends.try_reserve_exact(marker_count)
        .map_err(|_| allocation_error())?;
    begins
        .try_reserve_exact(marker_count)
        .map_err(|_| allocation_error())?;
    names_to_erase
        .try_reserve_exact(marker_count)
        .map_err(|_| allocation_error())?;
    marker_name_references
        .try_reserve_exact(marker_count)
        .map_err(|_| allocation_error())?;
    for marker in &markers {
        match marker {
            ApiMarker::Begin {
                load_rva,
                call_rva,
                next_rva,
                name_rva,
                name_reference_rva,
                compilation_type,
                lock_to_key,
            } => {
                if let Some(name_rva) = name_rva {
                    let length = sdk_name_length(view, *name_rva).ok_or_else(|| {
                        EmitError::SdkMarker(format!(
                            "SDK Begin name at {name_rva} is not a bounded NUL-terminated string"
                        ))
                    })?;
                    names_to_erase.push((*name_rva, length));
                }
                if let Some(reference) = name_reference_rva {
                    marker_name_references.push(*reference);
                }
                begins.push((
                    MarkerSite {
                        call: *call_rva,
                        next: *next_rva,
                        load: *load_rva,
                        static_marker: false,
                    },
                    *compilation_type,
                    *lock_to_key,
                ));
            }
            ApiMarker::End {
                load_rva,
                call_rva,
                next_rva,
            } => ends.push(MarkerSite {
                call: *call_rva,
                next: *next_rva,
                load: *load_rva,
                static_marker: false,
            }),
        }
    }
    for marker in asm_markers {
        match marker {
            SdkMarker::Begin {
                rva,
                next_rva,
                compilation_type,
                ..
            } => begins.push((
                MarkerSite {
                    call: rva,
                    next: next_rva,
                    load: None,
                    static_marker: true,
                },
                compilation_type,
                false,
            )),
            SdkMarker::End { rva, next_rva } => ends.push(MarkerSite {
                call: rva,
                next: next_rva,
                load: None,
                static_marker: true,
            }),
        }
    }
    if begins.is_empty() {
        return Err(EmitError::NoSdkMarkers);
    }
    let mut end_patches = Vec::new();
    end_patches
        .try_reserve_exact(ends.len())
        .map_err(|_| allocation_error())?;
    for end in &ends {
        end_patches.push(end_patch(*end)?);
    }

    let mut code = Vec::new();
    let mut stubs = Vec::new();
    let mut runtime_functions = Vec::new();
    let mut outcome = Vec::new();
    stubs
        .try_reserve_exact(begins.len())
        .map_err(|_| allocation_error())?;
    runtime_functions
        .try_reserve_exact(begins.len())
        .map_err(|_| allocation_error())?;
    outcome
        .try_reserve_exact(begins.len())
        .map_err(|_| allocation_error())?;
    for (begin, compilation_type, lock_to_key) in begins {
        if lock_to_key
            || !matches!(
                compilation_type,
                MarkerCompilationType::Default | MarkerCompilationType::Mutation
            )
        {
            return Err(EmitError::UnsupportedSdkMarker {
                rva: begin.call,
                compilation_type,
                lock_to_key,
            });
        }
        let runtime = pe
            .exception_table
            .as_ref()
            .and_then(|table| {
                table
                    .functions()
                    .find(|function| begin.call >= function.begin && begin.call < function.end)
            })
            .ok_or(EmitError::SdkMarkerOutsideRuntimeFunction { rva: begin.call })?;
        if outcome
            .iter()
            .any(|selected: &SdkMutation| selected.function == runtime.begin)
        {
            return Err(EmitError::MultipleSdkBegins {
                function: runtime.begin,
            });
        }
        let offset = code_offset(code.len(), runtime.begin)?;
        let placement = code_rva.checked_add(offset).ok_or(EmitError::Layout {
            rva: runtime.begin,
            reason: "the appended SDK code does not fit in the RVA space".to_string(),
        })?;
        let (ready, reached_ends, sdk_stubs) =
            prepare_sdk(&pe, &data, runtime.begin, placement, begin, &ends, options)?;
        let offset = usize::try_from(offset).map_err(|_| EmitError::Layout {
            rva: runtime.begin,
            reason: "the aligned SDK code offset does not fit the host address width".to_string(),
        })?;
        let padding = offset.checked_sub(code.len()).ok_or(EmitError::Layout {
            rva: runtime.begin,
            reason: "the aligned SDK code offset moved backwards".to_string(),
        })?;
        let additional = padding
            .checked_add(ready.bytes.len())
            .ok_or(EmitError::Layout {
                rva: runtime.begin,
                reason: "the appended SDK code length overflows the host address width".to_string(),
            })?;
        code.try_reserve(additional)
            .map_err(|_| allocation_error())?;
        pad_to(&mut code, offset);
        code.extend_from_slice(&ready.bytes);
        stubs.push(Stub::spanning(
            ready.protected.original,
            placement,
            begin.next.get() - ready.protected.original.get(),
        ));
        runtime_functions.push(ready.runtime_function);
        outcome.push(SdkMutation {
            begin: begin.call,
            function: runtime.begin,
            relocated: ready.protected.relocated,
            length: ready.protected.length,
            reached_ends,
            sdk_stubs,
            report: ready.protected.report,
        });
    }

    marker_name_references.sort_unstable();
    marker_name_references.dedup();
    let name_references = collect_image_references(view, &marker_name_references)?;
    let mut patched = data;
    for stub in &stubs {
        stub.write(&pe, &mut patched)?;
    }
    for patch in end_patches {
        apply_end_patch(&pe, &mut patched, patch)?;
    }
    for (rva, length) in &mut names_to_erase {
        *length = erasable_name_length(*rva, *length, &name_references);
    }
    names_to_erase.retain(|(_, length)| *length != 0);
    names_to_erase.sort_unstable();
    names_to_erase.dedup();
    for (rva, length) in names_to_erase {
        erase_sdk_name(&pe, &mut patched, rva, length)?;
    }
    let mut image = PeImage::from_bytes(patched)?;
    image.add_section(NewSection {
        name: &options.code_section,
        data: &code,
        characteristics: CODE_SECTION,
    })?;
    image.extend_exception_table(&options.pdata_section, &runtime_functions)?;
    Ok((image, outcome))
}

fn allocation_error() -> EmitError {
    EmitError::SdkMarker("memory allocation failed while preparing SDK protection".to_string())
}

fn sdk_name_length(image: Image<'_>, rva: Rva) -> Option<u32> {
    let payload = image.c_string_bytes(rva, MAX_SDK_NAME_LEN)?;
    u32::try_from(payload.len().checked_add(1)?).ok()
}

fn collect_image_references(
    image: Image<'_>,
    marker_references: &[Rva],
) -> Result<Vec<Rva>, EmitError> {
    let marker_extents = marker_reference_extents(image, marker_references)?;
    let mut references = Vec::new();
    for section in image
        .pe()
        .sections
        .iter()
        .filter(|section| section.permissions.execute)
    {
        let length = usize::try_from(section.size_of_raw_data).map_err(|_| EmitError::Layout {
            rva: section.virtual_address,
            reason: "executable section length exceeds the host address width".to_string(),
        })?;
        let bytes = image
            .bytes_from(section.virtual_address)
            .and_then(|bytes| bytes.get(..length))
            .ok_or(EmitError::Layout {
                rva: section.virtual_address,
                reason: "executable section bytes are not fully file-backed".to_string(),
            })?;
        for host_offset in 0..length {
            let offset = u32::try_from(host_offset).map_err(|_| EmitError::Layout {
                rva: section.virtual_address,
                reason: "executable scan offset exceeds the PE address width".to_string(),
            })?;
            let source = section
                .virtual_address
                .checked_add(offset)
                .ok_or(EmitError::Layout {
                    rva: section.virtual_address,
                    reason: "executable scan exceeds the PE address width".to_string(),
                })?;
            let extent = marker_extents.partition_point(|(_, end)| *end <= source);
            if marker_extents
                .get(extent)
                .is_some_and(|(start, _)| *start <= source)
            {
                continue;
            }
            let mut decoder = Decoder::with_ip(
                64,
                &bytes[host_offset..],
                u64::from(source.get()),
                DecoderOptions::NONE,
            );
            let raw = decoder.decode();
            let target = if raw.code() == Code::Lea_r64_m && raw.is_ip_rel_memory_operand() {
                u32::try_from(raw.ip_rel_memory_address()).ok().map(Rva)
            } else if matches!(raw.code(), Code::Mov_r64_imm64 | Code::Mov_r32_imm32) {
                let value = if raw.code() == Code::Mov_r64_imm64 {
                    raw.immediate64()
                } else {
                    u64::from(raw.immediate32())
                };
                let relative = value.checked_sub(image.image_base().get()).unwrap_or(value);
                u32::try_from(relative).ok().map(Rva)
            } else {
                None
            };
            if let Some(target) = target.filter(|target| image.is_mapped(*target)) {
                references.try_reserve(1).map_err(|_| allocation_error())?;
                references.push(target);
            }
        }
    }
    Ok(references)
}

fn marker_reference_extents(
    image: Image<'_>,
    marker_references: &[Rva],
) -> Result<Vec<(Rva, Rva)>, EmitError> {
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(marker_references.len())
        .map_err(|_| allocation_error())?;
    for source in marker_references {
        let bytes = image
            .bytes_from(*source)
            .ok_or_else(|| EmitError::SdkMarker(format!("name producer {source} is not mapped")))?;
        let mut decoder =
            Decoder::with_ip(64, bytes, u64::from(source.get()), DecoderOptions::NONE);
        let raw = decoder.decode();
        if raw.is_invalid()
            || !matches!(
                raw.code(),
                Code::Lea_r64_m | Code::Mov_r64_imm64 | Code::Mov_r32_imm32
            )
        {
            return Err(EmitError::SdkMarker(format!(
                "name producer {source} is not a supported materialization instruction"
            )));
        }
        let length = u32::try_from(raw.len()).map_err(|_| EmitError::Layout {
            rva: *source,
            reason: "name producer length exceeds the PE address width".to_string(),
        })?;
        let end = source.checked_add(length).ok_or(EmitError::Layout {
            rva: *source,
            reason: "name producer extent exceeds the PE address width".to_string(),
        })?;
        extents.push((*source, end));
    }
    extents.sort_unstable();
    let mut merged: Vec<(Rva, Rva)> = Vec::new();
    merged
        .try_reserve_exact(extents.len())
        .map_err(|_| allocation_error())?;
    for (start, end) in extents {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    Ok(merged)
}

fn erasable_name_length(name: Rva, length: u32, references: &[Rva]) -> u32 {
    let Some(end) = name.checked_add(length) else {
        return 0;
    };
    let mut erasable = length;
    for reference in references {
        if *reference < name || *reference >= end {
            continue;
        }
        if *reference == name {
            return 0;
        } else {
            erasable = erasable.min(reference.get() - name.get());
        }
    }
    erasable
}

fn erase_sdk_name(pe: &PeFile, data: &mut [u8], rva: Rva, length: u32) -> Result<(), EmitError> {
    pe.mapped_range(data, rva, length)?;
    let offset = usize::try_from(pe.rva_to_offset(rva)?.get()).map_err(|_| EmitError::Layout {
        rva,
        reason: "SDK marker name offset exceeds the host address width".to_string(),
    })?;
    let length = usize::try_from(length).map_err(|_| EmitError::Layout {
        rva,
        reason: "SDK marker name length exceeds the host address width".to_string(),
    })?;
    let end = offset.checked_add(length).ok_or(EmitError::Layout {
        rva,
        reason: "SDK marker name range overflows the host address width".to_string(),
    })?;
    data.get_mut(offset..end)
        .ok_or(EmitError::Layout {
            rva,
            reason: "SDK marker name is not file-backed".to_string(),
        })?
        .fill(0);
    Ok(())
}

fn end_patch(end: MarkerSite) -> Result<EndPatch, EmitError> {
    let (rva, fill) = if end.static_marker {
        (
            end.call.checked_add(2).ok_or(EmitError::Layout {
                rva: end.call,
                reason: "static SDK End payload exceeds the PE address width".to_string(),
            })?,
            0,
        )
    } else {
        (end.call, 0x90)
    };
    let length = end
        .next
        .get()
        .checked_sub(rva.get())
        .ok_or(EmitError::Layout {
            rva,
            reason: "SDK End patch range is inverted".to_string(),
        })?;
    Ok(if fill == 0 {
        EndPatch::StaticPayload { rva, length }
    } else {
        EndPatch::ApiSpan { rva, length }
    })
}

fn apply_end_patch(pe: &PeFile, data: &mut [u8], patch: EndPatch) -> Result<(), EmitError> {
    let (rva, length, fill) = match patch {
        EndPatch::StaticPayload { rva, length } => (rva, length, 0),
        EndPatch::ApiSpan { rva, length } => (rva, length, 0x90),
    };
    pe.mapped_range(data, rva, length)?;
    let offset = usize::try_from(pe.rva_to_offset(rva)?.get()).map_err(|_| EmitError::Layout {
        rva,
        reason: "SDK End patch offset exceeds the host address width".to_string(),
    })?;
    let length = usize::try_from(length).map_err(|_| EmitError::Layout {
        rva,
        reason: "SDK End patch length exceeds the host address width".to_string(),
    })?;
    let end = offset.checked_add(length).ok_or(EmitError::Layout {
        rva,
        reason: "SDK End patch range overflows the host address width".to_string(),
    })?;
    data.get_mut(offset..end)
        .ok_or(EmitError::Layout {
            rva,
            reason: "SDK End patch is not file-backed".to_string(),
        })?
        .fill(fill);
    Ok(())
}

fn code_offset(length: usize, rva: Rva) -> Result<u32, EmitError> {
    let length = u32::try_from(length).map_err(|_| EmitError::Layout {
        rva,
        reason: "the appended SDK code exceeds the PE address width".to_string(),
    })?;
    length
        .checked_add(FUNCTION_ALIGNMENT - 1)
        .map(|rounded| rounded / FUNCTION_ALIGNMENT * FUNCTION_ALIGNMENT)
        .ok_or(EmitError::Layout {
            rva,
            reason: "aligning the appended SDK code exceeds the PE address width".to_string(),
        })
}

fn validate_region_entries(
    function: &Function,
    begin_marker: Rva,
    entry: Rva,
    selected: &[Rva],
) -> Result<(), EmitError> {
    let epilogues = epilogues(function);
    let contains = |block: &BasicBlock, needle: Rva| {
        block
            .instructions
            .iter()
            .any(|instruction| instruction.rva() == Some(needle))
    };
    for block in &function.blocks {
        let Some(first_selected) = block.instructions.iter().position(|instruction| {
            instruction
                .rva()
                .is_some_and(|rva| selected.binary_search(&rva).is_ok())
        }) else {
            continue;
        };
        let is_entry_block = contains(block, entry);
        if first_selected != 0 {
            if is_entry_block
                && block.instructions[..first_selected]
                    .iter()
                    .any(|instruction| instruction.rva() == Some(begin_marker))
            {
                continue;
            }
            return Err(EmitError::SdkMarker(format!(
                "control flow enters SDK region block {} before its selected instructions",
                block.start
            )));
        }
        let complete_return_epilogue = function.architecture == vmp_types::Architecture::X64
            && block.terminator == Terminator::Return
            && block.instructions.iter().all(|instruction| {
                instruction
                    .rva()
                    .is_some_and(|rva| selected.binary_search(&rva).is_ok())
            })
            && epilogues
                .iter()
                .any(|epilogue| epilogue.begin == block.start && epilogue.end == block.end);
        for predecessor in &block.predecessors {
            let predecessor = function.blocks.get(predecessor.index()).ok_or_else(|| {
                EmitError::SdkMarker(format!(
                    "SDK region block {} has an invalid predecessor",
                    block.start
                ))
            })?;
            let predecessor_ends_selected = predecessor
                .instructions
                .last()
                .and_then(|instruction| instruction.rva())
                .is_some_and(|rva| selected.binary_search(&rva).is_ok());
            if predecessor_ends_selected
                || (is_entry_block && contains(predecessor, begin_marker))
                || complete_return_epilogue
            {
                continue;
            }
            return Err(EmitError::SdkMarker(format!(
                "control flow enters SDK region block {} without passing its Begin marker",
                block.start
            )));
        }
    }
    Ok(())
}

fn validate_register_marker_span(
    function: &Function,
    load: Rva,
    call: Rva,
) -> Result<(), EmitError> {
    let adjacent = function.blocks.iter().any(|block| {
        block.instructions.windows(2).any(|pair| {
            pair[0].rva() == Some(load)
                && pair[0].next_rva() == Some(call)
                && pair[1].rva() == Some(call)
        })
    });
    if adjacent {
        Ok(())
    } else {
        Err(EmitError::SdkMarker(format!(
            "SDK register marker load at {load} and call at {call} are not one straight-line span"
        )))
    }
}

fn build_region_slice(
    function: &Function,
    entry: Rva,
    selected: &[Rva],
    continuations: &[(Rva, Rva)],
) -> Result<Function, EmitError> {
    if selected.binary_search(&entry).is_err() {
        return Err(EmitError::SdkMarker(format!(
            "SDK region entry {entry} is not selected"
        )));
    }
    if selected.iter().any(|rva| *rva < entry) {
        return Err(EmitError::SdkMarker(
            "SDK region reaches code before its Begin continuation".to_string(),
        ));
    }

    let capacity = function
        .instruction_count()
        .checked_add(continuations.len())
        .ok_or_else(allocation_error)?;
    let mut retained: Vec<(Rva, usize, Instruction)> = Vec::new();
    retained
        .try_reserve(capacity)
        .map_err(|_| allocation_error())?;
    let mut retained_decoded = 0usize;
    let mut order = 0usize;
    for block in &function.blocks {
        let mut anchor = None;
        for instruction in &block.instructions {
            if let Some(rva) = instruction.rva() {
                if selected.binary_search(&rva).is_ok() {
                    order = order.checked_add(1).ok_or_else(allocation_error)?;
                    retained.push((rva, order, instruction.clone()));
                    anchor = Some(rva);
                    retained_decoded += 1;
                } else {
                    anchor = None;
                }
            } else if let Some(rva) = anchor {
                order = order.checked_add(1).ok_or_else(allocation_error)?;
                retained.push((rva, order, instruction.clone()));
            }
        }
    }
    if retained_decoded != selected.len() {
        return Err(EmitError::SdkMarker(
            "SDK region selection contains an undecoded instruction".to_string(),
        ));
    }

    for (marker, continuation) in continuations {
        let raw = RawInstruction::with_branch(Code::Jmp_rel32_64, u64::from(continuation.get()))
            .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
        let bytes = vmp_x86::encode_one(function.architecture, &raw, *marker)
            .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
        let decoded =
            Decoder::with_ip(64, &bytes, u64::from(marker.get()), DecoderOptions::NONE).decode();
        if decoded.is_invalid() || decoded.len() != 5 {
            return Err(EmitError::SdkMarker(format!(
                "SDK End bridge at {marker} did not encode as rel32"
            )));
        }
        order = order.checked_add(1).ok_or_else(allocation_error)?;
        retained.push((
            *marker,
            order,
            Instruction::decoded(*marker, decoded, &bytes),
        ));
    }
    retained.sort_by_key(|(rva, order, _)| (*rva, *order));
    let start = retained
        .first()
        .map(|(rva, _, _)| *rva)
        .ok_or_else(|| EmitError::SdkMarker("SDK region is empty".to_string()))?;
    let end = retained
        .iter()
        .rev()
        .find_map(|(_, _, instruction)| instruction.next_rva())
        .ok_or_else(|| EmitError::SdkMarker("SDK region end overflows".to_string()))?;
    let instructions = retained
        .into_iter()
        .map(|(_, _, instruction)| instruction)
        .collect();
    Ok(Function {
        architecture: function.architecture,
        entry,
        blocks: vec![BasicBlock {
            id: BlockId(0),
            start,
            end,
            instructions,
            terminator: Terminator::Halt,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }],
        entry_block: BlockId(0),
        unwind: None,
        issues: Vec::new(),
        stage: CompileStage::Decoded,
    })
}

fn patch_exit_bridges(
    relocated: &mut Relocated,
    continuations: &[(Rva, Rva)],
) -> Result<(), EmitError> {
    for (marker, continuation) in continuations {
        let moved = relocated.new_rva(*marker).ok_or_else(|| {
            EmitError::SdkMarker(format!("SDK End bridge at {marker} was not relocated"))
        })?;
        let len = relocated
            .instruction_len(vmp_types::Architecture::X64, *marker)
            .ok_or_else(|| {
                EmitError::SdkMarker(format!("SDK End bridge at {marker} cannot be measured"))
            })?;
        if len != 5 {
            return Err(EmitError::SdkMarker(format!(
                "SDK End bridge at {marker} relocated to {len} bytes"
            )));
        }
        let offset = relocated_offset(relocated, moved, len, *marker)?;
        let displacement = rel32(moved, 5, *continuation, *marker)?;
        relocated.bytes[offset] = 0xe9;
        relocated.bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
    }
    Ok(())
}

fn chainable_unwind(pe: &PeFile, data: &[u8], rva: Rva) -> Result<UnwindInfo, EmitError> {
    let first = UnwindInfo::parse(pe, data, rva)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    let mut current = first.clone();
    for _ in 0..=16 {
        validate_chainable_unwind_info(&current)?;
        if current.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            return Err(EmitError::SdkMarker(
                "covering function has language-specific unwind handlers".to_string(),
            ));
        }
        let Some(chained) = current.chained else {
            return Ok(first);
        };
        let target = UnwindInfo::parse(pe, data, chained.unwind_info)
            .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
        validate_chain_frame_state(&current, &target)?;
        current = target;
    }
    Err(EmitError::SdkMarker(
        "covering function unwind chain exceeds the supported depth".to_string(),
    ))
}

fn validate_chainable_unwind_info(unwind: &UnwindInfo) -> Result<(), EmitError> {
    if unwind.version != 1 {
        return Err(EmitError::SdkMarker(
            "covering function uses version-two location-dependent unwind metadata".to_string(),
        ));
    }
    Ok(())
}

fn validate_chain_frame_state(current: &UnwindInfo, target: &UnwindInfo) -> Result<(), EmitError> {
    if current.frame_register != target.frame_register
        || current.frame_offset != target.frame_offset
    {
        return Err(EmitError::SdkMarker(
            "covering function unwind chain changes frame-register state".to_string(),
        ));
    }
    Ok(())
}

fn chained_slice_unwind(original: &UnwindInfo, runtime: RuntimeFunction) -> UnwindInfo {
    UnwindInfo {
        version: 1,
        flags: UNW_FLAG_CHAININFO,
        size_of_prolog: 0,
        frame_register: original.frame_register,
        frame_offset: original.frame_offset,
        codes: Vec::new(),
        handler: None,
        chained: Some(runtime),
    }
}

fn prepare_sdk(
    pe: &PeFile,
    data: &[u8],
    entry: Rva,
    placement: Rva,
    begin: MarkerSite,
    ends: &[MarkerSite],
    options: &Options,
) -> Result<(Ready, Vec<Rva>, Vec<SdkStub>), EmitError> {
    let view = Image::new(pe, data);
    let mut function =
        decode_function(view, entry).map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    if !function.is_complete() {
        return Err(EmitError::SdkMarker(format!(
            "covering function {entry} is incomplete"
        )));
    }
    let unwind_range = function
        .unwind
        .ok_or(EmitError::SdkMarkerOutsideRuntimeFunction { rva: begin.call })?;
    if unwind_range.begin != entry {
        return Err(EmitError::SdkMarker(format!(
            "covering runtime function starts at {}, not {entry}",
            unwind_range.begin
        )));
    }
    let original_unwind = chainable_unwind(pe, data, unwind_range.unwind_info)?;
    let patch_from = begin.load.unwrap_or(begin.call);
    let prologue_end = entry
        .checked_add(u32::from(original_unwind.size_of_prolog))
        .ok_or(EmitError::Layout {
            rva: entry,
            reason: "covering prologue end exceeds the PE address width".to_string(),
        })?;
    if patch_from < prologue_end {
        return Err(EmitError::SdkMarker(
            "SDK Begin marker intersects the covering prologue".to_string(),
        ));
    }
    if !prologue_has_valid_boundary(&function, entry, original_unwind.size_of_prolog) {
        return Err(EmitError::SdkMarker(
            "covering unwind prologue ends inside an instruction".to_string(),
        ));
    }
    if let Some(load) = begin.load {
        validate_register_marker_span(&function, load, begin.call)?;
    }
    let marker_extent = begin.next.get().saturating_sub(patch_from.get());
    if marker_extent < STUB_LEN {
        return Err(EmitError::SdkMarker(format!(
            "SDK Begin marker at {} has only {marker_extent} byte(s) available for its jump",
            begin.call
        )));
    }
    let mut sdk_calls = discover_sdk_api_calls(view, &function)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;

    let mut end_starts = Vec::new();
    end_starts
        .try_reserve_exact(ends.len())
        .map_err(|_| allocation_error())?;
    end_starts.extend(ends.iter().map(|site| site.start()));
    let region = recover_marker_region_from(&function, begin.call, begin.next, &end_starts)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    sdk_calls.retain(|call| region.instructions.binary_search(&call.call_rva).is_ok());
    let selected = region.instructions;
    let mut insertion_points = Vec::new();
    insertion_points
        .try_reserve_exact(selected.len())
        .map_err(|_| allocation_error())?;
    insertion_points.extend_from_slice(&selected);
    let mut mutation_targets = Vec::new();
    mutation_targets
        .try_reserve_exact(selected.len())
        .map_err(|_| allocation_error())?;
    mutation_targets.extend_from_slice(&selected);
    let scope = MutationScope::exact(mutation_targets, insertion_points);
    let mut continuations = Vec::new();
    continuations
        .try_reserve_exact(region.reached_ends.len())
        .map_err(|_| allocation_error())?;
    for reached in &region.reached_ends {
        let site = ends
            .iter()
            .find(|site| site.start() == *reached)
            .ok_or_else(|| {
                EmitError::SdkMarker(format!("missing continuation for SDK End at {reached}"))
            })?;
        if let Some(load) = site.load {
            validate_register_marker_span(&function, load, site.call)?;
        }
        continuations.push((*reached, site.next));
    }
    validate_region_entries(&function, begin.call, begin.next, &selected)?;
    let mut reached_end_sites = Vec::new();
    reached_end_sites
        .try_reserve_exact(region.reached_ends.len())
        .map_err(|_| allocation_error())?;
    for reached in &region.reached_ends {
        let site = ends
            .iter()
            .find(|site| site.start() == *reached)
            .ok_or_else(|| EmitError::SdkMarker(format!("missing SDK End site at {reached}")))?;
        reached_end_sites.push((site.call, site.load));
    }
    neutralize_marker_calls(&mut function, begin.call, begin.load, &reached_end_sites)
        .map_err(|error| EmitError::SdkMarker(error.to_string()))?;

    let mut frozen = Frozen::new();
    let epilogues = epilogues(&function);
    let mut selected_epilogues = Vec::new();
    selected_epilogues
        .try_reserve_exact(epilogues.len())
        .map_err(|_| allocation_error())?;
    for epilogue in &epilogues {
        let epilogue_instructions: Vec<_> = function
            .instructions()
            .filter_map(|instruction| instruction.rva())
            .filter(|rva| *rva >= epilogue.begin && *rva < epilogue.end)
            .collect();
        let selected_count = epilogue_instructions
            .iter()
            .filter(|rva| selected.binary_search(rva).is_ok())
            .count();
        if selected_count != 0 && selected_count != epilogue_instructions.len() {
            return Err(EmitError::SdkMarker(format!(
                "SDK region partially intersects epilogue {}..{}",
                epilogue.begin, epilogue.end
            )));
        }
        if selected_count != 0 {
            selected_epilogues.push(*epilogue);
        }
        frozen.freeze(epilogue.begin, epilogue.end);
    }
    let report = mutate_scoped(
        &mut function,
        &frozen,
        &scope,
        options.seed,
        &options.mutation,
    )
    .map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    if report.is_noop() {
        return Err(EmitError::SdkMarker(
            "selected SDK region admitted no mutation for this seed".to_string(),
        ));
    }

    let slice = build_region_slice(&function, begin.next, &selected, &continuations)?;
    if has_absolute_fixups(&slice) {
        return Err(EmitError::SdkMarker(
            "selected SDK region has absolute fixups".to_string(),
        ));
    }
    let mut relocated =
        relocate(&slice, placement).map_err(|error| EmitError::SdkMarker(error.to_string()))?;
    patch_exit_bridges(&mut relocated, &continuations)?;
    if !crate::epilogues_kept_their_shape(&function, &relocated, &selected_epilogues) {
        return Err(EmitError::SdkMarker(
            "relocated SDK epilogue changed shape".to_string(),
        ));
    }
    let length = u32::try_from(relocated.bytes.len()).map_err(|_| EmitError::Layout {
        rva: entry,
        reason: "relocated SDK function length exceeds the PE address width".to_string(),
    })?;
    let end = placement.checked_add(length).ok_or(EmitError::Layout {
        rva: entry,
        reason: "relocated SDK function end exceeds the PE address width".to_string(),
    })?;
    let sdk_stubs = install_sdk_stubs(&mut relocated, &sdk_calls, end)?;
    let reached_ends = region
        .reached_ends
        .iter()
        .filter_map(|reached| {
            ends.iter()
                .find(|site| site.start() == *reached)
                .map(|site| site.call)
        })
        .collect();
    let unwind = chained_slice_unwind(
        &original_unwind,
        RuntimeFunction {
            begin: unwind_range.begin,
            end: unwind_range.end,
            unwind_info: unwind_range.unwind_info,
        },
    );
    Ok((
        Ready {
            runtime_function: NewFunction {
                begin: placement,
                end,
                unwind,
            },
            protected: Protected {
                original: patch_from,
                relocated: placement,
                length,
                report,
            },
            bytes: relocated.bytes,
        },
        reached_ends,
        sdk_stubs,
    ))
}

fn install_sdk_stubs(
    relocated: &mut Relocated,
    calls: &[SdkApiCall],
    first_stub: Rva,
) -> Result<Vec<SdkStub>, EmitError> {
    let mut stubs = Vec::new();
    stubs
        .try_reserve(calls.len())
        .map_err(|_| allocation_error())?;
    let mut bytes = Vec::new();
    for call in calls {
        if stubs.iter().any(|stub: &SdkStub| stub.api == call.api) {
            continue;
        }
        let offset = u32::try_from(bytes.len()).map_err(|_| EmitError::Layout {
            rva: call.call_rva,
            reason: "SDK fallback stubs exceed the PE address width".to_string(),
        })?;
        let rva = first_stub.checked_add(offset).ok_or(EmitError::Layout {
            rva: call.call_rva,
            reason: "SDK fallback stub address exceeds the PE address width".to_string(),
        })?;
        let body = sdk_stub_bytes(call.api);
        bytes
            .try_reserve(body.len())
            .map_err(|_| allocation_error())?;
        bytes.extend_from_slice(body);
        stubs.push(SdkStub { api: call.api, rva });
    }
    for call in calls {
        let stub = stubs
            .iter()
            .find(|stub| stub.api == call.api)
            .ok_or_else(|| EmitError::SdkMarker("missing SDK fallback stub".to_string()))?;
        patch_sdk_call(relocated, *call, stub.rva)?;
    }
    relocated
        .bytes
        .try_reserve(bytes.len())
        .map_err(|_| allocation_error())?;
    relocated.bytes.extend_from_slice(&bytes);
    Ok(stubs)
}

fn sdk_stub_bytes(api: SdkApi) -> &'static [u8] {
    match api {
        // MS x64: return the first pointer argument unchanged.
        SdkApi::DecryptStringA | SdkApi::DecryptStringW => &[0x48, 0x89, 0xc8, 0xc3],
        SdkApi::FreeString => &[0x31, 0xc0, 0xc3],
        SdkApi::IsProtected => &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
    }
}

fn patch_sdk_call(
    relocated: &mut Relocated,
    call: SdkApiCall,
    target: Rva,
) -> Result<(), EmitError> {
    if let Some(load) = call.load_rva {
        let moved = relocated.new_rva(load).ok_or_else(|| {
            EmitError::SdkMarker(format!("SDK register load at {load} was not relocated"))
        })?;
        let len = relocated
            .instruction_len(vmp_types::Architecture::X64, load)
            .ok_or_else(|| {
                EmitError::SdkMarker(format!("SDK register load at {load} cannot be measured"))
            })?;
        if len != 7 {
            return Err(EmitError::SdkMarker(format!(
                "SDK register load at {load} relocated to an unexpected {len}-byte encoding"
            )));
        }
        let offset = relocated_offset(relocated, moved, len, load)?;
        let displacement = rel32(moved, 7, target, load)?;
        let encoded = &mut relocated.bytes[offset..offset + len];
        if encoded[0] & 0xf8 != 0x48 || encoded[1] != 0x8b || encoded[2] & 0xc7 != 0x05 {
            return Err(EmitError::SdkMarker(format!(
                "SDK register load at {load} no longer has canonical RIP-relative mov encoding"
            )));
        }
        encoded[1] = 0x8d;
        encoded[3..7].copy_from_slice(&displacement.to_le_bytes());
        return Ok(());
    }

    let moved = relocated.new_rva(call.call_rva).ok_or_else(|| {
        EmitError::SdkMarker(format!("SDK call at {} was not relocated", call.call_rva))
    })?;
    let len = relocated
        .instruction_len(vmp_types::Architecture::X64, call.call_rva)
        .ok_or_else(|| {
            EmitError::SdkMarker(format!("SDK call at {} cannot be measured", call.call_rva))
        })?;
    if !(5..=6).contains(&len) {
        return Err(EmitError::SdkMarker(format!(
            "SDK call at {} relocated to an unexpected {len}-byte encoding",
            call.call_rva
        )));
    }
    let offset = relocated_offset(relocated, moved, len, call.call_rva)?;
    let displacement = rel32(moved, 5, target, call.call_rva)?;
    relocated.bytes[offset] = if call.tail_call { 0xe9 } else { 0xe8 };
    relocated.bytes[offset + 1..offset + 5].copy_from_slice(&displacement.to_le_bytes());
    relocated.bytes[offset + 5..offset + len].fill(0x90);
    Ok(())
}

fn relocated_offset(
    relocated: &Relocated,
    moved: Rva,
    len: usize,
    original: Rva,
) -> Result<usize, EmitError> {
    let offset = moved
        .get()
        .checked_sub(relocated.rva.get())
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| EmitError::SdkMarker(format!("relocated SDK site {original} underflows")))?;
    let end = offset.checked_add(len).ok_or_else(|| {
        EmitError::SdkMarker(format!("relocated SDK site {original} length overflows"))
    })?;
    if end > relocated.bytes.len() {
        return Err(EmitError::SdkMarker(format!(
            "relocated SDK site {original} lies outside the encoded function"
        )));
    }
    Ok(offset)
}

fn rel32(from: Rva, instruction_len: u32, target: Rva, original: Rva) -> Result<i32, EmitError> {
    let next = from.checked_add(instruction_len).ok_or(EmitError::Layout {
        rva: original,
        reason: "SDK call next address exceeds the PE address width".to_string(),
    })?;
    i32::try_from(i64::from(target.get()) - i64::from(next.get())).map_err(|_| EmitError::Layout {
        rva: original,
        reason: "SDK fallback stub is outside rel32 range".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn nop(rva: Rva) -> Instruction {
        let raw =
            Decoder::with_ip(64, &[0x90], u64::from(rva.get()), DecoderOptions::NONE).decode();
        Instruction::decoded(rva, raw, &[0x90])
    }

    fn decode(rva: Rva, bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(64, bytes, u64::from(rva.get()), DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let offset = usize::try_from(raw.ip() - u64::from(rva.get()))
                .expect("test instruction offset fits");
            instructions.push(Instruction::decoded(
                Rva(u32::try_from(raw.ip()).expect("test RVA fits")),
                raw,
                &bytes[offset..offset + raw.len()],
            ));
        }
        instructions
    }

    #[test]
    fn code_offset_rejects_lengths_above_the_pe_address_width() {
        assert!(matches!(
            code_offset(usize::MAX, Rva(0x1000)),
            Err(EmitError::Layout {
                rva: Rva(0x1000),
                ..
            })
        ));
        assert!(matches!(
            code_offset(u32::MAX as usize, Rva(0x2000)),
            Err(EmitError::Layout {
                rva: Rva(0x2000),
                ..
            })
        ));
    }

    #[test]
    fn region_validation_rejects_an_external_predecessor() {
        let function = Function {
            architecture: vmp_types::Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    start: Rva(0x1000),
                    end: Rva(0x1001),
                    instructions: vec![nop(Rva(0x1000))],
                    terminator: Terminator::Jump,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
                BasicBlock {
                    id: BlockId(1),
                    start: Rva(0x2000),
                    end: Rva(0x2001),
                    instructions: vec![nop(Rva(0x2000))],
                    terminator: Terminator::Return,
                    successors: Vec::new(),
                    predecessors: vec![BlockId(0), BlockId(2)],
                },
                BasicBlock {
                    id: BlockId(2),
                    start: Rva(0x3000),
                    end: Rva(0x3001),
                    instructions: vec![nop(Rva(0x3000))],
                    terminator: Terminator::Jump,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
            ],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        };
        let error = validate_region_entries(&function, Rva(0x1000), Rva(0x2000), &[Rva(0x2000)])
            .expect_err("the second predecessor bypasses the Begin marker");
        assert!(matches!(error, EmitError::SdkMarker(_)));
    }

    #[test]
    fn region_validation_accepts_a_shared_complete_return_epilogue() {
        let function = Function {
            architecture: vmp_types::Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    start: Rva(0x1000),
                    end: Rva(0x1002),
                    instructions: vec![nop(Rva(0x1000)), nop(Rva(0x1001))],
                    terminator: Terminator::Jump,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
                BasicBlock {
                    id: BlockId(1),
                    start: Rva(0x2000),
                    end: Rva(0x2005),
                    instructions: decode(Rva(0x2000), &[0x48, 0x83, 0xc4, 0x28, 0xc3]),
                    terminator: Terminator::Return,
                    successors: Vec::new(),
                    predecessors: vec![BlockId(0), BlockId(2)],
                },
                BasicBlock {
                    id: BlockId(2),
                    start: Rva(0x3000),
                    end: Rva(0x3001),
                    instructions: vec![nop(Rva(0x3000))],
                    terminator: Terminator::Jump,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
            ],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        };

        validate_region_entries(
            &function,
            Rva(0x1000),
            Rva(0x1001),
            &[Rva(0x1001), Rva(0x2000), Rva(0x2004)],
        )
        .expect("a complete shared return epilogue remains safe for external predecessors");
    }

    #[test]
    fn region_validation_rejects_a_continuation_backedge() {
        let mut function = Function {
            architecture: vmp_types::Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    start: Rva(0x1000),
                    end: Rva(0x1001),
                    instructions: vec![nop(Rva(0x1000))],
                    terminator: Terminator::FallThrough,
                    successors: vec![vmp_ir::Edge::new(
                        vmp_ir::EdgeKind::FallThrough,
                        vmp_ir::EdgeTarget::Block(BlockId(1)),
                    )],
                    predecessors: Vec::new(),
                },
                BasicBlock {
                    id: BlockId(1),
                    start: Rva(0x2000),
                    end: Rva(0x2001),
                    instructions: vec![nop(Rva(0x2000))],
                    terminator: Terminator::Return,
                    successors: Vec::new(),
                    predecessors: vec![BlockId(0), BlockId(2)],
                },
                BasicBlock {
                    id: BlockId(2),
                    start: Rva(0x3000),
                    end: Rva(0x3001),
                    instructions: vec![nop(Rva(0x3000))],
                    terminator: Terminator::Jump,
                    successors: vec![vmp_ir::Edge::new(
                        vmp_ir::EdgeKind::Jump,
                        vmp_ir::EdgeTarget::Block(BlockId(1)),
                    )],
                    predecessors: Vec::new(),
                },
            ],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        };
        function.blocks[0].instructions.push(nop(Rva(0x1001)));
        let error = validate_region_entries(&function, Rva(0x1000), Rva(0x2000), &[Rva(0x2000)])
            .expect_err("an End continuation must not re-enter selected code");
        assert!(matches!(error, EmitError::SdkMarker(_)));
    }

    #[test]
    fn register_marker_span_rejects_an_interior_block_entry() {
        let function = Function {
            architecture: vmp_types::Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    start: Rva(0x1000),
                    end: Rva(0x1001),
                    instructions: vec![nop(Rva(0x1000))],
                    terminator: Terminator::FallThrough,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
                BasicBlock {
                    id: BlockId(1),
                    start: Rva(0x1001),
                    end: Rva(0x1002),
                    instructions: vec![nop(Rva(0x1001))],
                    terminator: Terminator::Return,
                    successors: Vec::new(),
                    predecessors: vec![BlockId(0), BlockId(2)],
                },
            ],
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        };
        let error = validate_register_marker_span(&function, Rva(0x1000), Rva(0x1001))
            .expect_err("the call is a separately addressable block entry");
        assert!(matches!(error, EmitError::SdkMarker(_)));
    }

    #[test]
    fn version_two_unwind_is_not_chainable_for_a_relocated_slice() {
        let mut unwind = UnwindInfo::leaf();
        unwind.version = 2;
        let error = validate_chainable_unwind_info(&unwind)
            .expect_err("version-two epilogue metadata is location-dependent");
        assert!(matches!(error, EmitError::SdkMarker(_)));
    }

    #[test]
    fn chained_slice_unwind_preserves_the_original_frame_state() {
        let mut original = UnwindInfo::leaf();
        original.frame_register = 5;
        original.frame_offset = 3;
        let runtime = RuntimeFunction {
            begin: Rva(0x1000),
            end: Rva(0x1100),
            unwind_info: Rva(0x2000),
        };
        let chained = chained_slice_unwind(&original, runtime);
        assert_eq!(chained.frame_register, 5);
        assert_eq!(chained.frame_offset, 3);
        assert_eq!(chained.chained, Some(runtime));
    }

    #[test]
    fn named_marker_payload_is_erased_in_the_candidate_image() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let offset = pe
            .rva_to_offset(Rva(0x72c8))
            .expect("marker name is file-backed")
            .get() as usize;
        let following = data[offset + 12];
        erase_sdk_name(&pe, &mut data, Rva(0x72c8), 12).expect("name erasure must succeed");
        assert_eq!(&data[offset..offset + 12], &[0; 12]);
        assert_eq!(data[offset + 12], following);
    }

    #[test]
    fn cpp_corpus_name_reference_scan_keeps_the_full_unshared_extent() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let data = std::fs::read(path).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let references = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027)])
            .expect("reference scan must not allocate-fail");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &references), 12);
    }

    #[test]
    fn executable_reference_scan_includes_code_outside_pdata() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let table = pe
            .exception_table
            .as_ref()
            .expect("x64 corpus has an exception table");
        let source = pe
            .sections
            .iter()
            .filter(|section| section.permissions.execute)
            .flat_map(|section| {
                (0..section.size_of_raw_data.saturating_sub(7))
                    .filter_map(move |offset| section.virtual_address.checked_add(offset))
            })
            .find(|candidate| {
                let end = candidate.checked_add(7);
                end.is_some_and(|end| {
                    table
                        .functions()
                        .all(|function| end <= function.begin || *candidate >= function.end)
                })
            })
            .expect("fixture must have seven executable bytes outside pdata");
        let target = Rva(0x72ce);
        let next = source.checked_add(7).expect("test instruction fits");
        let displacement = i64::from(target.get()) - i64::from(next.get());
        let displacement = i32::try_from(displacement).expect("test target fits rel32");
        let offset = pe
            .rva_to_offset(source)
            .expect("test instruction is file-backed")
            .get() as usize;
        data[offset..offset + 7].copy_from_slice(&[0x48, 0x8d, 0x05, 0, 0, 0, 0]);
        data[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
        let pe = PeFile::parse(&data).expect("adapted corpus reparses");
        let references = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027)])
            .expect("reference scan succeeds");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &references), 6);
    }

    #[test]
    fn executable_reference_scan_includes_mov_ecx_imm32_outside_pdata() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let table = pe.exception_table.as_ref().expect("fixture has pdata");
        let source = pe
            .sections
            .iter()
            .filter(|section| section.permissions.execute)
            .flat_map(|section| {
                (0..section.size_of_raw_data.saturating_sub(5))
                    .filter_map(move |offset| section.virtual_address.checked_add(offset))
            })
            .find(|candidate| {
                candidate.checked_add(5).is_some_and(|end| {
                    table
                        .functions()
                        .all(|function| end <= function.begin || *candidate >= function.end)
                })
            })
            .expect("fixture has executable bytes outside pdata");
        let offset = pe
            .rva_to_offset(source)
            .expect("test instruction is file-backed")
            .get() as usize;
        data[offset] = 0xb9;
        data[offset + 1..offset + 5].copy_from_slice(&0x72c8_u32.to_le_bytes());
        let pe = PeFile::parse(&data).expect("adapted corpus reparses");
        let references = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027)])
            .expect("reference scan succeeds");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &references), 0);
    }

    #[test]
    fn non_utf8_cpp_marker_name_still_has_a_bounded_extent() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required corpus reads");
        let pe = PeFile::parse(&data).expect("required corpus parses");
        let offset = pe
            .rva_to_offset(Rva(0x72c8))
            .expect("marker name is file-backed")
            .get() as usize;
        data[offset] = 0xff;
        let pe = PeFile::parse(&data).expect("adapted corpus reparses");
        let image = Image::new(&pe, &data);
        assert_eq!(sdk_name_length(image, Rva(0x72c8)), Some(12));
        assert_eq!(image.utf8_c_string(Rva(0x72c8), MAX_SDK_NAME_LEN), None);
    }

    #[test]
    fn cpp_marker_name_erasure_stops_at_an_interior_reference() {
        assert_eq!(erasable_name_length(Rva(0x2000), 13, &[Rva(0x2006)]), 6);
    }

    #[test]
    fn cpp_marker_name_erasure_is_suppressed_by_an_ordinary_start_reference() {
        assert_eq!(erasable_name_length(Rva(0x2000), 13, &[Rva(0x2000)]), 0);
    }

    #[test]
    fn cpp_marker_name_erasure_keeps_the_full_unshared_extent() {
        assert_eq!(erasable_name_length(Rva(0x2000), 13, &[]), 13);
    }

    #[test]
    fn two_marker_reference_sources_do_not_suppress_shared_name_erasure() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let table = pe.exception_table.as_ref().expect("fixture has pdata");
        let source = pe
            .sections
            .iter()
            .filter(|section| section.permissions.execute)
            .flat_map(|section| {
                (0..section.size_of_raw_data.saturating_sub(7))
                    .filter_map(move |offset| section.virtual_address.checked_add(offset))
            })
            .find(|candidate| {
                candidate.checked_add(7).is_some_and(|end| {
                    table
                        .functions()
                        .all(|function| end <= function.begin || *candidate >= function.end)
                })
            })
            .expect("fixture has executable bytes outside pdata");
        let next = source.checked_add(7).expect("test instruction fits");
        let displacement = i64::from(0x72c8) - i64::from(next.get());
        let displacement = i32::try_from(displacement).expect("test target fits rel32");
        let offset = pe
            .rva_to_offset(source)
            .expect("test instruction is file-backed")
            .get() as usize;
        data[offset..offset + 7].copy_from_slice(&[0x48, 0x8d, 0x05, 0, 0, 0, 0]);
        data[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
        let pe = PeFile::parse(&data).expect("adapted corpus reparses");

        let ordinary = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027)])
            .expect("ordinary reference scan succeeds");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &ordinary), 0);
        let marker_only = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027), source])
            .expect("marker-only reference scan succeeds");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &marker_only), 12);
    }

    #[test]
    fn mov_rcx_imm64_marker_extent_excludes_overlapping_mov_ecx_decode() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(path).expect("required SDK corpus must read");
        let pe_header = u32::from_le_bytes(
            data[0x3c..0x40]
                .try_into()
                .expect("DOS header contains e_lfanew"),
        ) as usize;
        let image_base_offset = pe_header + 4 + 20 + 24;
        data[image_base_offset..image_base_offset + 8]
            .copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        let pe = PeFile::parse(&data).expect("low-base corpus parses");
        let offset = pe
            .rva_to_offset(Rva(0x1027))
            .expect("name producer is file-backed")
            .get() as usize;
        let name_va = pe
            .optional
            .image_base
            .get()
            .checked_add(u64::from(0x72c8_u32))
            .expect("name VA fits");
        data[offset..offset + 2].copy_from_slice(&[0x48, 0xb9]);
        data[offset + 2..offset + 10].copy_from_slice(&name_va.to_le_bytes());
        data[offset + 10..offset + 12].fill(0x90);
        let pe = PeFile::parse(&data).expect("adapted low-base corpus reparses");
        let references = collect_image_references(Image::new(&pe, &data), &[Rva(0x1027)])
            .expect("reference scan succeeds");
        assert_eq!(erasable_name_length(Rva(0x72c8), 12, &references), 12);
    }

    #[test]
    fn chained_unwind_rejects_a_frame_state_mismatch() {
        let mut current = UnwindInfo::leaf();
        current.frame_register = 5;
        current.frame_offset = 3;
        let target = UnwindInfo::leaf();
        let error = validate_chain_frame_state(&current, &target)
            .expect_err("one established frame must be consistent across the chain");
        assert!(matches!(error, EmitError::SdkMarker(_)));
    }

    #[test]
    fn register_end_patch_preserves_the_iat_load_and_neutralizes_only_the_call() {
        assert_eq!(
            end_patch(MarkerSite {
                load: Some(Rva(0x1000)),
                call: Rva(0x1007),
                next: Rva(0x1009),
                static_marker: false,
            })
            .expect("valid End patch"),
            EndPatch::ApiSpan {
                rva: Rva(0x1007),
                length: 2,
            }
        );
    }
}
