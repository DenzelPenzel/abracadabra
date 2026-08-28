//! Control-flow region selected by one SDK Begin marker and all reachable Ends.

use iced_x86::{Code, Instruction as RawInstruction};
use vmp_ir::{BlockId, EdgeTarget, Function};
use vmp_types::Rva;

use crate::encode_one;

/// Instructions selected for mutation between one Begin and its reachable Ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerRegion {
    /// Mutation-eligible original instruction addresses, in address order.
    pub instructions: Vec<Rva>,
    /// End-call addresses reached from this Begin, in address order.
    pub reached_ends: Vec<Rva>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MarkerRegionError {
    #[error("Begin call at {rva} is not a decoded instruction")]
    BeginNotDecoded { rva: Rva },
    #[error("Begin call at {rva} has no following instruction")]
    BeginHasNoContinuation { rva: Rva },
    #[error("no End marker is reachable from Begin at {begin}")]
    NoReachableEnd { begin: Rva },
    #[error("marker-region resource accounting overflowed")]
    ResourceOverflow,
    #[error("memory allocation failed while analysing the marker region")]
    AllocationFailed,
    #[error("marker call at {rva} could not be encoded as a NOP: {reason}")]
    NeutralizationEncode { rva: Rva, reason: String },
}

/// Recovers the instruction region controlled by one SDK Begin call.
pub fn recover_marker_region(
    function: &Function,
    begin_call: Rva,
    end_calls: &[Rva],
) -> Result<MarkerRegion, MarkerRegionError> {
    let (begin_block, begin_index) = locate(function, begin_call)
        .ok_or(MarkerRegionError::BeginNotDecoded { rva: begin_call })?;
    let begin_instruction = function
        .block(begin_block)
        .and_then(|block| block.instructions.get(begin_index))
        .ok_or(MarkerRegionError::BeginNotDecoded { rva: begin_call })?;
    let start_rva = begin_instruction
        .next_rva()
        .ok_or(MarkerRegionError::BeginHasNoContinuation { rva: begin_call })?;
    recover_marker_region_from(function, begin_call, start_rva, end_calls)
}

/// Recovers a marker region when the marker's physical extent is larger than
/// its decoded control-transfer instruction, as with the static assembly form.
pub fn recover_marker_region_from(
    function: &Function,
    begin_marker: Rva,
    start_rva: Rva,
    end_markers: &[Rva],
) -> Result<MarkerRegion, MarkerRegionError> {
    locate(function, begin_marker)
        .ok_or(MarkerRegionError::BeginNotDecoded { rva: begin_marker })?;
    let start = locate(function, start_rva)
        .ok_or(MarkerRegionError::BeginHasNoContinuation { rva: begin_marker })?;

    let mut ends = Vec::new();
    ends.try_reserve_exact(end_markers.len())
        .map_err(|_| MarkerRegionError::AllocationFailed)?;
    ends.extend_from_slice(end_markers);
    ends.sort_unstable();
    ends.dedup();
    // Ends belonging to another function are not malformed input;
    // they are simply irrelevant to this region recovery.
    ends.retain(|&end| locate(function, end).is_some());

    let mut block_offsets = Vec::new();
    block_offsets
        .try_reserve_exact(function.blocks.len().saturating_add(1))
        .map_err(|_| MarkerRegionError::AllocationFailed)?;
    let mut instruction_count = 0usize;
    for block in &function.blocks {
        block_offsets.push(instruction_count);
        instruction_count = instruction_count
            .checked_add(block.instructions.len())
            .ok_or(MarkerRegionError::ResourceOverflow)?;
    }
    block_offsets.push(instruction_count);

    let mut visited = Vec::new();
    visited
        .try_reserve_exact(instruction_count)
        .map_err(|_| MarkerRegionError::AllocationFailed)?;
    visited.resize(instruction_count, false);
    let mut work = Vec::new();
    push_work(&mut work, start)?;
    let mut instructions = Vec::new();
    let mut reached_ends = Vec::new();

    while let Some((block_id, instruction_index)) = work.pop() {
        let block = function
            .block(block_id)
            .ok_or(MarkerRegionError::ResourceOverflow)?;
        let global_index = block_offsets
            .get(block_id.index())
            .and_then(|offset| offset.checked_add(instruction_index))
            .ok_or(MarkerRegionError::ResourceOverflow)?;
        let seen = visited
            .get_mut(global_index)
            .ok_or(MarkerRegionError::ResourceOverflow)?;
        if *seen {
            continue;
        }
        *seen = true;
        let instruction = block
            .instructions
            .get(instruction_index)
            .ok_or(MarkerRegionError::ResourceOverflow)?;
        let rva = instruction
            .rva()
            .ok_or(MarkerRegionError::ResourceOverflow)?;

        if ends.binary_search(&rva).is_ok() {
            reached_ends
                .try_reserve(1)
                .map_err(|_| MarkerRegionError::AllocationFailed)?;
            reached_ends.push(rva);
            continue;
        }
        instructions
            .try_reserve(1)
            .map_err(|_| MarkerRegionError::AllocationFailed)?;
        instructions.push(rva);

        if instruction_index + 1 < block.instructions.len() {
            push_work(&mut work, (block_id, instruction_index + 1))?;
            continue;
        }
        // A return or a branch out of the decoded function stays in the marker function; only paths
        // that actually reach an End are cut there by ParseEndCommands.
        for edge in &block.successors {
            if let EdgeTarget::Block(target) = edge.target {
                push_work(&mut work, (target, 0))?;
            }
        }
    }

    if reached_ends.is_empty() {
        return Err(MarkerRegionError::NoReachableEnd {
            begin: begin_marker,
        });
    }
    instructions.sort_unstable();
    instructions.dedup();
    reached_ends.sort_unstable();
    reached_ends.dedup();
    Ok(MarkerRegion {
        instructions,
        reached_ends,
    })
}

/// Replaces the selected Begin load/call and reached End load/calls with native NOPs.
pub fn neutralize_marker_calls(
    function: &mut Function,
    begin_call: Rva,
    begin_load: Option<Rva>,
    reached_ends: &[(Rva, Option<Rva>)],
) -> Result<(), MarkerRegionError> {
    let architecture = function.architecture;
    for block in &mut function.blocks {
        for instruction in &mut block.instructions {
            let Some(rva) = instruction.rva() else {
                continue;
            };
            let selected = rva == begin_call
                || begin_load == Some(rva)
                || reached_ends
                    .iter()
                    .any(|(call, load)| *call == rva || *load == Some(rva));
            if !selected {
                continue;
            }
            let raw = RawInstruction::with(Code::Nopd);
            let bytes = encode_one(architecture, &raw, rva).map_err(|error| {
                MarkerRegionError::NeutralizationEncode {
                    rva,
                    reason: error.to_string(),
                }
            })?;
            instruction.replace(raw, &bytes);
        }
    }
    Ok(())
}

fn locate(function: &Function, rva: Rva) -> Option<(BlockId, usize)> {
    function.blocks.iter().find_map(|block| {
        block
            .instructions
            .iter()
            .position(|instruction| instruction.rva() == Some(rva))
            .map(|index| (block.id, index))
    })
}

fn push_work(
    work: &mut Vec<(BlockId, usize)>,
    item: (BlockId, usize),
) -> Result<(), MarkerRegionError> {
    work.try_reserve(1)
        .map_err(|_| MarkerRegionError::AllocationFailed)?;
    work.push(item);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::sdk_markers::{discover_direct_api_markers, ApiMarker};
    use crate::{decode_function, Image};
    use vmp_pe::PeFile;

    fn required_fixture() -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vmp-pe")
            .join("test-corpus")
            .join("win64-app-msvc-amd64");
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()))
    }

    #[test]
    fn neutralizes_only_selected_marker_loads_and_calls() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let mut function =
            decode_function(image, Rva(0x1000)).expect("covering function must decode");
        let addresses: Vec<_> = function
            .instructions()
            .filter_map(|instruction| instruction.rva())
            .collect();
        let previous = |call| {
            addresses
                .iter()
                .copied()
                .filter(|rva| *rva < call)
                .max()
                .expect("marker call must have a preceding instruction")
        };
        let begin_call = Rva(0x1033);
        let reached_end = Rva(0x10f9);
        let unreachable_end = Rva(0x1143);
        let begin_load = previous(begin_call);
        let reached_load = previous(reached_end);
        let unreachable_load = previous(unreachable_end);

        neutralize_marker_calls(
            &mut function,
            begin_call,
            Some(begin_load),
            &[(reached_end, Some(reached_load))],
        )
        .expect("selected marker sites must neutralize");

        for selected in [begin_load, begin_call, reached_load, reached_end] {
            assert_eq!(
                function
                    .instructions()
                    .find(|instruction| instruction.rva() == Some(selected))
                    .expect("selected instruction remains present")
                    .raw()
                    .code(),
                Code::Nopd
            );
        }
        for unselected in [unreachable_load, unreachable_end] {
            assert_ne!(
                function
                    .instructions()
                    .find(|instruction| instruction.rva() == Some(unselected))
                    .expect("unselected instruction remains present")
                    .raw()
                    .code(),
                Code::Nopd
            );
        }
    }

    #[test]
    fn one_begin_reaches_both_cpp_corpus_end_paths() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let markers = discover_direct_api_markers(image).expect("markers must scan");
        let begin = markers
            .iter()
            .find_map(|marker| match marker {
                ApiMarker::Begin { call_rva, .. } => Some(*call_rva),
                ApiMarker::End { .. } => None,
            })
            .expect("fixture must contain Begin");
        let ends: Vec<Rva> = markers
            .iter()
            .filter_map(|marker| match marker {
                ApiMarker::End { call_rva, .. } => Some(*call_rva),
                ApiMarker::Begin { .. } => None,
            })
            .chain(std::iter::once(Rva(0xdead_beef)))
            .collect();
        let mut function =
            decode_function(image, Rva(0x1000)).expect("covering function must decode");

        let region = recover_marker_region(&function, begin, &ends)
            .expect("both branches must terminate at SDK End calls");
        assert_eq!(region.reached_ends, vec![Rva(0x10f9), Rva(0x1143)]);
        assert!(!region.instructions.contains(&begin));
        assert!(!region.instructions.contains(&Rva(0x10f9)));
        assert!(!region.instructions.contains(&Rva(0x1143)));
        assert_eq!(region.instructions.first(), Some(&Rva(0x1039)));

        let reached_end_sites: Vec<_> = region
            .reached_ends
            .iter()
            .copied()
            .map(|rva| (rva, None))
            .collect();
        neutralize_marker_calls(&mut function, begin, None, &reached_end_sites)
            .expect("marker calls must neutralize");
        let neutralized: Vec<Rva> = function
            .instructions()
            .filter(|instruction| instruction.raw().code() == Code::Nopd)
            .filter_map(|instruction| instruction.rva())
            .filter(|rva| *rva == begin || region.reached_ends.binary_search(rva).is_ok())
            .collect();
        assert_eq!(neutralized, vec![Rva(0x1033), Rva(0x10f9), Rva(0x1143)]);
        for rva in neutralized {
            let instruction = function
                .instructions()
                .find(|instruction| instruction.rva() == Some(rva))
                .expect("neutralized marker remains in the IR");
            assert_eq!(
                instruction.raw().ip(),
                u64::from(rva.get()),
                "replacement must retain the IP used for internal branch retargeting"
            );
        }
    }

    #[test]
    fn begin_without_a_reachable_end_is_rejected_explicitly() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let function = decode_function(image, Rva(0x1000)).expect("covering function must decode");
        assert_eq!(
            recover_marker_region(&function, Rva(0x1033), &[Rva(0xdead_beef)]),
            Err(MarkerRegionError::NoReachableEnd { begin: Rva(0x1033) })
        );
    }

    #[test]
    fn explicit_static_marker_extent_starts_after_its_payload() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let mut function =
            decode_function(image, Rva(0x1000)).expect("covering function must decode");
        let begin = function
            .blocks
            .iter_mut()
            .flat_map(|block| block.instructions.iter_mut())
            .find(|instruction| instruction.rva() == Some(Rva(0x1033)))
            .expect("fixture Begin is decoded");
        let raw = RawInstruction::with_branch(Code::Jmp_rel8_64, 0x1039)
            .expect("short static jump is constructible");
        begin.replace(raw, &[0xeb, 0x04]);

        let region = recover_marker_region_from(
            &function,
            Rva(0x1033),
            Rva(0x1039),
            &[Rva(0x10f9), Rva(0x1143)],
        )
        .expect("explicit continuation skips static marker payload");
        assert_eq!(region.reached_ends, vec![Rva(0x10f9), Rva(0x1143)]);
        assert_eq!(region.instructions.first(), Some(&Rva(0x1039)));
    }
}
