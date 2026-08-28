//! Placing mutated code into the output image.
//!
//! This is the backend of protection: `vmp-x86` decodes, `vmp-mutation`
//! rewrites, and this crate decides where the result lives and patches the
//! container so the program still runs.
//!
//! # The shape of one protected function
//!
//! A mutated function is not written back over the original. It is encoded for
//! a fresh address in an appended section, given its own `RUNTIME_FUNCTION`
//! entry, and the original entry point is overwritten with a five-byte jump to
//! the copy. Callers keep calling the original address and land in the new
//! code; the original body stays in the file, unreachable.
//!
//! # Why so much is refused
//!
//! Every check in [`SkipReason`] exists because getting it wrong produces a
//! binary that loads, starts, and then dies somewhere unrelated. A skipped
//! function still works, so the default on any doubt is to skip.

use vmp_ir::{DecodeIssue, Function, OperandRef};
use vmp_mutation::{Frozen, Report, Seed};
use vmp_pe::{NewFunction, NewSection, PeError, PeFile, PeImage, UnwindInfo};
use vmp_types::{Architecture, Rva};
use vmp_x86::{decode_function, epilogues, relocate, Epilogue, Image, Relocated};

pub mod sdk;
mod stub;

use stub::{Stub, STUB_LEN};

/// Characteristics of the section mutated code is placed in:
/// `CNT_CODE | MEM_EXECUTE | MEM_READ`.
const CODE_SECTION: u32 = 0x6000_0020;

/// Every protected function starts on this boundary inside the new section.
const FUNCTION_ALIGNMENT: u32 = 16;

/// Knobs for one protection run.
#[derive(Debug, Clone)]
pub struct Options {
    pub seed: Seed,
    /// Name of the appended section holding mutated code.
    pub code_section: String,
    /// Name of the appended section holding the rebuilt exception directory.
    pub pdata_section: String,
    pub mutation: vmp_mutation::Options,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            seed: Seed::default(),
            code_section: ".vmpc".to_string(),
            pdata_section: ".vmpx".to_string(),
            mutation: vmp_mutation::Options::default(),
        }
    }
}

/// One function that was mutated and moved.
#[derive(Debug, Clone)]
pub struct Protected {
    /// Entry point in the input image; now the address of the jump stub.
    pub original: Rva,
    /// Entry point of the mutated copy.
    pub relocated: Rva,
    /// Length of the mutated copy in bytes.
    pub length: u32,
    pub report: Report,
}

/// One function that was left alone, and why.
#[derive(Debug, Clone)]
pub struct Skipped {
    pub rva: Rva,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The decoder refused the function outright.
    NotDecodable(String),
    /// The decoder could not account for every path.
    Incomplete(Vec<DecodeIssue>),
    /// No `RUNTIME_FUNCTION` covers the entry, so a copy could not be described
    /// to the unwinder. On x64 that makes the copy unsafe for any function that
    /// might be on the stack when an exception is raised — which, with a
    /// `catch_unwind` anywhere in the process, is all of them.
    NoUnwindData,
    /// The entry is inside a `RUNTIME_FUNCTION` rather than at its start, so it
    /// names a fragment the exception directory cannot describe on its own.
    NotAFunctionEntry { covering: Rva },
    /// The unwind info carries language-specific handler data, which cannot be
    /// re-emitted for a new address without also moving the handler.
    UnwindNotReEmittable(String),
    /// Re-encoding changed the layout of the prologue, so the existing
    /// `UNWIND_CODE` offsets no longer describe it.
    PrologueMoved,
    /// An epilogue came back with its instructions no longer adjacent or no
    /// longer the same size, so the unwinder would stop recognising it.
    EpilogueMoved,
    /// The function reads or writes an absolute address recorded in `.reloc`.
    /// Moving the code means the fixup has to move with it, which is a
    /// relocation-table rewrite this milestone does not do.
    HasAbsoluteFixups,
    /// Shorter than the jump that would have to replace its entry.
    TooShortForStub { length: u32 },
    /// Mutation left the function byte-identical, so moving it would add risk
    /// and change nothing.
    NothingToDo,
    /// Mutation itself failed.
    MutationFailed(String),
}

/// The outcome of one protection run.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub protected: Vec<Protected>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("the image could not be rewritten: {0}")]
    Pe(#[from] PeError),
    #[error("laying out the function at {rva} failed: {reason}")]
    Layout { rva: Rva, reason: String },
    #[error("only x64 images are supported, this one is {architecture:?}")]
    UnsupportedArchitecture { architecture: Architecture },
    #[error("no requested function could be protected")]
    NothingProtected,
    #[error("SDK marker discovery or region recovery failed: {0}")]
    SdkMarker(String),
    #[error("the image contains no supported SDK Begin markers")]
    NoSdkMarkers,
    #[error("SDK marker at {rva} requests unsupported {compilation_type:?} (lock-to-key: {lock_to_key})")]
    UnsupportedSdkMarker {
        rva: Rva,
        compilation_type: vmp_pe::markers::MarkerCompilationType,
        lock_to_key: bool,
    },
    #[error("SDK marker at {rva} is not covered by an x64 RUNTIME_FUNCTION")]
    SdkMarkerOutsideRuntimeFunction { rva: Rva },
    #[error("multiple SDK Begin markers select the covering function at {function}")]
    MultipleSdkBegins { function: Rva },
}

/// Mutates each function in `entries`, moves it into a new section and points
/// its original entry at the copy.
///
/// Returns the rewritten image together with a per-function account of what
/// happened. Functions that fail any eligibility check are reported in
/// [`Outcome::skipped`] and left untouched in the output.
pub fn protect(
    image: PeImage,
    entries: &[Rva],
    options: &Options,
) -> Result<(PeImage, Outcome), EmitError> {
    if image.pe().architecture != Architecture::X64 {
        return Err(EmitError::UnsupportedArchitecture {
            architecture: image.pe().architecture,
        });
    }

    // Branches and RIP-relative operands encode a distance, not an address, so
    // the code cannot be encoded until its final address is known. The section
    // that will hold it does not exist yet, hence asking where it would land
    let data = image.bytes().to_vec();
    let code_rva = image.next_section_rva()?;

    // Filled in together, one entry each per protected function: `code` becomes
    // the appended section, a `Stub` patches the original entry, a
    // `NewFunction` describes the copy to the unwinder
    let mut outcome = Outcome::default();
    let mut code: Vec<u8> = Vec::new();
    let mut stubs: Vec<Stub> = Vec::new();
    let mut runtime_functions: Vec<NewFunction> = Vec::new();

    // Each function gets its place in the new section before anything is
    // encoded for it
    // func    size      place
    // 0x1150  51 byte   0x10000
    // 0x14a4  619 byte  0x10040
    for &entry in entries {
        let offset = align_up(code.len() as u32, FUNCTION_ALIGNMENT);
        let placement = code_rva.checked_add(offset).ok_or(EmitError::Layout {
            rva: entry,
            reason: "the appended section does not fit in the RVA space".to_string(),
        })?;

        match prepare(image.pe(), &data, entry, placement, options) {
            Ok(ready) => {
                // The bytes were encoded for `placement`, so the gap alignment
                // opened has to be filled before they go in
                pad_to(&mut code, offset as usize);
                code.extend_from_slice(&ready.bytes);
                stubs.push(Stub::new(entry, placement));
                runtime_functions.push(ready.runtime_function);
                outcome.protected.push(ready.protected);
            }
            // One function being ineligible is not the run failing
            Err(reason) => outcome.skipped.push(Skipped { rva: entry, reason }),
        }
    }

    // Nothing passed, so there is no output worth writing
    if outcome.protected.is_empty() {
        return Err(EmitError::NothingProtected);
    }

    // The stubs go in before the sections are appended so that the last append
    // recomputes the checksum over the final bytes. Patching afterwards would
    // leave the stored checksum describing the pre-patch image.
    let mut patched = data;
    for stub in &stubs {
        stub.write(image.pe(), &mut patched)?;
    }

    // Two appended sections: the copies, then the exception directory that
    // describes them
    let mut image = PeImage::from_bytes(patched)?;
    image.add_section(NewSection {
        name: &options.code_section,
        data: &code,
        characteristics: CODE_SECTION,
    })?;
    image.extend_exception_table(&options.pdata_section, &runtime_functions)?;

    Ok((image, outcome))
}

/// A function that passed every check and is ready to be placed.
struct Ready {
    bytes: Vec<u8>,
    runtime_function: NewFunction,
    protected: Protected,
}

/// Runs one function through every eligibility check and encodes it for
/// `placement`.
///
/// The checks are ordered so that everything knowable without mutating is asked
/// first. Mutation is the expensive step and it consumes the function's random
/// stream, so a refusal it could not have influenced is better found before it
/// runs.
fn prepare(
    pe: &PeFile,
    data: &[u8],
    entry: Rva,
    placement: Rva,
    options: &Options,
) -> Result<Ready, SkipReason> {
    let view = Image::new(pe, data);
    let mut function = decode_function(view, entry)
        .map_err(|error| SkipReason::NotDecodable(error.to_string()))?;
    if !function.is_complete() {
        return Err(SkipReason::Incomplete(function.issues.clone()));
    }

    // The copy needs a `RUNTIME_FUNCTION` of its own, and one describes a whole
    // function, so an address inside somebody else's is no good. Reporting where
    // that function starts is more useful than reporting the address we refused
    let unwind_range = function.unwind.ok_or(SkipReason::NoUnwindData)?;
    if unwind_range.begin != entry {
        return Err(SkipReason::NotAFunctionEntry {
            covering: unwind_range.begin,
        });
    }
    let unwind = UnwindInfo::parse(pe, data, unwind_range.unwind_info)
        .map_err(|error| SkipReason::UnwindNotReEmittable(error.to_string()))?;
    // Ask for the re-emitted form now rather than discovering halfway through
    // the rewrite that this function's unwind info cannot be reproduced
    unwind
        .to_bytes()
        .map_err(|error| SkipReason::UnwindNotReEmittable(error.to_string()))?;

    if has_absolute_fixups(&function) {
        return Err(SkipReason::HasAbsoluteFixups);
    }

    // The jump that replaces the entry has to fit inside the function, or it
    // would run over whatever follows
    let original_length = unwind_range.end.get().saturating_sub(entry.get());
    if original_length < STUB_LEN {
        return Err(SkipReason::TooShortForStub {
            length: original_length,
        });
    }

    // `UNWIND_CODE` offsets describe the prologue byte by byte, so it is copied
    // verbatim and the unwind info can be re-used as is
    let mut frozen = Frozen::new();
    if let Some(prologue_end) = entry.checked_add(u32::from(unwind.size_of_prolog)) {
        frozen.freeze(entry, prologue_end);
    }

    let epilogues = epilogues(&function);
    for epilogue in &epilogues {
        frozen.freeze(epilogue.begin, epilogue.end);
    }

    // A copy identical to the original would cost a stub, a `.pdata` entry and
    // section space, and buy nothing
    let report = vmp_mutation::mutate(&mut function, &frozen, options.seed, &options.mutation)
        .map_err(|error| SkipReason::MutationFailed(error.to_string()))?;
    if report.is_noop() {
        return Err(SkipReason::NothingToDo);
    }

    // Re-encodes the whole function for its new address, fixing up branches and
    // RIP-relative operands
    let relocated = relocate(&function, placement)
        .map_err(|error| SkipReason::NotDecodable(error.to_string()))?;
    if !prologue_kept_its_layout(
        &function,
        &relocated,
        entry,
        placement,
        unwind.size_of_prolog,
    ) {
        return Err(SkipReason::PrologueMoved);
    }
    if !epilogues_kept_their_shape(&function, &relocated, &epilogues) {
        return Err(SkipReason::EpilogueMoved);
    }

    // Mutation changes the length, so the copy's bounds come from the encoded
    // bytes rather than from the original range
    let length = u32::try_from(relocated.bytes.len()).map_err(|_| SkipReason::PrologueMoved)?;
    let end = placement
        .checked_add(length)
        .ok_or(SkipReason::PrologueMoved)?;

    Ok(Ready {
        runtime_function: NewFunction {
            begin: placement,
            end,
            unwind,
        },
        protected: Protected {
            original: entry,
            relocated: placement,
            length,
            report,
        },
        bytes: relocated.bytes,
    })
}

/// Whether every prologue instruction still sits at the same offset from the
/// entry as it did before.
///
/// `UNWIND_CODE.CodeOffset` is a byte offset from the start of the function, so
/// the unwind info can be re-used for the copy only if the prologue's internal
/// layout is untouched. That is not automatic even with the prologue frozen
/// against mutation: the block encoder normalizes encodings — dropping a
/// redundant `REX`, resizing a branch — so an unmutated prologue can still come
/// back a different size.
fn prologue_kept_its_layout(
    function: &Function,
    relocated: &Relocated,
    entry: Rva,
    placement: Rva,
    size_of_prolog: u8,
) -> bool {
    if !prologue_has_valid_boundary(function, entry, size_of_prolog) {
        return false;
    }
    let Some(prologue_end) = entry.checked_add(u32::from(size_of_prolog)) else {
        return false;
    };
    let Some(relocated_end) = placement.checked_add(u32::from(size_of_prolog)) else {
        return false;
    };
    let mut expected_original = entry;
    let mut expected_relocated = placement;

    for instruction in function
        .instructions()
        .filter(|instruction| instruction.rva().is_some_and(|rva| rva < prologue_end))
    {
        let Some(rva) = instruction.rva() else {
            return false;
        };
        if rva != expected_original || relocated.new_rva(rva) != Some(expected_relocated) {
            return false;
        }
        let Ok(original_length) = u32::try_from(instruction.len()) else {
            return false;
        };
        let Some(relocated_length) = relocated.instruction_len(function.architecture, rva) else {
            return false;
        };
        if relocated_length != instruction.len() {
            return false;
        }
        let Ok(relocated_length) = u32::try_from(relocated_length) else {
            return false;
        };
        let Some(next_original) = rva.checked_add(original_length) else {
            return false;
        };
        let Some(next_relocated) = expected_relocated.checked_add(relocated_length) else {
            return false;
        };
        expected_original = next_original;
        expected_relocated = next_relocated;
    }

    expected_original == prologue_end && expected_relocated == relocated_end
}

/// Whether the declared prologue ends on an instruction boundary.
///
/// SDK marker excision can shorten an instruction, so callers that still have
/// the original function must run this check before replacing marker calls.
pub(crate) fn prologue_has_valid_boundary(
    function: &Function,
    entry: Rva,
    size_of_prolog: u8,
) -> bool {
    let Some(prologue_end) = entry.checked_add(u32::from(size_of_prolog)) else {
        return false;
    };
    let mut expected = entry;

    for instruction in function
        .instructions()
        .filter(|instruction| instruction.rva().is_some_and(|rva| rva < prologue_end))
    {
        let Some(rva) = instruction.rva() else {
            return false;
        };
        if rva != expected {
            return false;
        }
        let Ok(length) = u32::try_from(instruction.len()) else {
            return false;
        };
        let Some(next) = rva.checked_add(length) else {
            return false;
        };
        expected = next;
    }

    expected == prologue_end
}

/// Whether every epilogue came back with its instructions still adjacent and
/// still the same size.
///
/// Freezing an epilogue keeps a transform out of it, which is a statement about
/// intent; this is the one about the result. The unwinder matches the code
/// stream, so an epilogue survives only if reading forward from its first
/// instruction still finds the same run. Re-encoding can break that on its own,
/// the same way it moves a prologue nothing touched.
///
/// Every instruction must keep its encoded length, and consecutive instructions
/// inside the epilogue must remain adjacent. Measuring each instruction from its
/// own relocated bytes avoids depending on the mapping of the next block, where
/// a branch rewritten by the block encoder legitimately has no single address.
pub(crate) fn epilogues_kept_their_shape(
    function: &Function,
    relocated: &Relocated,
    ranges: &[Epilogue],
) -> bool {
    ranges.iter().all(|range| {
        let inside: Vec<&vmp_ir::Instruction> = function
            .instructions()
            .filter(|instruction| {
                instruction
                    .rva()
                    .is_some_and(|rva| rva >= range.begin && rva < range.end)
            })
            .collect();

        !inside.is_empty()
            && inside.iter().all(|instruction| {
                instruction.rva().is_some_and(|rva| {
                    relocated.instruction_len(function.architecture, rva) == Some(instruction.len())
                })
            })
            && inside.windows(2).all(|pair| {
                let (Some(from), Some(to)) = (pair[0].rva(), pair[1].rva()) else {
                    return false;
                };
                let (Some(from), Some(to)) = (relocated.new_rva(from), relocated.new_rva(to))
                else {
                    return false;
                };
                from.checked_add(pair[0].len() as u32) == Some(to)
            })
    })
}

fn has_absolute_fixups(function: &Function) -> bool {
    function.instructions().any(|instruction| {
        instruction
            .refs()
            .iter()
            .any(|reference| matches!(reference, OperandRef::Absolute { .. }))
    })
}

fn align_up(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}

fn pad_to(buffer: &mut Vec<u8>, length: usize) {
    // `int3` rather than `nop`: nothing should execute the gap between two
    // functions, and a breakpoint says so where a slide of nops would quietly
    // run on into the next function
    if length > buffer.len() {
        buffer.resize(length, 0xcc);
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions};
    use vmp_ir::{BasicBlock, BlockId, CompileStage, Instruction, Terminator};

    use super::*;

    fn function(bytes: &[u8]) -> Function {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let offset = usize::try_from(raw.ip() - 0x1000).expect("small fixture");
            instructions.push(Instruction::decoded(
                Rva(u32::try_from(raw.ip()).expect("small fixture")),
                raw,
                &bytes[offset..offset + raw.len()],
            ));
        }
        let end = Rva(0x1000 + u32::try_from(bytes.len()).expect("small fixture"));
        Function {
            architecture: Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
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
    fn a_prologue_rejects_a_shortened_final_instruction_extent() {
        let function = function(&[0xff, 0x15, 0, 0, 0, 0]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0x90],
            moved: vec![(Rva(0x1000), Rva(0x2000))],
        };

        assert!(!prologue_kept_its_layout(
            &function,
            &relocated,
            Rva(0x1000),
            Rva(0x2000),
            6,
        ));
    }

    #[test]
    fn a_prologue_boundary_inside_an_original_instruction_is_invalid() {
        let function = function(&[0xff, 0x15, 0, 0, 0, 0]);

        assert!(!prologue_has_valid_boundary(&function, Rva(0x1000), 1));
    }

    #[test]
    fn an_epilogue_rejects_a_changed_final_instruction_extent() {
        let function = function(&[0xc3]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0x66, 0xc3],
            moved: vec![(Rva(0x1000), Rva(0x2000))],
        };

        assert!(!epilogues_kept_their_shape(
            &function,
            &relocated,
            &[Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1001),
            }],
        ));
    }

    #[test]
    fn an_epilogue_rejects_a_missing_instruction_mapping() {
        let function = function(&[0x48, 0x83, 0xc4, 0x20, 0xc3]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0x48, 0x83, 0xc4, 0x20, 0xc3],
            moved: vec![(Rva(0x1000), Rva(0x2000))],
        };

        assert!(!epilogues_kept_their_shape(
            &function,
            &relocated,
            &[Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1005),
            }],
        ));
    }

    #[test]
    fn an_epilogue_rejects_a_widened_gap_between_instructions() {
        let function = function(&[0x48, 0x83, 0xc4, 0x20, 0xc3]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0x48, 0x83, 0xc4, 0x20, 0x90, 0xc3],
            moved: vec![(Rva(0x1000), Rva(0x2000)), (Rva(0x1004), Rva(0x2005))],
        };

        assert!(!epilogues_kept_their_shape(
            &function,
            &relocated,
            &[Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1005),
            }],
        ));
    }

    #[test]
    fn an_unchanged_epilogue_keeps_its_shape() {
        let function = function(&[0x48, 0x83, 0xc4, 0x20, 0xc3]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0x48, 0x83, 0xc4, 0x20, 0xc3],
            moved: vec![(Rva(0x1000), Rva(0x2000)), (Rva(0x1004), Rva(0x2004))],
        };

        assert!(epilogues_kept_their_shape(
            &function,
            &relocated,
            &[Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1005),
            }],
        ));
    }

    #[test]
    fn an_epilogue_ignores_a_missing_mapping_after_its_range() {
        let function = function(&[0xc3, 0xeb, 0x00]);
        let relocated = Relocated {
            rva: Rva(0x2000),
            bytes: vec![0xc3, 0xe9, 0x00, 0x00, 0x00, 0x00],
            moved: vec![(Rva(0x1000), Rva(0x2000))],
        };

        assert!(epilogues_kept_their_shape(
            &function,
            &relocated,
            &[Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1001),
            }],
        ));
    }
}
