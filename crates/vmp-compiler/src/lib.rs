//! Protection pipeline orchestration.
//!
//! This crate owns selection and compilation. Frontends provide bytes and
//! selection inputs; they remain responsible for filesystem IO and rendering.

use std::collections::HashSet;

/// Mutation-only compatibility alias for the emitter outcome.
///
/// Kept at the compiler boundary so frontends do not depend on `vmp-emit`;
/// Virtualization will introduce a compiler-owned mode result rather than
/// extending this Mutation-specific shape.
pub use vmp_emit::Outcome;
/// Mutation-only compatibility alias for one protected function.
pub use vmp_emit::Protected;
/// Mutation-only compatibility alias for a stable emitter refusal category.
pub use vmp_emit::SkipReason;
/// Mutation-only compatibility alias for one skipped function.
pub use vmp_emit::Skipped;
/// Mutation-only compatibility alias for the transformation report.
pub use vmp_mutation::Report as MutationReport;
/// Deterministic Mutation seed passed through the compiler boundary.
pub use vmp_mutation::Seed;
pub use vmp_symbols::MAX_SIDECAR_INPUT_BYTES;

use vmp_pe::{markers::SdkMarker, PeImage};
use vmp_symbols::Selector;
use vmp_types::{Architecture, Rva};

/// One optional demangled-symbol selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSelection {
    pub name: String,
    pub occurrence: Option<usize>,
}

/// Inputs for one Mutation compilation.
#[derive(Debug)]
pub struct MutationRequest {
    pub image: Vec<u8>,
    pub rvas: Vec<Rva>,
    pub symbol: Option<SymbolSelection>,
    pub map: Option<String>,
    pub pdb: Option<Vec<u8>>,
    pub seed: Seed,
}

/// The complete in-memory result of one Mutation compilation.
#[derive(Debug)]
pub struct MutationProduct {
    pub image: Vec<u8>,
    pub outcome: Outcome,
    pub seed: Seed,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("loading the PE for rewriting failed: {0}")]
    Pe(#[from] vmp_pe::PeError),
    #[error("protecting the PE failed: {0}")]
    Emit(#[from] vmp_emit::EmitError),
    #[error("discovering SDK API markers failed: {0}")]
    ApiSdkDiscovery(#[from] vmp_x86::sdk_markers::ApiMarkerError),
    #[error("discovering static SDK markers failed: {0}")]
    StaticSdkDiscovery(#[from] vmp_pe::markers::MarkerError),
    #[error("nothing to protect: the image declares no exception directory entries")]
    NoFunctionEntries,
    #[error("loading symbols failed: {0}")]
    Symbols(#[from] vmp_symbols::SymbolError),
    #[error("resolving the selected symbol failed: {0}")]
    Resolve(#[from] vmp_symbols::ResolveError),
    #[error(
        "symbol `{name}` is ambiguous: {matches} code occurrences; select an occurrence in 0..={last}"
    )]
    AmbiguousSymbol {
        name: String,
        matches: usize,
        last: usize,
    },
    #[error("symbol `{name}` resolves to {rva}, which is not executable")]
    SymbolNotExecutable { name: String, rva: Rva },
    #[error("symbol `{name}` resolves to {rva}, which is not an x64 RUNTIME_FUNCTION entry")]
    SymbolNotFunctionEntry { name: String, rva: Rva },
    #[error("allocation failed while {context}")]
    SelectionAllocation { context: &'static str },
    #[error(
        "{skipped} of the {requested} explicitly selected function(s) could not be protected; \
         the first is {first} ({reason})"
    )]
    ExplicitSelectionFailed {
        skipped: usize,
        requested: usize,
        first: Rva,
        reason: &'static str,
    },
}

/// Applies Mutation to explicit selectors or the image's default selection.
pub fn protect_mutation(request: MutationRequest) -> Result<MutationProduct, Error> {
    let MutationRequest {
        image,
        mut rvas,
        symbol,
        map,
        pdb,
        seed,
    } = request;
    let explicit = !rvas.is_empty() || symbol.is_some();
    let options = vmp_emit::Options {
        seed,
        ..vmp_emit::Options::default()
    };
    let image = PeImage::from_bytes(image)?;

    if let Some(selection) = symbol {
        let symbols =
            vmp_symbols::load_symbols(image.pe(), image.bytes(), map.as_deref(), pdb.as_deref())?;
        let selector_name = try_owned_symbol(&selection.name)?;
        let selector = match selection.occurrence {
            Some(index) => Selector::Occurrence {
                name: selector_name,
                index,
            },
            None => Selector::All(selector_name),
        };
        let resolved = symbols.resolve_code(&selector)?;
        if selection.occurrence.is_none() && resolved.len() > 1 {
            return Err(Error::AmbiguousSymbol {
                name: selection.name,
                matches: resolved.len(),
                last: resolved.len() - 1,
            });
        }
        for &rva in &resolved {
            match validate_symbol_entry(&image, rva) {
                Ok(()) => {}
                Err(InvalidSymbolEntry::NotExecutable) => {
                    return Err(Error::SymbolNotExecutable {
                        name: selection.name,
                        rva,
                    });
                }
                Err(InvalidSymbolEntry::NotFunctionEntry) => {
                    return Err(Error::SymbolNotFunctionEntry {
                        name: selection.name,
                        rva,
                    });
                }
            }
        }
        rvas.try_reserve(resolved.len())
            .map_err(|_| Error::SelectionAllocation {
                context: "retaining selected function RVAs",
            })?;
        rvas.extend(resolved);
    }
    stable_dedup_entries(&mut rvas)?;

    let automatic = !explicit;
    let (protected, outcome) = if automatic && has_sdk_begin(&image)? {
        let (protected_image, sdk) = vmp_emit::sdk::protect_direct_sdk_mutation(image, &options)?;
        let mut protected_functions = Vec::new();
        protected_functions
            .try_reserve_exact(sdk.len())
            .map_err(|_| Error::SelectionAllocation {
                context: "retaining SDK protection results",
            })?;
        for mutation in sdk {
            protected_functions.push(Protected {
                original: mutation.function,
                relocated: mutation.relocated,
                length: mutation.length,
                report: mutation.report,
            });
        }
        (
            protected_image,
            Outcome {
                protected: protected_functions,
                skipped: Vec::new(),
            },
        )
    } else {
        let entries = if automatic {
            exception_entries(&image)?
        } else {
            rvas
        };
        if entries.is_empty() {
            return Err(Error::NoFunctionEntries);
        }
        vmp_emit::protect(image, &entries, &options)?
    };

    if explicit {
        if let Some(skipped) = outcome.skipped.first() {
            return Err(Error::ExplicitSelectionFailed {
                skipped: outcome.skipped.len(),
                requested: outcome.protected.len() + outcome.skipped.len(),
                first: skipped.rva,
                reason: skip_reason_name(&skipped.reason),
            });
        }
    }

    Ok(MutationProduct {
        image: protected.into_bytes(),
        outcome,
        seed: options.seed,
    })
}

fn has_sdk_begin(image: &PeImage) -> Result<bool, Error> {
    if image.pe().architecture != Architecture::X64 {
        return Ok(false);
    }
    let view = vmp_x86::Image::new(image.pe(), image.bytes());
    let has_api_begin = vmp_x86::sdk_markers::discover_direct_api_markers(view)?
        .iter()
        .any(|marker| matches!(marker, vmp_x86::sdk_markers::ApiMarker::Begin { .. }));
    let has_static_begin = vmp_pe::markers::discover_asm_markers(image.pe(), image.bytes())?
        .iter()
        .any(|marker| matches!(marker, SdkMarker::Begin { .. }));
    Ok(has_api_begin || has_static_begin)
}

fn exception_entries(image: &PeImage) -> Result<Vec<Rva>, Error> {
    let Some(table) = image.pe().exception_table.as_ref() else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(table.functions().count())
        .map_err(|_| Error::SelectionAllocation {
            context: "retaining exception-directory function entries",
        })?;
    entries.extend(table.functions().map(|function| function.begin));
    Ok(entries)
}

fn stable_dedup_entries(entries: &mut Vec<Rva>) -> Result<(), Error> {
    let mut seen = HashSet::new();
    seen.try_reserve(entries.len())
        .map_err(|_| Error::SelectionAllocation {
            context: "deduplicating selected function RVAs",
        })?;
    entries.retain(|entry| seen.insert(*entry));
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum InvalidSymbolEntry {
    NotExecutable,
    NotFunctionEntry,
}

fn validate_symbol_entry(image: &PeImage, rva: Rva) -> Result<(), InvalidSymbolEntry> {
    let executable = image
        .pe()
        .section_at(rva)
        .is_some_and(|section| section.permissions.execute);
    if !executable {
        return Err(InvalidSymbolEntry::NotExecutable);
    }
    let is_function_entry = image
        .pe()
        .exception_table
        .as_ref()
        .is_some_and(|table| table.functions().any(|function| function.begin == rva));
    if !is_function_entry {
        return Err(InvalidSymbolEntry::NotFunctionEntry);
    }
    Ok(())
}

fn try_owned_symbol(name: &str) -> Result<String, Error> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(name.len())
        .map_err(|_| Error::SelectionAllocation {
            context: "retaining the selected symbol name",
        })?;
    retained.push_str(name);
    Ok(retained)
}

/// Stable machine-readable name for an emitter skip reason.
pub fn skip_reason_name(reason: &SkipReason) -> &'static str {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn pe_fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus")
            .join(name);
        std::fs::read(path).expect("the required PE fixture is readable")
    }

    #[test]
    fn direct_sdk_markers_select_the_sdk_pipeline() {
        let image = PeImage::from_bytes(pe_fixture("win64-app-msvc-amd64"))
            .expect("the required SDK fixture parses");
        assert!(has_sdk_begin(&image).expect("SDK marker discovery succeeds"));
    }

    #[test]
    fn pe32_sdk_markers_do_not_select_the_x64_sdk_pipeline() {
        let mut data = pe_fixture("win32-app-test1-i386");
        let image = PeImage::from_bytes(data.clone()).expect("the required PE32 fixture parses");
        let thunk = image
            .pe()
            .imports
            .as_ref()
            .expect("the PE32 fixture has imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK32.dll")
            .expect("the PE32 fixture imports the SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                vmp_pe::ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("the PE32 fixture imports the Begin marker");
        let thunk_va = image
            .pe()
            .optional
            .image_base
            .get()
            .checked_add(u64::from(thunk.get()))
            .and_then(|value| u32::try_from(value).ok())
            .expect("the PE32 thunk VA fits")
            .to_le_bytes();
        let offset = image
            .pe()
            .rva_to_offset(image.pe().entry_point())
            .expect("the PE32 entry point is file-backed")
            .get() as usize;
        data[offset..offset + 7].copy_from_slice(&[
            0xa1,
            thunk_va[0],
            thunk_va[1],
            thunk_va[2],
            thunk_va[3],
            0xff,
            0xd0,
        ]);
        let image = PeImage::from_bytes(data).expect("the adapted PE32 fixture parses");
        let markers = vmp_x86::sdk_markers::discover_direct_api_markers(vmp_x86::Image::new(
            image.pe(),
            image.bytes(),
        ))
        .expect("PE32 marker discovery succeeds");
        assert!(markers
            .iter()
            .any(|marker| matches!(marker, vmp_x86::sdk_markers::ApiMarker::Begin { .. })));
        assert!(!has_sdk_begin(&image).expect("default-source selection succeeds"));
    }

    #[test]
    fn explicit_entries_are_stably_deduplicated() {
        let mut entries = vec![Rva(3), Rva(1), Rva(3), Rva(2), Rva(1)];
        stable_dedup_entries(&mut entries).expect("the small dedup set allocates");
        assert_eq!(entries, vec![Rva(3), Rva(1), Rva(2)]);
    }

    #[test]
    fn symbol_entry_validation_rejects_a_non_executable_section() {
        let image = PeImage::from_bytes(pe_fixture("win64-app-msvc-amd64"))
            .expect("the required PE fixture parses");
        let rva = image
            .pe()
            .sections
            .iter()
            .find(|section| !section.permissions.execute && section.virtual_size != 0)
            .expect("the required PE fixture has a non-executable section")
            .virtual_address;

        assert_eq!(
            validate_symbol_entry(&image, rva),
            Err(InvalidSymbolEntry::NotExecutable)
        );
    }
}
