//! Property-based sweep over every real PE in the corpus directory.
//!
//! Unlike [`corpus.rs`], which pins values of specific named fixtures, this test
//! makes no assumption about which files are present: it walks the corpus, and
//! for every input that is a supported PE it requires the parser to accept it
//! and the append-only writer to either produce a verified rewrite or refuse
//! with a typed fail-closed error.
//!
//! The corpus directory is `VMP_CORPUS_DIR` when set, otherwise the committed
//! `test-corpus` tree. `VMP_REQUIRE_CORPUS=1` turns a missing or PE-free corpus
//! into a failure, which is how CI pins the gate to freshly linked fixtures on
//! Windows and to the committed corpus everywhere else.

use std::path::{Path, PathBuf};

use vmp_pe::{NewSection, PeError, PeFile, PeImage};

const READ_ONLY_DATA: u32 = 0x4000_0040;
const MACHINE_I386: u16 = 0x014c;
const MACHINE_AMD64: u16 = 0x8664;

fn corpus_dir() -> PathBuf {
    match std::env::var_os("VMP_CORPUS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("test-corpus"),
    }
}

fn required() -> bool {
    std::env::var_os("VMP_REQUIRE_CORPUS").is_some()
}

/// Recognises a supported PE without relying on the parser under test.
fn is_supported_pe(bytes: &[u8]) -> bool {
    let read_u16 = |offset: usize| -> Option<u16> {
        let slice = bytes.get(offset..offset + 2)?;
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let slice = bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };

    if read_u16(0) != Some(0x5a4d) {
        return false;
    }
    let Some(nt) = read_u32(0x3c).map(|value| value as usize) else {
        return false;
    };
    if read_u32(nt) != Some(0x0000_4550) {
        return false;
    }
    matches!(read_u16(nt + 4), Some(MACHINE_I386 | MACHINE_AMD64))
}

/// Every reason the writer is allowed to refuse a real input. Any other error —
/// or a failure to reparse its own output — is a defect, not a policy.
fn is_documented_refusal(error: &PeError) -> bool {
    matches!(
        error,
        PeError::NoSectionHeaderSpace { .. }
            | PeError::SectionHeaderSlotNotEmpty { .. }
            | PeError::HeaderDirectoryOverlapsSlot { .. }
            | PeError::OverlayPresent { .. }
            | PeError::CertificateTablePresent
            | PeError::ControlFlowGuardUnsupported
            | PeError::TooManySections
            | PeError::UnsupportedRewriteLayout { .. }
    )
}

#[test]
fn every_corpus_pe_parses_and_rewrites_or_is_refused() {
    let dir = corpus_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        assert!(
            !required(),
            "VMP_REQUIRE_CORPUS is set but corpus directory {} is unavailable",
            dir.display()
        );
        eprintln!("skipping: corpus directory {} not available", dir.display());
        return;
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();

    let mut examined = 0usize;
    let mut rewritten = 0usize;
    for path in paths {
        let Ok(original) = std::fs::read(&path) else {
            continue;
        };
        if !is_supported_pe(&original) {
            continue;
        }
        examined += 1;

        let before = match PeFile::parse(&original) {
            Ok(pe) => pe,
            Err(error) => panic!("{}: supported PE must parse, got {error}", path.display()),
        };

        let mut image = match PeImage::from_bytes(original.clone()) {
            Ok(image) => image,
            Err(error) => panic!(
                "{}: PeImage::from_bytes must agree with PeFile::parse, got {error}",
                path.display()
            ),
        };
        let request = NewSection {
            name: ".vmpdat",
            data: b"corpus-sweep",
            characteristics: READ_ONLY_DATA,
        };
        match image.add_section(request) {
            Err(error) => {
                assert!(
                    is_documented_refusal(&error),
                    "{}: refusal must be a documented fail-closed policy, got {error}",
                    path.display()
                );
                assert_eq!(
                    image.bytes(),
                    original,
                    "{}: a refused rewrite must leave the image untouched",
                    path.display()
                );
                eprintln!("{}: refused ({error})", path.display());
            }
            Ok(()) => {
                rewritten += 1;
                let output = image.bytes();
                let after =
                    PeFile::parse(output).expect("committed output has already been reparsed");
                assert_eq!(after.sections.len(), before.sections.len() + 1);

                for (old, new) in before.sections.iter().zip(&after.sections) {
                    assert_eq!(new.name, old.name, "{}", path.display());
                    assert_eq!(new.virtual_address, old.virtual_address);
                    assert_eq!(new.virtual_size, old.virtual_size);
                    assert_eq!(new.pointer_to_raw_data, old.pointer_to_raw_data);
                    assert_eq!(new.size_of_raw_data, old.size_of_raw_data);
                    assert_eq!(new.characteristics, old.characteristics);

                    let start = old.pointer_to_raw_data.get() as usize;
                    let end = start + old.size_of_raw_data as usize;
                    assert_eq!(
                        &output[start..end],
                        &original[start..end],
                        "{}: existing raw bytes must be preserved",
                        path.display()
                    );
                }

                // Byte preservation says nothing moved; model preservation says
                // the loader metadata still means the same thing
                assert_eq!(
                    after.base_relocations,
                    before.base_relocations,
                    "{}: the relocation model changed",
                    path.display()
                );
                assert_eq!(
                    after.tls,
                    before.tls,
                    "{}: the TLS model changed",
                    path.display()
                );
                assert_eq!(
                    after.exception_table,
                    before.exception_table,
                    "{}: the unwind model changed",
                    path.display()
                );
                assert_eq!(
                    after.imports,
                    before.imports,
                    "{}: the import model changed",
                    path.display()
                );
                assert_eq!(
                    after.exports,
                    before.exports,
                    "{}: the export model changed",
                    path.display()
                );

                let mut again =
                    PeImage::from_bytes(original.clone()).expect("input parsed once already");
                again
                    .add_section(request)
                    .expect("the same request must succeed again");
                assert_eq!(
                    output,
                    again.bytes(),
                    "{}: the writer must be deterministic",
                    path.display()
                );

                eprintln!(
                    "{}: rewritten ({} -> {} sections)",
                    path.display(),
                    before.sections.len(),
                    after.sections.len()
                );
            }
        }
    }

    if required() {
        assert!(
            examined > 0,
            "VMP_REQUIRE_CORPUS is set but {} holds no supported PE",
            dir.display()
        );
        assert!(
            rewritten > 0,
            "VMP_REQUIRE_CORPUS is set but no corpus PE could be rewritten"
        );
    } else if examined == 0 {
        eprintln!("skipping: no supported PE in {}", dir.display());
    }
}
