//! Writer integration tests against the named real Windows fixtures in
//! `test-corpus`.

use std::path::{Path, PathBuf};

use vmp_pe::{Fixup, FixupKind, NewFunction, NewSection, PeError, PeFile, PeImage, UnwindInfo};
use vmp_types::Rva;

const READ_ONLY_DATA: u32 = 0x4000_0040;

/// See [`corpus.rs`] for why the pinned suites keep their own directory
/// variable instead of following `VMP_CORPUS_DIR`.
fn test_binaries_dir() -> PathBuf {
    match std::env::var_os("VMP_TEST_BINARIES_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("test-corpus"),
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

/// Asserts that the loader metadata means the same thing before and after.
///
/// Comparing raw bytes proves nothing moved; comparing the structured models
/// proves the directories still describe the same imports, relocations, thread
/// local storage and unwind data.
fn assert_directories_unchanged(before: &PeFile, after: &PeFile) {
    assert_eq!(
        after.base_relocations, before.base_relocations,
        "the base relocation model must survive the rewrite"
    );
    assert_eq!(after.tls, before.tls, "the TLS model must survive");
    assert_eq!(
        after.exception_table, before.exception_table,
        "the unwind model must survive"
    );
    assert_eq!(
        after.imports, before.imports,
        "the import model must survive"
    );
    assert_eq!(
        after.exports, before.exports,
        "the export model must survive"
    );
}

fn assert_old_sections_preserved(original: &[u8], output: &[u8], before: &PeFile, after: &PeFile) {
    assert_eq!(after.sections.len(), before.sections.len() + 1);
    for (old, rewritten) in before.sections.iter().zip(&after.sections) {
        assert_eq!(rewritten.name, old.name);
        assert_eq!(rewritten.virtual_size, old.virtual_size);
        assert_eq!(rewritten.virtual_address, old.virtual_address);
        assert_eq!(rewritten.size_of_raw_data, old.size_of_raw_data);
        assert_eq!(rewritten.pointer_to_raw_data, old.pointer_to_raw_data);
        assert_eq!(rewritten.characteristics, old.characteristics);

        let start = old.pointer_to_raw_data.get() as usize;
        let end = start + old.size_of_raw_data as usize;
        assert_eq!(&output[start..end], &original[start..end]);
    }

    assert_eq!(after.data_directories.len(), before.data_directories.len());
    for (old, rewritten) in before.data_directories.iter().zip(&after.data_directories) {
        assert_eq!(rewritten.address, old.address);
        assert_eq!(rewritten.size, old.size);
    }
}

fn rewrite_fixture(name: &str, expected_checksum: u32) {
    let Some(original) = read(name) else {
        return;
    };
    let before = PeFile::parse(&original).expect("fixture must parse");
    let mut first = PeImage::from_bytes(original.clone()).expect("fixture must parse");
    first
        .add_section(NewSection {
            name: ".vmpdat",
            data: b"stage-two",
            characteristics: READ_ONLY_DATA,
        })
        .expect("fixture must accept an append-only data section");

    let output = first.into_bytes();
    let after = PeFile::parse(&output).expect("writer output must reparse");
    // Independent oracle: pefile 2024.8.26 `generate_checksum()` and
    // `verify_checksum()` over the deterministic output below.
    assert_eq!(after.optional.checksum, expected_checksum);
    assert_old_sections_preserved(&original, &output, &before, &after);
    assert_directories_unchanged(&before, &after);

    let mut second = PeImage::from_bytes(original).expect("fixture must parse");
    second
        .add_section(NewSection {
            name: ".vmpdat",
            data: b"stage-two",
            characteristics: READ_ONLY_DATA,
        })
        .expect("same rewrite must succeed");
    assert_eq!(output, second.into_bytes(), "writer must be deterministic");
}

#[test]
fn rewrites_real_pe32_plus_without_changing_existing_metadata() {
    rewrite_fixture("win64-app-msvc-amd64", 0x0001_7aa6);
}

#[test]
fn rewrites_real_pe32_without_changing_existing_metadata() {
    rewrite_fixture("win32-app-test1-i386", 0x0000_29b9);
}

/// An eight-byte-aligned address inside a mapped section that no existing fixup
/// already claims.
fn free_fixup_target(pe: &PeFile) -> Rva {
    let used: Vec<u32> = pe
        .base_relocations
        .as_ref()
        .map(|table| table.fixups().iter().map(|fixup| fixup.rva.get()).collect())
        .unwrap_or_default();
    for section in &pe.sections {
        if section.virtual_size == 0 {
            continue;
        }
        let start = section.virtual_address.get();
        let end = start + section.virtual_size;
        let mut rva = start.next_multiple_of(8);
        while rva + 8 <= end {
            if !used.contains(&rva) {
                return Rva(rva);
            }
            rva += 8;
        }
    }
    panic!("the fixture has no free relocation target");
}

/// Rewrites the relocation and exception directories of a real x64 fixture and
/// checks that both models come back exactly as planned while everything else is
/// preserved.
fn rewrite_directories(name: &str) {
    let Some(original) = read(name) else {
        return;
    };
    let before = PeFile::parse(&original).expect("fixture must parse");
    let baseline_relocations = before
        .base_relocations
        .clone()
        .expect("the fixture has relocations");
    let baseline_exceptions = before
        .exception_table
        .clone()
        .expect("the fixture has unwind data");

    let mut image = PeImage::from_bytes(original.clone()).expect("fixture must parse");
    let target = free_fixup_target(&before);
    image
        .extend_base_relocations(
            ".vmprel",
            &[Fixup {
                rva: target,
                kind: FixupKind::Dir64,
            }],
        )
        .expect("the relocation table must be extendable");

    let after_relocations = image.pe().base_relocations.clone().expect("still present");
    assert_eq!(
        after_relocations.len(),
        baseline_relocations.len() + 1,
        "exactly one fixup was added"
    );
    assert!(after_relocations.fixups().contains(&Fixup {
        rva: target,
        kind: FixupKind::Dir64
    }));
    for fixup in baseline_relocations.fixups() {
        assert!(
            after_relocations.fixups().contains(fixup),
            "the original fixup {fixup:?} must survive"
        );
    }
    assert_eq!(
        image.pe().exception_table,
        Some(baseline_exceptions.clone()),
        "rewriting relocations must not disturb unwind data"
    );

    // The appended section for the new code the protector would emit
    let code_begin = Rva(before.optional.size_of_image);
    image
        .extend_exception_table(
            ".vmpexc",
            &[NewFunction {
                begin: code_begin,
                end: Rva(code_begin.get() + 0x10),
                unwind: UnwindInfo::leaf(),
            }],
        )
        .expect("the exception table must be extendable");

    let after_exceptions = image
        .pe()
        .exception_table
        .clone()
        .expect("unwind data is present");
    assert_eq!(after_exceptions.len(), baseline_exceptions.len() + 1);
    for entry in baseline_exceptions.entries() {
        assert!(
            after_exceptions.entries().contains(entry),
            "the original unwind entry for {:?} must survive unchanged",
            entry.function.begin
        );
    }
    assert_eq!(
        image.pe().base_relocations,
        Some(after_relocations),
        "rewriting unwind data must not disturb relocations"
    );

    // Existing raw bytes and section headers are still untouched after two
    // directory rewrites
    let output = image.bytes();
    for section in &before.sections {
        let start = section.pointer_to_raw_data.get() as usize;
        let end = start + section.size_of_raw_data as usize;
        assert_eq!(&output[start..end], &original[start..end]);
    }
    PeFile::parse(output).expect("the twice-rewritten output must reparse");
}

#[test]
fn rewrites_directories_of_a_real_x64_fixture() {
    rewrite_directories("win64-app-msvc-amd64");
}

#[test]
fn rewrites_directories_of_a_real_seh_fixture() {
    rewrite_directories("seh-x64");
}

#[test]
fn reports_directory_overlap_before_nonzero_slot_for_real_dll() {
    let Some(original) = read("win32-dll-test1-i386") else {
        return;
    };
    let mut image = PeImage::from_bytes(original).expect("fixture must parse");

    assert!(matches!(
        image.add_section(NewSection {
            name: ".vmpdat",
            data: &[1],
            characteristics: READ_ONLY_DATA,
        }),
        Err(PeError::HeaderDirectoryOverlapsSlot { directory: 11, .. })
    ));
}
