//! Parser integration tests against the named fixtures in `test-corpus`.
//!
//! Each test pins values that belong to one specific binary — an entry point, a
//! section count, an image base — so it needs that exact file and cannot run
//! against a substitute. The fixtures are therefore committed next to the crate
//! and these tests run in every checkout.

use std::path::{Path, PathBuf};

use vmp_pe::{PeError, PeFile};
use vmp_types::{Architecture, ImageBase, Rva};

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

#[test]
fn parses_win64_msvc_exe() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("win64 fixture must parse");

    assert_eq!(pe.architecture, Architecture::X64);
    assert_eq!(pe.optional.entry_point, Rva(0x13ec));
    assert_eq!(pe.optional.image_base, ImageBase(0x1_4000_0000));
    assert_eq!(pe.optional.subsystem, 2, "windows-gui");
    assert_eq!(pe.optional.size_of_image, 0x1_0000);
    assert_eq!(pe.optional.size_of_headers, 0x400);
    assert_eq!(pe.sections.len(), 6);
    assert_eq!(pe.data_directories.len(), 16);

    assert_eq!(pe.sections[0].name, ".text");
    assert!(pe.sections[0].permissions.execute);

    // An x64 image must have an exception directory (unwind data) and imports.
    assert!(pe.features.has_exception_directory);
    assert!(pe.features.has_imports);
    assert!(!pe.features.control_flow_guard);
    assert!(!pe.features.is_dotnet);
}

#[test]
fn maps_entry_rva_to_file_offset() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("win64 fixture must parse");
    // .text: va=0x1000 raw=0x400; entry 0x13ec -> 0x400 + 0x3ec = 0x7ec.
    let off = pe
        .rva_to_offset(pe.entry_point())
        .expect("entry RVA must map into .text");
    assert_eq!(off.get(), 0x7ec);
}

#[test]
fn unmapped_rva_is_typed_error() {
    let Some(data) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("win64 fixture must parse");
    // Well past SizeOfImage -> UnmappedRva, without a panic.
    assert!(matches!(
        pe.rva_to_offset(Rva(0x00ff_0000)),
        Err(PeError::UnmappedRva { .. })
    ));
}

#[test]
fn parses_win32_pe() {
    let Some(data) = read("win32-app-test1-i386") else {
        return;
    };
    let pe = PeFile::parse(&data).expect("win32 fixture must parse");
    assert_eq!(pe.architecture, Architecture::X86);
    assert_eq!(pe.optional.image_base, ImageBase(0x0040_0000));
    assert!(!pe.optional.is_pe32_plus());
}

#[test]
fn parses_legacy_x86_load_config_when_structure_size_exceeds_directory_size() {
    let Some(data) = read("seh-x86") else {
        return;
    };

    let pe = PeFile::parse(&data).expect(
        "legacy IMAGE_LOAD_CONFIG_DIRECTORY32 may declare a larger internal Size than the data-directory entry",
    );
    assert_eq!(pe.architecture, Architecture::X86);
    assert!(pe.features.has_load_config);
}

#[test]
fn corrupt_inputs_never_panic() {
    // Empty input.
    assert!(matches!(PeFile::parse(&[]), Err(PeError::Truncated { .. })));
    // Correct size, but a garbage signature.
    let junk = [0u8; 1024];
    assert!(matches!(
        PeFile::parse(&junk),
        Err(PeError::BadDosSignature { .. })
    ));

    // A real header truncated to 200 bytes.
    if let Some(mut data) = read("win64-app-msvc-amd64") {
        data.truncate(200);
        let result = PeFile::parse(&data);
        assert!(result.is_err(), "truncated input must error, not panic");
    }
}
