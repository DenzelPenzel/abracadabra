use std::path::{Path, PathBuf};

use vmp_pe::{ExportTarget, Fixup, FixupKind, ImportTarget, PeFile};
use vmp_types::{Architecture, ImageBase, Rva};

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

#[test]
fn matches_cpp_open_exe_expectations() {
    let Some(bytes) = read("win32-app-test1-i386") else {
        return;
    };
    let pe = PeFile::parse(&bytes).expect("fixture must parse");
    const BASE: u64 = 0x0040_0000;

    // arch name "i386", 32-bit addresses, image base 0x400000
    assert_eq!(pe.architecture, Architecture::X86);
    assert_eq!(pe.architecture.pointer_width(), 4);
    assert_eq!(pe.optional.image_base, ImageBase(BASE));
    // :38 — entry_point() == 0x401000
    assert_eq!(pe.entry_point(), Rva(0x1000));

    // three segments with these names and memory types
    let names: Vec<&str> = pe.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".rdata", ".data"]);
    let permissions: Vec<String> = pe.sections.iter().map(|s| s.permissions.as_rwx()).collect();
    assert_eq!(
        permissions,
        ["r-x", "r--", "rw-"],
        ":45-47 mtReadable|mtExecutable, mtReadable, mtReadable|mtWritable"
    );

    let imports = pe.imports.as_ref().expect("the fixture imports");
    let expected: [(&str, &[(&str, u32)]); 3] = [
        (
            "user32.dll",
            &[
                ("SetFocus", 0x2028),                // 0x402028 :54
                ("MessageBoxA", 0x202c),             // 0x40202c :56
                ("GetDlgItemTextA", 0x2030),         // 0x402030 :58
                ("GetDlgItem", 0x2034),              // 0x402034 :60
                ("EndDialog", 0x2038),               // 0x402038 :62
                ("DialogBoxIndirectParamA", 0x203c), // 0x40203c :64
            ],
        ),
        (
            "kernel32.dll",
            &[
                ("MultiByteToWideChar", 0x2010), // 0x402010 :68
                ("GlobalFree", 0x2014),          // 0x402014 :70
                ("ExitProcess", 0x2018),         // 0x402018 :72
                ("GetModuleHandleA", 0x201c),    // 0x40201c :74
                ("GlobalAlloc", 0x2020),         // 0x402020 :76
            ],
        ),
        (
            "VMProtectSDK32.dll",
            &[
                ("VMProtectDecryptStringA", 0x2000), // 0x402000 :80
                ("VMProtectEnd", 0x2004),            // 0x402004 :82
                ("VMProtectBegin", 0x2008),          // 0x402008 :84
            ],
        ),
    ];
    assert_eq!(imports.descriptors.len(), 3, ":50");
    for (library, (expected_name, functions)) in imports.descriptors.iter().zip(&expected) {
        assert_eq!(&library.name, expected_name);
        assert_eq!(
            library.functions.len(),
            functions.len(),
            "{expected_name} function count"
        );
        for (function, (name, thunk)) in library.functions.iter().zip(*functions) {
            assert_eq!(
                function.target,
                ImportTarget::Name {
                    hint: match &function.target {
                        ImportTarget::Name { hint, .. } => *hint,
                        ImportTarget::Ordinal(_) => panic!("{name} must be imported by name"),
                    },
                    name: (*name).to_owned(),
                }
            );
            assert_eq!(
                function.thunk_rva,
                Rva(*thunk),
                "{name} IAT slot: C++ pins VA {:#x}",
                BASE + u64::from(*thunk)
            );
        }
    }

    assert_eq!(pe.base_relocations, None, ":87 the fixture has no fixups");
}

#[test]
fn matches_cpp_open_dll_expectations() {
    let Some(bytes) = read("win32-dll-test1-i386") else {
        return;
    };
    let pe = PeFile::parse(&bytes).expect("fixture must parse");
    const BASE: u64 = 0x3ff3_0000;
    assert_eq!(pe.optional.image_base, ImageBase(BASE));

    // export module name and entry count
    let exports = pe.exports.as_ref().expect("the fixture exports");
    assert_eq!(exports.name, "ShimEng.dll", ":106");
    assert_eq!(exports.entries.len(), 11, ":107");

    // first and last entry are forwarders into APPHELP
    let first = &exports.entries[0];
    assert_eq!(first.name.as_deref(), Some("SE_DllLoaded"), ":108");
    assert_eq!(
        first.target,
        ExportTarget::Forwarder("APPHELP.SE_DllLoaded".to_owned()),
        ":109"
    );
    let last = &exports.entries[10];
    assert_eq!(last.name.as_deref(), Some("SE_ProcessDying"), ":111");
    assert_eq!(
        last.target,
        ExportTarget::Forwarder("APPHELP.SE_ProcessDying".to_owned()),
        ":112"
    );
    assert_eq!(exports.ordinal_base, 1);
    assert_eq!(first.ordinal, 1);
    assert_eq!(last.ordinal, 11);

    let relocations = pe
        .base_relocations
        .as_ref()
        .expect("the fixture has fixups");
    let expected: [u32; 12] = [
        0x103a, // 0x3ff3103a :117
        0x1042, // 0x3ff31042 :119
        0x104d, // 0x3ff3104d :121
        0x1089, // 0x3ff31089 :123
        0x10a2, // 0x3ff310a2 :125
        0x10ae, // 0x3FF310AE :127
        0x10b6, // 0x3FF310B6 :129
        0x10be, // 0x3FF310BE :131
        0x10ca, // 0x3FF310CA :133
        0x10e0, // 0x3FF310E0 :135
        0x10e8, // 0x3FF310E8 :137
        0x10f0, // 0x3ff310f0 :139
    ];
    assert_eq!(relocations.len(), 12, ":116");
    let fixups: Vec<Fixup> = expected
        .iter()
        .map(|rva| Fixup {
            rva: Rva(*rva),
            kind: FixupKind::HighLow,
        })
        .collect();
    assert_eq!(
        relocations.fixups(),
        fixups.as_slice(),
        "fixup set must match the addresses the C++ test pins"
    );
}

#[test]
fn matches_cpp_checksum_values() {
    for (fixture, expected) in [
        ("win32-app-delphi-i386", 0x000e_4490u32), // :417
        ("win64-app-msvc-amd64", 0x0000_b8c9),     // :419
    ] {
        let Some(bytes) = read(fixture) else {
            continue;
        };
        let pe = PeFile::parse(&bytes).expect("fixture must parse");
        assert_eq!(
            pe.compute_checksum(&bytes).expect("checksum must compute"),
            expected,
            "{fixture}: checksum must match os::FileGetCheckSum"
        );
    }
}

#[test]
fn stored_checksum_is_current_where_the_linker_wrote_one() {
    let Some(bytes) = read("win64-app-msvc-amd64") else {
        return;
    };
    let pe = PeFile::parse(&bytes).expect("fixture must parse");
    assert_eq!(pe.optional.checksum, 0x0000_b8c9);
    assert_eq!(
        pe.compute_checksum(&bytes).expect("checksum must compute"),
        pe.optional.checksum
    );
}
