//! Windows gate for the complete symbol-selected CLI path.

#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use vmp_pe::PeFile;
use vmp_types::Rva;

#[allow(unsafe_code)]
mod os {
    use super::{c_void, wide, Path};

    #[link(name = "imagehlp")]
    extern "system" {
        fn MapFileAndCheckSumW(
            filename: *const u16,
            header_sum: *mut u32,
            checksum: *mut u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(filename: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x20;
    const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x02;

    pub fn checksums(path: &Path) -> Result<(u32, u32), u32> {
        let path = wide(path);
        let mut stored = 0;
        let mut computed = 0;
        let status = unsafe { MapFileAndCheckSumW(path.as_ptr(), &mut stored, &mut computed) };
        if status == 0 {
            Ok((stored, computed))
        } else {
            Err(status)
        }
    }

    pub fn maps_as_image(path: &Path) -> Result<(), u32> {
        let path = wide(path);
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE,
            )
        };
        if module.is_null() {
            return Err(unsafe { GetLastError() });
        }
        unsafe { FreeLibrary(module) };
        Ok(())
    }
}

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vmp-symbols/test-corpus")
        .join(name)
}

fn run(path: &Path) -> Output {
    Command::new(path)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env(
            "SYSTEMROOT",
            std::env::var_os("SYSTEMROOT").unwrap_or_default(),
        )
        .output()
        .unwrap_or_else(|error| panic!("running {} failed: {error}", path.display()))
}

#[test]
fn pdb_selected_main_loads_runs_and_has_unwind_metadata() {
    let input = corpus("foo.exe");
    assert!(
        corpus("foo.pdb").is_file(),
        "required PDB corpus is missing"
    );
    let directory =
        std::env::temp_dir().join(format!("vmp-cli-windows-symbol-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("scratch directory must be created");
    let protected = directory.join("foo-protected.exe");

    let command = Command::new(env!("CARGO_BIN_EXE_vmp"))
        .arg("protect")
        .arg(&input)
        .arg("--output")
        .arg(&protected)
        .arg("--symbol")
        .arg("main")
        .arg("--symbol-index")
        .arg("0")
        .arg("--seed")
        .arg("1")
        .arg("--json")
        .output()
        .expect("symbol-selected CLI must start");
    assert!(
        command.status.success(),
        "symbol-selected CLI failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&command.stdout).expect("CLI report must be JSON");
    assert_eq!(report["summary"]["requested"], 1);
    assert_eq!(report["summary"]["protected"], 1);
    assert_eq!(report["summary"]["skipped"], 0);
    assert_eq!(report["protected"][0]["original"], "0x00006560");
    let relocated_text = report["protected"][0]["relocated"]
        .as_str()
        .expect("relocated RVA must be textual");
    let relocated = u32::from_str_radix(
        relocated_text
            .strip_prefix("0x")
            .expect("relocated RVA must be hexadecimal"),
        16,
    )
    .expect("relocated RVA must parse");

    let bytes = std::fs::read(&protected).expect("protected image must be readable");
    let pe = PeFile::parse(&bytes).expect("protected image must reparse");
    assert!(
        pe.exception_table.as_ref().is_some_and(|table| {
            table
                .functions()
                .any(|function| function.begin == Rva(relocated))
        }),
        "relocated main must have a RUNTIME_FUNCTION entry"
    );

    let (stored, computed) = os::checksums(&protected).expect("imagehlp checksum must succeed");
    assert_eq!(stored, computed, "stored checksum must match imagehlp");
    assert_eq!(pe.optional.checksum, computed);
    os::maps_as_image(&protected).expect("Windows loader must map protected image");

    let before = run(&input);
    let after = run(&protected);
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);

    let _ = std::fs::remove_dir_all(directory);
}
