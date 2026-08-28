//! Windows-only loader and execution gate for the append-only writer.
//!
//! Reparsing our own output proves only that the writer agrees with itself. This
//! gate hands the rewritten image to the operating system instead:
//!
//! 1. `MapFileAndCheckSumW` (imagehlp) recomputes the PE checksum with the same
//!    implementation the Windows SDK tooling uses, so the stored value is
//!    verified independently of [`vmp_pe`].
//! 2. `LoadLibraryExW` with `LOAD_LIBRARY_AS_IMAGE_RESOURCE` maps the file
//!    through the kernel's image path, which validates the headers exactly as a
//!    real load would, without running any code.
//! 3. The original and the rewritten executable are run with identical
//!    arguments and environment, and their exit code, stdout and stderr must
//!    match byte for byte.
//!
//! The target is `pe-loader-probe`, built from this crate, so the gate never
//! depends on a checked-in binary. Set `VMP_LOADER_PROBE_EXTRA` to a
//! semicolon-separated list of additional executables (CI points it at the
//! 32-bit build) to run the same checks over them.
//!
//! The whole file is `cfg(windows)`; on other hosts it compiles to nothing and
//! the gate is reported as not run.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use vmp_pe::{NewSection, PeFile, PeImage};

const READ_ONLY_DATA: u32 = 0x4000_0040;

/// Loader-aware Windows entry points.
///
/// This is the only place in the crate that needs `unsafe`: the point of the
/// gate is to let the operating system, rather than another copy of our own
/// logic, judge the rewritten image.
#[allow(unsafe_code)]
mod os {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

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

    /// `CHECKSUM_SUCCESS`.
    const CHECKSUM_SUCCESS: u32 = 0;
    /// Maps the file as an image without resolving imports or running code.
    const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x0000_0020;

    fn wide(path: &Path) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Returns the checksum stored in the header and the one imagehlp computes.
    pub fn map_file_and_checksum(path: &Path) -> Result<(u32, u32), u32> {
        let filename = wide(path);
        let mut header_sum = 0u32;
        let mut checksum = 0u32;
        // SAFETY: `filename` is NUL-terminated and outlives the call; both out
        // parameters are valid, initialized and exclusively borrowed here.
        let status =
            unsafe { MapFileAndCheckSumW(filename.as_ptr(), &mut header_sum, &mut checksum) };
        if status == CHECKSUM_SUCCESS {
            Ok((header_sum, checksum))
        } else {
            Err(status)
        }
    }

    /// Maps the file through the loader's image path, then unmaps it.
    pub fn maps_as_image(path: &Path) -> Result<(), u32> {
        let filename = wide(path);
        // SAFETY: `filename` is NUL-terminated and outlives the call; the flag
        // maps the image without executing it, and the handle is released below.
        let module = unsafe {
            LoadLibraryExW(
                filename.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_AS_IMAGE_RESOURCE,
            )
        };
        if module.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: `module` is a handle this function just obtained.
        unsafe { FreeLibrary(module) };
        Ok(())
    }
}

/// Creates a fresh directory for one gate run.
fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vmp-pe-gate-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temporary directory must be creatable");
    dir
}

fn append_sections(original: &[u8], count: usize) -> Vec<u8> {
    let mut image = PeImage::from_bytes(original.to_vec()).expect("probe binary must parse");
    for index in 0..count {
        let name = format!(".vmpd{index}");
        image
            .add_section(NewSection {
                name: &name,
                data: b"windows-loader-gate",
                characteristics: READ_ONLY_DATA,
            })
            .unwrap_or_else(|error| {
                panic!("appending section {index} to the probe binary failed: {error}")
            });
    }
    image.into_bytes()
}

fn run(path: &Path, argument: &str) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let output = Command::new(path)
        .arg(argument)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env(
            "SYSTEMROOT",
            std::env::var_os("SYSTEMROOT").unwrap_or_default(),
        )
        .output()
        .unwrap_or_else(|error| panic!("running {} failed: {error}", path.display()));
    (output.status.code(), output.stdout, output.stderr)
}

/// Runs every check over one probe executable.
fn gate(probe: &Path, label: &str) {
    let original = std::fs::read(probe)
        .unwrap_or_else(|error| panic!("reading {} failed: {error}", probe.display()));
    let rewritten = append_sections(&original, 2);
    let parsed = PeFile::parse(&rewritten).expect("rewritten probe must reparse");

    let dir = scratch_dir(label);
    let rewritten_path = dir.join(
        probe
            .file_name()
            .map(|name| {
                let mut renamed = std::ffi::OsString::from("rewritten-");
                renamed.push(name);
                renamed
            })
            .unwrap_or_else(|| std::ffi::OsString::from("rewritten.exe")),
    );
    std::fs::write(&rewritten_path, &rewritten).expect("rewritten image must be writable");

    // 1. Independent checksum oracle.
    let (header_sum, computed) = os::map_file_and_checksum(&rewritten_path)
        .unwrap_or_else(|status| panic!("MapFileAndCheckSumW failed with status {status}"));
    assert_eq!(
        header_sum, computed,
        "{label}: imagehlp must agree with the checksum the writer stored"
    );
    assert_eq!(
        parsed.optional.checksum, computed,
        "{label}: the parsed checksum must be the value imagehlp computes"
    );

    // 2. The kernel's image mapping validates the headers.
    os::maps_as_image(&rewritten_path).unwrap_or_else(|error| {
        panic!("{label}: the loader refused to map the rewritten image, GetLastError={error}")
    });

    // 3. Identical observable behaviour.
    for argument in ["0", "7"] {
        let before = run(probe, argument);
        let after = run(&rewritten_path, argument);
        assert_eq!(
            before.0, after.0,
            "{label}: exit code changed for argument {argument}"
        );
        assert_eq!(
            String::from_utf8_lossy(&before.1),
            String::from_utf8_lossy(&after.1),
            "{label}: stdout changed for argument {argument}"
        );
        assert_eq!(
            String::from_utf8_lossy(&before.2),
            String::from_utf8_lossy(&after.2),
            "{label}: stderr changed for argument {argument}"
        );
    }
    assert_eq!(
        run(probe, "7").0,
        Some(7),
        "{label}: the probe must forward its exit code"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewritten_probe_passes_the_windows_loader_and_execution_gate() {
    gate(Path::new(env!("CARGO_BIN_EXE_pe-loader-probe")), "host");
}

#[test]
fn rewritten_extra_probes_pass_the_windows_loader_and_execution_gate() {
    let Some(extra) = std::env::var_os("VMP_LOADER_PROBE_EXTRA") else {
        eprintln!("skipping: VMP_LOADER_PROBE_EXTRA is not set");
        return;
    };
    let extra = extra.to_string_lossy().into_owned();
    let paths: Vec<&str> = extra
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    assert!(
        !paths.is_empty(),
        "VMP_LOADER_PROBE_EXTRA is set but lists no executable"
    );
    for (index, path) in paths.iter().enumerate() {
        gate(Path::new(path), &format!("extra{index}"));
    }
}
