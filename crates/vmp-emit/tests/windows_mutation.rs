//! Windows-only gate for mutated and relocated code.
//!
//! Every other test in this crate checks that the output is *shaped* the way we
//! intended. This one hands it to the operating system and to the CPU instead:
//!
//! 1. `MapFileAndCheckSumW` recomputes the checksum independently of
//!    [`vmp_pe`], so the stored value is verified by the same implementation
//!    the Windows SDK tooling uses.
//! 2. `LoadLibraryExW` with `LOAD_LIBRARY_AS_IMAGE_RESOURCE` maps the file
//!    through the kernel's image path, validating the headers exactly as a real
//!    load would, without running code.
//! 3. The original and the protected executable are run with identical
//!    arguments and environment; exit code, stdout and stderr must match byte
//!    for byte. The probe panics six frames deep and catches at the top, so
//!    this step exercises the exception directory of the relocated copies —
//!    the one thing no amount of re-parsing can check.
//!
//! The whole file is `cfg(windows)`; elsewhere it compiles to nothing and the
//! gate is reported as not run.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use vmp_emit::{protect, Options, Outcome};
use vmp_pe::{PeFile, PeImage};
use vmp_types::Rva;
use vmp_x86::{decode_function, Image};

/// Loader-aware Windows entry points.
///
/// Duplicated from the `vmp-pe` gate rather than shared: a test helper that
/// two crates depend on is a third place for the checks to drift out of sync
/// with what each gate actually needs.
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

    const CHECKSUM_SUCCESS: u32 = 0;
    const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x0000_0020;
    const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x0000_0002;

    fn wide(path: &Path) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// The checksum stored in the header and the one imagehlp computes.
    pub fn map_file_and_checksum(path: &Path) -> Result<(u32, u32), u32> {
        let name = wide(path);
        let mut header_sum = 0u32;
        let mut checksum = 0u32;
        let status = unsafe { MapFileAndCheckSumW(name.as_ptr(), &mut header_sum, &mut checksum) };
        if status == CHECKSUM_SUCCESS {
            Ok((header_sum, checksum))
        } else {
            Err(status)
        }
    }

    /// Whether the kernel accepts the file as an image.
    pub fn maps_as_image(path: &Path) -> Result<(), u32> {
        let name = wide(path);
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
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

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vmp-emit-gate-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temporary directory must be creatable");
    dir
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

/// Every `.pdata` entry, which is the widest set of function entry points a
/// stripped binary offers.
fn entry_points(pe: &PeFile) -> Vec<Rva> {
    pe.exception_table
        .as_ref()
        .expect("an x64 image has an exception directory")
        .functions()
        .map(|function| function.begin)
        .collect()
}

fn reported_junk(report: &vmp_mutation::Report) -> usize {
    report
        .applied
        .iter()
        .filter(|(name, _)| name.starts_with("junk-"))
        .map(|(_, count)| *count)
        .sum()
}

fn instruction_count(pe: &PeFile, data: &[u8], entry: Rva) -> usize {
    decode_function(Image::new(pe, data), entry)
        .unwrap_or_else(|error| panic!("the function at {entry} must decode: {error}"))
        .instruction_count()
}

fn assert_junk_report_matches_bytes(
    original: &[u8],
    protected: &[u8],
    outcome: &Outcome,
    label: &str,
) {
    let original_pe = PeFile::parse(original).expect("the original probe must parse");
    let protected_pe = PeFile::parse(protected).expect("the protected probe must parse");

    for function in &outcome.protected {
        let before = instruction_count(&original_pe, original, function.original);
        let after = instruction_count(&protected_pe, protected, function.relocated);
        let observed = after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "{label}: the copy at {} physically lost instructions",
                function.relocated
            )
        });
        let jump_expansions = function
            .report
            .applied
            .get("indirect-jump-to-push-ret")
            .copied()
            .unwrap_or(0);
        assert_eq!(
            observed,
            reported_junk(&function.report) + jump_expansions,
            "{label}: physical instruction increase in the copy at {} disagrees with junk plus jmp-to-push-ret expansion",
            function.relocated
        );
    }
}

fn gate(probe: &Path, label: &str, options: &Options) -> Outcome {
    let original = std::fs::read(probe)
        .unwrap_or_else(|error| panic!("reading {} failed: {error}", probe.display()));
    let image = PeImage::from_bytes(original.clone()).expect("the probe must parse");
    eprintln!(
        "{label}: dll_characteristics={:#06x} guard_flags(hex)={:x?} control_flow_guard={}",
        image.pe().optional.dll_characteristics,
        image.pe().features.guard_flags,
        image.pe().features.control_flow_guard
    );
    let entries = entry_points(image.pe());

    let (output, outcome) = protect(image, &entries, options)
        .unwrap_or_else(|error| panic!("{label}: protecting the probe failed: {error}"));
    assert!(
        !outcome.protected.is_empty(),
        "{label}: the gate proves nothing if no function was mutated"
    );
    eprintln!(
        "{label}: mutated {} of {} functions",
        outcome.protected.len(),
        entries.len()
    );

    let parsed = PeFile::parse(output.bytes()).expect("the protected probe must reparse");
    let dir = scratch_dir(label);
    let protected_path = dir.join("protected-mutation-probe.exe");
    std::fs::write(&protected_path, output.bytes()).expect("the protected image must be writable");

    // 1. Independent checksum oracle.
    let (header_sum, computed) = os::map_file_and_checksum(&protected_path)
        .unwrap_or_else(|status| panic!("{label}: MapFileAndCheckSumW failed with {status}"));
    assert_eq!(
        header_sum, computed,
        "{label}: imagehlp must agree with the checksum the writer stored"
    );
    assert_eq!(
        parsed.optional.checksum, computed,
        "{label}: the parsed checksum must be the value imagehlp computes"
    );

    // 2. The kernel's image mapping validates the headers.
    os::maps_as_image(&protected_path).unwrap_or_else(|error| {
        panic!("{label}: the loader refused to map the protected image, GetLastError={error}")
    });

    // 3. Identical observable behaviour, including the unwind through the
    //    relocated frames.
    for argument in ["0", "7"] {
        let before = run(probe, argument);
        let after = run(&protected_path, argument);
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
    assert!(
        String::from_utf8_lossy(&run(probe, "0").1).contains("unwound=true"),
        "{label}: the probe must actually unwind, or the gate checks nothing"
    );
    assert_junk_report_matches_bytes(&original, output.bytes(), &outcome, label);

    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

#[test]
fn a_mutated_probe_still_loads_runs_and_unwinds() {
    gate(
        Path::new(env!("CARGO_BIN_EXE_mutation-probe")),
        "host",
        &Options::default(),
    );
}

#[test]
fn junk_only_still_loads_runs_and_unwinds() {
    let options = Options {
        seed: vmp_mutation::Seed::new(7),
        mutation: vmp_mutation::Options {
            rewrites: false,
            junk: true,
        },
        ..Options::default()
    };
    let outcome = gate(
        Path::new(env!("CARGO_BIN_EXE_mutation-probe")),
        "junk-only",
        &options,
    );
    let junk: usize = outcome
        .protected
        .iter()
        .map(|protected| reported_junk(&protected.report))
        .sum();

    assert!(junk > 0, "the fixed seed must execute the junk-only path");
    assert!(outcome.protected.iter().all(|protected| {
        protected
            .report
            .applied
            .keys()
            .all(|name| name.starts_with("junk-"))
    }));
}

/// The bytes have to actually change, or the gate above would pass on a
/// protector that does nothing.
#[test]
fn protection_changes_the_code_of_every_reported_function() {
    let probe = Path::new(env!("CARGO_BIN_EXE_mutation-probe"));
    let original = std::fs::read(probe).expect("the probe is readable");
    let image = PeImage::from_bytes(original.clone()).expect("the probe must parse");
    let entries = entry_points(image.pe());
    let (output, outcome) = protect(image, &entries, &Options::default()).expect("protects");

    for protected in &outcome.protected {
        assert!(
            protected.report.changes() > 0,
            "the function at {} is reported as protected but nothing was rewritten",
            protected.original
        );
    }
    assert_ne!(
        output.bytes(),
        original.as_slice(),
        "the protected image must differ from its input"
    );
}
