//! Windows gate for automatic SDK marker protection across linker topologies.

#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use iced_x86::{Mnemonic, OpKind, Register};
use vmp_pe::markers::{MarkerCompilationType, SdkMarker};
use vmp_pe::PeFile;
use vmp_types::Rva;
use vmp_x86::sdk_markers::{ApiMarker, SdkApi, SdkApiCall};

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

fn run(path: &Path, argument: &str) -> Output {
    Command::new(path)
        .arg(argument)
        .current_dir(path.parent().expect("probe has a parent directory"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env(
            "SYSTEMROOT",
            std::env::var_os("SYSTEMROOT").unwrap_or_default(),
        )
        .output()
        .unwrap_or_else(|error| panic!("running {} failed: {error}", path.display()))
}

fn json_rva(value: &serde_json::Value) -> Rva {
    let text = value.as_str().expect("reported RVA must be textual");
    Rva(u32::from_str_radix(
        text.strip_prefix("0x")
            .expect("reported RVA must be hexadecimal"),
        16,
    )
    .expect("reported RVA must fit the PE address width"))
}

fn assert_marker_topology(
    pe: &PeFile,
    data: &[u8],
    load_rva: Option<Rva>,
    call_rva: Rva,
    expected_load_prefix: Option<&[u8]>,
    expected_call_prefix: &[u8],
    topology: &str,
) {
    match (load_rva, expected_load_prefix) {
        (Some(load_rva), Some(prefix)) => assert_eq!(
            pe.mapped_range(
                data,
                load_rva,
                u32::try_from(prefix.len()).expect("load prefix length must fit"),
            )
            .expect("SDK register load must be file-backed"),
            prefix,
            "CI fixture did not preserve the required {topology} load"
        ),
        (None, None) => {}
        _ => panic!("CI fixture reported the wrong {topology} load topology"),
    }
    assert_eq!(
        pe.mapped_range(
            data,
            call_rva,
            u32::try_from(expected_call_prefix.len()).expect("call prefix length must fit"),
        )
        .expect("SDK call must be file-backed"),
        expected_call_prefix,
        "CI fixture did not preserve the required {topology} call"
    );
}

fn fallback_stub(api: SdkApi) -> &'static [u8] {
    match api {
        SdkApi::DecryptStringA | SdkApi::DecryptStringW => &[0x48, 0x89, 0xc8, 0xc3],
        SdkApi::FreeString => &[0x31, 0xc0, 0xc3],
        SdkApi::IsProtected => &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
    }
}

fn is_static_physical_mutation(raw: &iced_x86::Instruction) -> bool {
    raw.mnemonic() == Mnemonic::Sub
        && raw.op0_kind() == OpKind::Register
        && raw.op1_kind() == OpKind::Register
        && raw.op0_register() == raw.op1_register()
        && matches!(
            raw.op0_register(),
            Register::EDX | Register::R8D | Register::R9D
        )
}

fn assert_register_calls_use_fallback_stubs(
    original_function: &vmp_ir::Function,
    original_calls: &[SdkApiCall],
    pe: &PeFile,
    data: &[u8],
    relocated: &vmp_ir::Function,
) {
    let expected: Vec<_> = original_calls
        .iter()
        .map(|call| {
            let load_rva = call
                .load_rva
                .expect("register fixture API calls must retain their load RVAs");
            let load = original_function
                .instructions()
                .find(|instruction| instruction.rva() == Some(load_rva))
                .expect("register fixture load must remain in the decoded input");
            assert_eq!(load.bytes().get(..3), Some(&[0x48, 0x8b, 0x05][..]));
            let iat = Rva(u32::try_from(load.raw().ip_rel_memory_address())
                .expect("x64 SDK IAT address must fit the PE coordinate space"));
            (call.api, iat)
        })
        .collect();

    let instructions: Vec<_> = relocated.instructions().collect();
    let rewritten: Vec<_> = instructions
        .windows(2)
        .filter_map(|pair| {
            let load = pair[0];
            let call = pair[1];
            let bytes = load.bytes();
            if bytes.len() != 7
                || bytes[..3] != [0x48, 0x8d, 0x05]
                || call.bytes() != [0xff, 0xd0]
                || load.raw().op0_register() != Register::RAX
                || !load.raw().is_ip_rel_memory_operand()
                || call.raw().op0_register() != Register::RAX
            {
                return None;
            }
            Some(Rva(u32::try_from(load.raw().ip_rel_memory_address())
                .expect("fallback target must fit the PE coordinate space")))
        })
        .collect();
    assert_eq!(
        rewritten.len(),
        expected.len(),
        "every register-loaded runtime-free API call must remain a canonical lea/call pair"
    );
    for ((api, old_iat), target) in expected.into_iter().zip(rewritten) {
        assert_ne!(
            target, old_iat,
            "rewritten load must not retain its SDK IAT"
        );
        assert_eq!(
            pe.mapped_range(
                data,
                target,
                u32::try_from(fallback_stub(api).len()).expect("stub length must fit"),
            )
            .expect("fallback target must be mapped inside the protected image"),
            fallback_stub(api),
            "rewritten register load must resolve to the exact local fallback body for {api:?}"
        );
    }
}

fn assert_automatic_sdk_marker_path(
    source: PathBuf,
    expected_load_prefix: Option<&[u8]>,
    expected_call_prefix: &[u8],
    topology: &str,
) {
    let original = std::fs::read(&source).expect("CI-built SDK probe must be readable");
    let original_pe = PeFile::parse(&original).expect("CI-built SDK probe must parse");
    let original_image = vmp_x86::Image::new(&original_pe, &original);
    let markers = vmp_x86::sdk_markers::discover_direct_api_markers(original_image)
        .expect("CI-built SDK markers must scan");
    let (begin_load, begin_call, begin_next) = markers
        .iter()
        .find_map(|marker| match marker {
            ApiMarker::Begin {
                load_rva,
                call_rva,
                next_rva,
                ..
            } => Some((*load_rva, *call_rva, *next_rva)),
            ApiMarker::End { .. } => None,
        })
        .expect("probe must have one SDK Begin");
    assert_marker_topology(
        &original_pe,
        &original,
        begin_load,
        begin_call,
        expected_load_prefix,
        expected_call_prefix,
        topology,
    );
    let ends: Vec<_> = markers
        .iter()
        .filter_map(|marker| match marker {
            ApiMarker::End {
                load_rva,
                call_rva,
                next_rva,
            } => Some((*load_rva, *call_rva, *next_rva)),
            ApiMarker::Begin { .. } => None,
        })
        .collect();
    assert_eq!(ends.len(), 2, "probe must exercise two distinct SDK Ends");
    for (load_rva, call_rva, _) in &ends {
        assert_marker_topology(
            &original_pe,
            &original,
            *load_rva,
            *call_rva,
            expected_load_prefix,
            expected_call_prefix,
            topology,
        );
    }
    let original_runtime = original_pe
        .exception_table
        .as_ref()
        .expect("x64 probe must have an exception table")
        .functions()
        .find(|function| begin_call >= function.begin && begin_call < function.end)
        .expect("Begin must belong to one runtime function");
    let original_function = vmp_x86::decode_function(original_image, original_runtime.begin)
        .expect("SDK probe function must decode");
    let end_calls: Vec<_> = ends.iter().map(|(_, call, _)| *call).collect();
    let region = vmp_x86::marker_region::recover_marker_region_from(
        &original_function,
        begin_call,
        begin_next,
        &end_calls,
    )
    .expect("SDK probe region must recover");
    assert_eq!(region.reached_ends.len(), 2);
    let api_calls =
        vmp_x86::sdk_markers::discover_sdk_api_calls(original_image, &original_function)
            .expect("runtime-free SDK calls must scan");
    for api in [
        SdkApi::IsProtected,
        SdkApi::DecryptStringA,
        SdkApi::DecryptStringW,
        SdkApi::FreeString,
    ] {
        assert!(api_calls.iter().any(|call| call.api == api));
    }
    let source_dir = source.parent().expect("probe has a parent directory");
    let directory = std::env::temp_dir().join(format!(
        "vmp-cli-windows-sdk-{topology}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("scratch directory must be created");
    let input = directory.join("sdk-probe.exe");
    let runtime = directory.join("VMProtectSDK64.dll");
    std::fs::copy(&source, &input).expect("SDK probe must copy");
    std::fs::copy(source_dir.join("VMProtectSDK64.dll"), &runtime)
        .expect("SDK runtime stub must copy");
    let protected = directory.join("sdk-protected.exe");

    let command = Command::new(env!("CARGO_BIN_EXE_vmp"))
        .arg("protect")
        .arg(&input)
        .arg("--output")
        .arg(&protected)
        .arg("--seed")
        .arg("1")
        .arg("--json")
        .output()
        .expect("SDK-selected CLI must start");
    assert!(
        command.status.success(),
        "SDK-selected CLI failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&command.stdout).expect("CLI report must be JSON");
    assert_eq!(report["summary"]["requested"], 1);
    assert_eq!(report["summary"]["protected"], 1);
    assert_eq!(report["summary"]["skipped"], 0);
    let relocated_rva = json_rva(&report["protected"][0]["relocated"]);

    let bytes = std::fs::read(&protected).expect("protected image must be readable");
    let pe = PeFile::parse(&bytes).expect("protected image must reparse");
    assert_eq!(
        pe.mapped_range(&bytes, original_runtime.begin, 5)
            .expect("original runtime entry remains mapped"),
        original_pe
            .mapped_range(&original, original_runtime.begin, 5)
            .expect("original runtime entry is mapped"),
        "region-only excision must not redirect the covering function entry"
    );
    let relocated_runtime = pe
        .exception_table
        .as_ref()
        .expect("protected probe must have an exception table")
        .functions()
        .find(|function| function.begin == relocated_rva)
        .expect("relocated slice must have a runtime entry");
    let unwind = vmp_pe::UnwindInfo::parse(&pe, &bytes, relocated_runtime.unwind_info)
        .expect("relocated slice unwind must parse");
    assert_eq!(unwind.chained, Some(original_runtime));
    let relocated = vmp_x86::decode_function(vmp_x86::Image::new(&pe, &bytes), relocated_rva)
        .expect("relocated SDK slice must decode");
    if expected_load_prefix.is_some() {
        assert_register_calls_use_fallback_stubs(
            &original_function,
            &api_calls,
            &pe,
            &bytes,
            &relocated,
        );
    }
    let continuation_targets: Vec<_> = relocated
        .instructions()
        .filter_map(|instruction| {
            u32::try_from(instruction.raw().near_branch_target())
                .ok()
                .map(Rva)
        })
        .filter(|target| ends.iter().any(|(_, _, next)| next == target))
        .collect();
    for (_, _, continuation) in &ends {
        assert_eq!(
            continuation_targets
                .iter()
                .filter(|target| *target == continuation)
                .count(),
            1,
            "each End must resume at its own original continuation"
        );
    }
    assert!(
        vmp_x86::sdk_markers::discover_sdk_api_calls(vmp_x86::Image::new(&pe, &bytes), &relocated,)
            .expect("protected SDK slice API scan")
            .is_empty(),
        "relocated slice must use local fallback stubs, not SDK imports"
    );
    let (stored, computed) = os::checksums(&protected).expect("imagehlp checksum must succeed");
    assert_eq!(stored, computed);
    assert_eq!(pe.optional.checksum, computed);
    os::maps_as_image(&protected).expect("Windows loader must map protected SDK image");

    for argument in ["0", "7", "9", "13"] {
        let before = run(&input, argument);
        let after = run(&protected, argument);
        assert!(
            before.status.success(),
            "unprotected SDK probe did not execute successfully: {}",
            String::from_utf8_lossy(&before.stderr)
        );
        assert!(!before.stdout.is_empty(), "SDK probe emitted no result");
        assert!(before.stderr.is_empty(), "SDK probe emitted diagnostics");
        assert_eq!(before.status.code(), after.status.code());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
        match argument {
            "0" => assert_eq!(
                after.stdout, b"result=171 unwound=false\r\n",
                "the even End path must preserve its exact continuation result"
            ),
            "7" => assert_eq!(
                after.stdout, b"result=75 unwound=false\r\n",
                "the odd End path must preserve its exact continuation result"
            ),
            "9" => assert_eq!(
                after.stdout, b"result=912 unwound=false\r\n",
                "the no-End return must preserve its independent result"
            ),
            "13" => assert_eq!(
                after.stdout, b"code=e0421001 unwound=true\r\n",
                "the exact exception must unwind through the relocated slice"
            ),
            _ => {}
        }
    }

    let _ = std::fs::remove_dir_all(directory);
}

fn assert_automatic_static_marker_path(source: PathBuf) {
    let original = std::fs::read(&source).expect("CI-built static SDK probe must be readable");
    let original_pe = PeFile::parse(&original).expect("CI-built static SDK probe must parse");
    let markers = vmp_pe::markers::discover_asm_markers(&original_pe, &original)
        .expect("static SDK markers must scan");
    let (begin, begin_next) = markers
        .iter()
        .find_map(|marker| match marker {
            SdkMarker::Begin {
                rva,
                next_rva,
                tag: 2,
                compilation_type: MarkerCompilationType::Mutation,
            } => Some((*rva, *next_rva)),
            _ => None,
        })
        .expect("probe must contain one Mutation static Begin");
    let ends: Vec<_> = markers
        .iter()
        .filter_map(|marker| match marker {
            SdkMarker::End { rva, next_rva } => Some((*rva, *next_rva)),
            SdkMarker::Begin { .. } => None,
        })
        .collect();
    assert_eq!(
        markers.len(),
        3,
        "probe must contain only one Begin and two Ends"
    );
    assert_eq!(ends.len(), 2, "probe must contain two distinct static Ends");
    assert_eq!(
        original_pe
            .mapped_range(&original, begin, 18)
            .expect("static Begin must be file-backed"),
        b"\xeb\x10VMProtect begin\x02"
    );
    for (end, _) in &ends {
        assert_eq!(
            original_pe
                .mapped_range(&original, *end, 16)
                .expect("static End must be file-backed"),
            b"\xeb\x0eVMProtect end\0"
        );
    }
    let original_runtime = original_pe
        .exception_table
        .as_ref()
        .expect("x64 static probe must have an exception table")
        .functions()
        .find(|function| begin >= function.begin && begin < function.end)
        .expect("static Begin must belong to one runtime function");
    let original_function = vmp_x86::decode_function(
        vmp_x86::Image::new(&original_pe, &original),
        original_runtime.begin,
    )
    .expect("static SDK probe function must decode");
    assert!(
        !original_function
            .instructions()
            .any(|instruction| is_static_physical_mutation(instruction.raw())),
        "unprotected static fixture must not already contain a Mutation replacement"
    );
    let end_rvas: Vec<_> = ends.iter().map(|(rva, _)| *rva).collect();
    let region = vmp_x86::marker_region::recover_marker_region_from(
        &original_function,
        begin,
        begin_next,
        &end_rvas,
    )
    .expect("static SDK probe region must recover");
    assert_eq!(region.reached_ends.len(), 2);

    let directory = std::env::temp_dir().join(format!(
        "vmp-cli-windows-sdk-static-marker-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("static scratch directory must be created");
    let input = directory.join("sdk-static-probe.exe");
    std::fs::copy(&source, &input).expect("static SDK probe must copy");
    let protected = directory.join("sdk-static-protected.exe");
    let command = Command::new(env!("CARGO_BIN_EXE_vmp"))
        .arg("protect")
        .arg(&input)
        .arg("--output")
        .arg(&protected)
        .arg("--seed")
        .arg("1")
        .arg("--json")
        .output()
        .expect("static SDK-selected CLI must start");
    assert!(
        command.status.success(),
        "static SDK-selected CLI failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&command.stdout).expect("static CLI report must be JSON");
    assert_eq!(report["summary"]["requested"], 1);
    assert_eq!(report["summary"]["protected"], 1);
    assert_eq!(report["summary"]["skipped"], 0);
    let rewrite_count: u64 = report["protected"][0]["rewrites"]
        .as_object()
        .expect("static rewrite report must be an object")
        .values()
        .map(|count| count.as_u64().expect("rewrite count must be numeric"))
        .sum();
    assert_ne!(
        rewrite_count, 0,
        "tag-2 static protection must perform deterministic Mutation work"
    );
    let relocated_rva = json_rva(&report["protected"][0]["relocated"]);
    let relocated_len = u32::try_from(
        report["protected"][0]["length"]
            .as_u64()
            .expect("relocated static length must be numeric"),
    )
    .expect("relocated static length must fit");

    let bytes = std::fs::read(&protected).expect("protected static image must be readable");
    let pe = PeFile::parse(&bytes).expect("protected static image must reparse");
    assert_eq!(
        pe.mapped_range(&bytes, original_runtime.begin, 5)
            .expect("static covering entry remains mapped"),
        original_pe
            .mapped_range(&original, original_runtime.begin, 5)
            .expect("original static covering entry is mapped"),
        "region-only static protection must preserve the covering function entry"
    );
    let begin_patch = pe
        .mapped_range(&bytes, begin, 18)
        .expect("original static Begin remains mapped");
    assert_eq!(begin_patch[0], 0xe9, "static Begin must redirect");
    assert!(begin_patch[5..].iter().all(|byte| *byte == 0x90));
    let displacement = i32::from_le_bytes(
        begin_patch[1..5]
            .try_into()
            .expect("static Begin jump must have a rel32 displacement"),
    );
    let begin_target = i64::from(begin.get()) + 5 + i64::from(displacement);
    assert_eq!(
        u32::try_from(begin_target).expect("static Begin target must fit an RVA"),
        relocated_rva.get(),
        "static Begin must target the reported relocated slice entry"
    );
    for (end, _) in &ends {
        let end_patch = pe
            .mapped_range(&bytes, *end, 16)
            .expect("original static End remains mapped");
        assert_eq!(&end_patch[..2], &[0xeb, 0x0e]);
        assert!(end_patch[2..].iter().all(|byte| *byte == 0));
    }
    let relocated_runtime = pe
        .exception_table
        .as_ref()
        .expect("protected static probe must have an exception table")
        .functions()
        .find(|function| function.begin == relocated_rva)
        .expect("relocated static slice must have a runtime entry");
    let unwind = vmp_pe::UnwindInfo::parse(&pe, &bytes, relocated_runtime.unwind_info)
        .expect("relocated static slice unwind must parse");
    assert_eq!(unwind.chained, Some(original_runtime));
    let runtime_len = relocated_runtime
        .end
        .get()
        .checked_sub(relocated_runtime.begin.get())
        .expect("relocated static runtime range must be ordered");
    assert_eq!(
        relocated_len, runtime_len,
        "CLI report length must equal the independently parsed runtime extent"
    );
    let relocated = pe
        .mapped_range(&bytes, relocated_runtime.begin, runtime_len)
        .expect("relocated static slice must be mapped");
    assert!(!relocated
        .windows(15)
        .any(|window| window == b"VMProtect begin"));
    assert!(!relocated
        .windows(13)
        .any(|window| window == b"VMProtect end"));
    let relocated_function =
        vmp_x86::decode_function(vmp_x86::Image::new(&pe, &bytes), relocated_runtime.begin)
            .expect("relocated static function must decode");
    let has_physical_mutation = relocated_function
        .instructions()
        .any(|instruction| is_static_physical_mutation(instruction.raw()));
    assert!(
        has_physical_mutation,
        "relocated static slice must contain a canonical physical Mutation rewrite"
    );
    let (stored, computed) = os::checksums(&protected).expect("static checksum must succeed");
    assert_eq!(stored, computed);
    assert_eq!(pe.optional.checksum, computed);
    os::maps_as_image(&protected).expect("Windows loader must map protected static image");

    for argument in ["0", "7", "9", "13"] {
        let before = run(&input, argument);
        let after = run(&protected, argument);
        assert!(before.status.success(), "unprotected static probe failed");
        assert_eq!(before.status.code(), after.status.code());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
        match argument {
            "0" => assert_eq!(after.stdout, b"result=171 unwound=false\r\n"),
            "7" => assert_eq!(after.stdout, b"result=75 unwound=false\r\n"),
            "9" => assert_eq!(after.stdout, b"result=912 unwound=false\r\n"),
            "13" => assert_eq!(after.stdout, b"code=e0421001 unwound=true\r\n"),
            _ => {}
        }
    }
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn automatic_direct_iat_sdk_marker_path_loads_runs_and_preserves_behavior() {
    let source = PathBuf::from(
        std::env::var_os("VMP_SDK_PROBE").expect("VMP_SDK_PROBE must name the CI-built probe"),
    );
    assert_automatic_sdk_marker_path(source, None, &[0xff, 0x15], "direct-iat");
}

#[test]
fn automatic_import_thunk_sdk_marker_path_loads_runs_and_preserves_behavior() {
    let source = PathBuf::from(
        std::env::var_os("VMP_SDK_THUNK_PROBE")
            .expect("VMP_SDK_THUNK_PROBE must name the CI-built probe"),
    );
    assert_automatic_sdk_marker_path(source, None, &[0xe8], "import-thunk");
}

#[test]
fn automatic_register_transfer_sdk_marker_path_loads_runs_and_preserves_behavior() {
    let source = PathBuf::from(
        std::env::var_os("VMP_SDK_REGISTER_PROBE")
            .expect("VMP_SDK_REGISTER_PROBE must name the CI-built probe"),
    );
    assert_automatic_sdk_marker_path(
        source,
        Some(&[0x48, 0x8b, 0x05]),
        &[0xff, 0xd0],
        "register-transfer",
    );
}

#[test]
fn automatic_static_sdk_marker_path_loads_runs_and_preserves_behavior() {
    let source = PathBuf::from(
        std::env::var_os("VMP_SDK_STATIC_PROBE")
            .expect("VMP_SDK_STATIC_PROBE must name the CI-built probe"),
    );
    assert_automatic_static_marker_path(source);
}
