use std::process::Command;

#[path = "support/virtualization_image.rs"]
mod fixture;

#[test]
fn cli_publishes_replayable_vm_pe_and_preserves_destination_on_refusal() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cli-virtualization-proof");
    std::fs::create_dir_all(&directory).expect("proof directory");
    let input = directory.join("input.exe");
    let output = directory.join("protected.exe");
    std::fs::write(&input, fixture::image(0x1000)).expect("input");
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_vmp"))
            .arg("protect")
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .args([
                "--mode",
                "virtualization",
                "--rva",
                "0x1000",
                "--seed",
                "37",
                "--json",
            ])
            .output()
            .expect("CLI")
    };
    let result = invoke();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("JSON");
    assert_eq!(report["mode"], "virtualization");
    assert_eq!(report["seed"], 37);
    assert_eq!(report["variant"], 37);
    assert_eq!(report["source_length"], 6);
    let protected = std::fs::read(&output).expect("published PE");
    let pe = vmp_pe::PeFile::parse(&protected).expect("PE");
    let gate = pe
        .mapped_range(&protected, vmp_types::Rva(0x1000), 7)
        .expect("gate");
    assert_eq!(gate[0], 0xe9);
    assert_eq!(&gate[5..], &[0x90, 0xc3]);
    let target = 0x1005_i64 + i64::from(i32::from_le_bytes(gate[1..5].try_into().expect("rel32")));
    assert_eq!(
        report["entry"],
        vmp_types::Rva(u32::try_from(target).expect("target RVA")).to_string()
    );
    assert!(invoke().status.success());
    assert_eq!(protected, std::fs::read(&output).expect("replay"));
    std::fs::write(&input, fixture::image(0x1003)).expect("interior caller");
    let rejected = invoke();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("replaced interior"));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        protected,
        std::fs::read(&output).expect("unchanged destination")
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
}

#[test]
fn virtualization_requires_one_explicit_rva_before_reading_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_vmp"))
        .args([
            "protect",
            "missing-input.exe",
            "--output",
            "unused-output.exe",
            "--mode",
            "virtualization",
        ])
        .output()
        .expect("CLI");
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).expect("stderr");
    assert!(
        error.contains("virtualization requires exactly one --rva"),
        "{error}"
    );
}
