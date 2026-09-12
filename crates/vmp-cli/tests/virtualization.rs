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
    let original = vmp_pe::PeFile::parse(&fixture::image(0x1000)).expect("original PE");
    let instance = &pe.sections[original.sections.len()];
    assert_eq!(report["instance"], instance.virtual_address.to_string());
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
    for selectors in [
        vec![],
        vec!["--rva", "0x1000", "--rva", "0x1010"],
        vec!["--rva", "0x1000", "--symbol", "leaf"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vmp"))
            .args([
                "protect",
                "missing-input.exe",
                "--output",
                "unused-output.exe",
                "--mode",
                "virtualization",
            ])
            .args(&selectors)
            .output()
            .expect("CLI");
        assert!(!output.status.success(), "{selectors:?}");
        assert!(output.stdout.is_empty(), "{selectors:?}");
        let error = String::from_utf8(output.stderr).expect("stderr");
        assert!(
            error.contains("virtualization requires exactly one --rva"),
            "{selectors:?}: {error}"
        );
    }
}

#[test]
fn symbol_selection_uses_sidecars_and_preserves_output_on_resolution_failure() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cli-virtualization-symbol-proof");
    std::fs::create_dir_all(&directory).expect("proof directory");
    let input = directory.join("input.exe");
    let output = directory.join("protected.exe");
    let map = "# Address Size File Name\n0x140001000 0x7 [  1] leaf\n";
    let mut bytes = fixture::image(0x1000);
    bytes[0x220..0x226].copy_from_slice(&[0xe8, 0xde, 0xff, 0xff, 0xff, 0xc3]);
    std::fs::write(&input, bytes).expect("input");
    std::fs::write(input.with_extension("map"), map).expect("MAP");
    let invoke = |selection: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_vmp"))
            .arg("protect")
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .args(["--mode", "virtualization", "--seed", "37", "--json"])
            .args(selection)
            .output()
            .expect("CLI")
    };
    assert!(invoke(&["--rva", "0x1000"]).status.success());
    let expected = std::fs::read(&output).expect("RVA output");
    for selection in [
        vec!["--symbol", "leaf"],
        vec!["--symbol", "leaf", "--symbol-index", "0"],
    ] {
        let result = invoke(&selection);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("JSON");
        assert_eq!(report["original"], "0x00001000");
        assert_eq!(expected, std::fs::read(&output).expect("symbol output"));
    }
    for (contents, name, diagnostic) in [
        (map.to_owned(), "missing", "was not found"),
        (
            format!("{map}0x140001020 0x6 [  1] leaf\n"),
            "leaf",
            "ambiguous",
        ),
        (
            format!("{map}0x140001020 0x6 [  1] caller\n"),
            "leaf",
            "replaced interior",
        ),
    ] {
        std::fs::write(input.with_extension("map"), contents).expect("MAP");
        let result = invoke(&["--symbol", name]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains(diagnostic), "{error}");
        assert_eq!(
            expected,
            std::fs::read(&output).expect("unchanged destination")
        );
    }
}

#[test]
fn declared_external_entries_are_checked_before_publication() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cli-virtualization-external-proof");
    std::fs::create_dir_all(&directory).expect("proof directory");
    let input = directory.join("input.exe");
    let output = directory.join("protected.exe");
    let mut bytes = fixture::image(0x1000);
    // This caller is not reachable from the PE entry or any relocated pointer
    bytes[0x220..0x226].copy_from_slice(&[0xe8, 0xde, 0xff, 0xff, 0xff, 0xc3]);
    std::fs::write(&input, bytes).expect("input");
    let invoke = |entries: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vmp"));
        command
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
            ]);
        for entry in entries {
            command.args(["--external-entry", entry]);
        }
        command.output().expect("CLI")
    };
    let accepted = invoke(&["0x1010", "0x1000"]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let protected = std::fs::read(&output).expect("published PE");
    for entries in [
        vec!["0x1010", "0x1020"],
        vec!["0x1020", "0x1010"],
        vec!["0x1003"],
    ] {
        let rejected = invoke(&entries);
        assert!(!rejected.status.success(), "{entries:?}");
        assert!(rejected.stdout.is_empty(), "{entries:?}");
        let error = String::from_utf8_lossy(&rejected.stderr);
        assert!(error.contains("replaced interior"), "{entries:?}: {error}");
        assert_eq!(
            protected,
            std::fs::read(&output).expect("unchanged destination")
        );
    }
}
