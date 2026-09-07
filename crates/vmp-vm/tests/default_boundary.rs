//! Check the current public API from an independent consumer

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn cargo() -> Command {
    Command::new(env!("CARGO"))
}

#[test]
fn only_current_implementation_is_available() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("legacy-oracle"),
        "old implementation feature remains"
    );
}

#[test]
fn cli_does_not_expose_unintegrated_virtualization() {
    let output = cargo()
        .args([
            "tree", "-p", "vmp-cli", "--edges", "normal", "--prefix", "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Cargo dependency inspection must run");
    assert!(output.status.success(), "{output:?}");
    let tree = String::from_utf8(output.stdout).expect("Cargo prints UTF-8");
    assert!(!tree.contains("vmp-runtime-windows"), "{tree}");
    assert!(!tree.contains("vmp-vm "), "{tree}");
}

struct Consumer(PathBuf);

impl Consumer {
    fn check(&self, source: &str, features: bool) -> Output {
        fs::write(self.0.join("src/lib.rs"), source).expect("consumer source must be writable");
        let mut command = cargo();
        command
            .args(["check", "--offline", "--quiet"])
            .current_dir(&self.0)
            // A separate target directory avoids the parent cargo test build lock
            .env("CARGO_TARGET_DIR", self.0.join("target"));
        if features {
            command.arg("--all-features");
        }
        command.output().expect("consumer check must run")
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ordinary_consumers_expose_only_current_api() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = std::env::temp_dir().join(format!("vmp-default-boundary-{}", std::process::id()));
    fs::create_dir(&path).expect("consumer directory must be newly created");
    let consumer = Consumer(path);
    fs::create_dir(consumer.0.join("src")).expect("consumer source directory must be writable");
    // TOML literal strings preserve Windows path separators
    fs::write(
        consumer.0.join("Cargo.toml"),
        format!(
            "[package]\nname = 'vmp-default-boundary'\nversion = '0.0.0'\nedition = '2021'\n\
             [workspace]\n\
             [dependencies]\nvmp-vm = {{ path = '{}' }}\n",
            root.display()
        ),
    )
    .expect("consumer manifest must be writable");

    let primitives = "pub use vmp_vm::{operand::{Condition, Register, Width}, stack::Machine, logical::{lower_instruction, Command}, instance::BodyInstance};";
    let output = consumer.check(primitives, false);
    assert!(output.status.success(), "{output:?}");

    for (crate_name, item) in [
        ("vmp_vm", "bytecode"),
        ("vmp_vm", "bytecode_v2"),
        ("vmp_vm", "host"),
        ("vmp_vm", "host_v2"),
        ("vmp_vm", "lowering"),
        ("vmp_vm", "stack_v2"),
    ] {
        let source = format!("pub use {crate_name}::{item};");
        let output = consumer.check(&source, false);
        assert!(
            !output.status.success(),
            "default consumer exposed {crate_name}::{item}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error[E0432]") && stderr.contains(item),
            "{stderr}"
        );
        let output = consumer.check(&source, true);
        assert!(
            !output.status.success(),
            "removed API returned with all features: {output:?}"
        );
    }
}
