//! The stable, versioned `protect` report.
//!
//! Like the `inspect` and `disasm` contracts, the DTO is decoupled from the
//! backend types: `vmp-emit` is expected to grow refusals and `vmp-mutation` to
//! grow rewrites, and neither may change the shape of this JSON.

use std::collections::BTreeMap;

use serde::Serialize;
use vmp_compiler::{Outcome, Protected, Seed, SkipReason, Skipped};

/// JSON schema version. Bumped on incompatible changes to the contract.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Serialize)]
pub struct ProtectReport {
    pub schema_version: &'static str,
    pub input: FileInfo,
    pub output: FileInfo,
    /// The value every per-function random stream was derived from; passing it
    /// back to `--seed` reproduces this run byte for byte.
    pub seed: u64,
    pub summary: Summary,
    pub protected: Vec<ProtectedEntry>,
    /// Every refusal, in the order the entries were requested.
    pub skipped: Vec<SkippedEntry>,
    /// How many functions each refusal accounts for, keyed by its stable name.
    pub skip_reasons: BTreeMap<&'static str, usize>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct Summary {
    /// Function entries the run was asked about. Each one is accounted for by
    /// exactly one of the two counts below.
    pub requested: usize,
    pub protected: usize,
    pub skipped: usize,
}

#[derive(Serialize)]
pub struct ProtectedEntry {
    /// Entry point in the input image; in the output it holds the jump stub.
    pub original: String,
    /// Entry point of the mutated copy.
    pub relocated: String,
    /// Length of the mutated copy in bytes.
    pub length: u32,
    /// How many times each rewrite fired, keyed by its stable name.
    pub rewrites: BTreeMap<&'static str, usize>,
}

#[derive(Serialize)]
pub struct SkippedEntry {
    pub rva: String,
    /// Stable kebab-case name of the refusal; the same names key
    /// [`ProtectReport::skip_reasons`].
    pub reason: &'static str,
}

impl ProtectReport {
    pub fn build(
        input: &str,
        input_size: u64,
        output: &str,
        output_size: u64,
        seed: Seed,
        outcome: &Outcome,
    ) -> ProtectReport {
        let mut skip_reasons: BTreeMap<&'static str, usize> = BTreeMap::new();
        for skipped in &outcome.skipped {
            *skip_reasons
                .entry(reason_name(&skipped.reason))
                .or_default() += 1;
        }

        ProtectReport {
            schema_version: SCHEMA_VERSION,
            input: FileInfo {
                path: input.to_owned(),
                size: input_size,
            },
            output: FileInfo {
                path: output.to_owned(),
                size: output_size,
            },
            seed: seed.get(),
            summary: Summary {
                // Every requested entry ends up in exactly one of the two
                // lists, so their sum is what the run was asked for
                requested: outcome.protected.len() + outcome.skipped.len(),
                protected: outcome.protected.len(),
                skipped: outcome.skipped.len(),
            },
            protected: outcome.protected.iter().map(protected_entry).collect(),
            skipped: outcome.skipped.iter().map(skipped_entry).collect(),
            skip_reasons,
        }
    }
}

fn protected_entry(protected: &Protected) -> ProtectedEntry {
    ProtectedEntry {
        original: protected.original.to_string(),
        relocated: protected.relocated.to_string(),
        length: protected.length,
        rewrites: protected.report.applied.clone(),
    }
}

fn skipped_entry(skipped: &Skipped) -> SkippedEntry {
    SkippedEntry {
        rva: skipped.rva.to_string(),
        reason: reason_name(&skipped.reason),
    }
}

/// The stable name of a refusal.
///
/// These strings are the contract: a consumer groups and counts by them, so a
/// new [`SkipReason`] gets a new name and an existing one keeps its own even if
/// the variant is renamed. The payloads are deliberately dropped — they are
/// prose meant for a human reading the source, not a machine.
pub fn reason_name(reason: &SkipReason) -> &'static str {
    vmp_compiler::skip_reason_name(reason)
}

/// Prints the run as a readable summary.
pub fn print_text(report: &ProtectReport) {
    println!("{}", render_text(report));
}

/// Lays the report out as the text the CLI prints.
///
/// Kept separate from the printing so the layout can be asserted on without
/// capturing stdout; a run over a real binary has hundreds of entries, which is
/// exactly the case worth pinning.
fn render_text(report: &ProtectReport) -> String {
    let mut lines = vec![
        format!(
            "Input:           {} ({} bytes)",
            report.input.path, report.input.size
        ),
        format!(
            "Output:          {} ({} bytes)",
            report.output.path, report.output.size
        ),
        format!("Seed:            {} ({:#018x})", report.seed, report.seed),
        format!(
            "Functions:       {} requested, {} protected, {} skipped",
            report.summary.requested, report.summary.protected, report.summary.skipped
        ),
    ];

    if !report.protected.is_empty() {
        lines.push(String::new());
        lines.push(format!("Protected ({}):", report.summary.protected));
        for entry in &report.protected {
            lines.push(format!(
                "  {} -> {}  {:>5} bytes, {}",
                entry.original,
                entry.relocated,
                entry.length,
                describe_rewrites(&entry.rewrites)
            ));
        }
    }

    // The individual addresses are in the JSON; a human wants to know which
    // check did the refusing, and how often
    if !report.skip_reasons.is_empty() {
        lines.push(String::new());
        lines.push(format!("Skipped ({}), by reason:", report.summary.skipped));
        for (reason, count) in &report.skip_reasons {
            lines.push(format!("  {reason:<24} {count}"));
        }
    }

    lines.join("\n")
}

fn describe_rewrites(rewrites: &BTreeMap<&'static str, usize>) -> String {
    if rewrites.is_empty() {
        return "no rewrites".to_owned();
    }
    let total: usize = rewrites.values().sum();
    let parts: Vec<String> = rewrites
        .iter()
        .map(|(name, count)| format!("{name} x{count}"))
        .collect();
    format!("{total} rewrite(s): {}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    use vmp_compiler::MutationReport as Report;
    use vmp_types::Rva;

    fn protected(original: u32, relocated: u32, rewrites: &[(&'static str, usize)]) -> Protected {
        Protected {
            original: Rva(original),
            relocated: Rva(relocated),
            length: 61,
            report: Report {
                applied: rewrites.iter().copied().collect(),
                visited: 24,
                frozen: 5,
            },
        }
    }

    fn skipped(rva: u32, reason: SkipReason) -> Skipped {
        Skipped {
            rva: Rva(rva),
            reason,
        }
    }

    fn build(outcome: &Outcome) -> ProtectReport {
        ProtectReport::build("in.exe", 1024, "out.exe", 2048, Seed::new(7), outcome)
    }

    /// The rendered text with runs of spaces collapsed, so an assertion is
    /// about the content of a line rather than its column widths.
    fn normalized(report: &ProtectReport) -> Vec<String> {
        render_text(report)
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    #[test]
    fn a_protected_function_reports_its_move_and_its_rewrites() {
        let outcome = Outcome {
            protected: vec![protected(0x1010, 0x27000, &[("zeroing-xor-to-sub", 2)])],
            skipped: Vec::new(),
        };
        let report = build(&outcome);

        assert_eq!(report.summary.requested, 1);
        assert_eq!(report.summary.protected, 1);
        assert_eq!(report.summary.skipped, 0);

        let lines = normalized(&report);
        assert!(
            lines.contains(&"Seed: 7 (0x0000000000000007)".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"Functions: 1 requested, 1 protected, 0 skipped".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.contains(
                &"0x00001010 -> 0x00027000 61 bytes, 2 rewrite(s): zeroing-xor-to-sub x2"
                    .to_owned()
            ),
            "{lines:?}"
        );
        // Nothing was refused, so the section that would list refusals is gone
        assert!(
            !lines.iter().any(|line| line.starts_with("Skipped")),
            "{lines:?}"
        );
    }

    #[test]
    fn skipped_functions_are_grouped_by_a_stable_reason_name() {
        let outcome = Outcome {
            protected: vec![protected(0x1010, 0x27000, &[("zeroing-xor-to-sub", 1)])],
            skipped: vec![
                skipped(0x1100, SkipReason::NoUnwindData),
                skipped(0x1200, SkipReason::HasAbsoluteFixups),
                skipped(0x1300, SkipReason::NoUnwindData),
                skipped(0x1400, SkipReason::TooShortForStub { length: 3 }),
            ],
        };
        let report = build(&outcome);

        assert_eq!(report.summary.requested, 5);
        assert_eq!(report.summary.skipped, 4);
        assert_eq!(report.skip_reasons.get("no-unwind-data"), Some(&2));
        assert_eq!(report.skip_reasons.get("has-absolute-fixups"), Some(&1));
        assert_eq!(report.skip_reasons.get("too-short-for-stub"), Some(&1));

        let lines = normalized(&report);
        assert!(
            lines.contains(&"Skipped (4), by reason:".to_owned()),
            "{lines:?}"
        );
        assert!(lines.contains(&"no-unwind-data 2".to_owned()), "{lines:?}");
        assert!(
            lines.contains(&"has-absolute-fixups 1".to_owned()),
            "{lines:?}"
        );
        // The grouped view is a summary; the addresses stay in the JSON
        assert!(!lines.iter().any(|line| line.contains("0x00001300")));

        let json = serde_json::to_string(&report).expect("the report serializes");
        assert!(
            json.contains(r#"{"rva":"0x00001300","reason":"no-unwind-data"}"#),
            "{json}"
        );
        assert!(
            json.contains(r#"{"rva":"0x00001400","reason":"too-short-for-stub"}"#),
            "{json}"
        );
    }
}
