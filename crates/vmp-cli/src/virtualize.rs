//! CLI adaptation and atomic publication for explicit scalar virtualization.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use vmp_compiler::virtualization::{protect_virtualization, Request};
use vmp_types::Rva;

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    mode: &'static str,
    input: super::protect::FileInfo,
    output: super::protect::FileInfo,
    seed: u64,
    variant: u8,
    original: String,
    entry: String,
    instance: String,
    source_length: u32,
}

pub fn run(
    input: &Path,
    output: &Path,
    rva: Rva,
    external_entries: &[Rva],
    seed: Option<u64>,
    json: bool,
) -> Result<()> {
    let image = std::fs::read(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;
    let input_size = image.len() as u64;
    let seed = super::protection_seed(seed, |bytes| {
        getrandom::fill(bytes).map_err(|error| anyhow!("system CSPRNG failed: {error}"))
    })?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(external_entries.len())
        .context("failed to retain external entries")?;
    entries.extend_from_slice(external_entries);
    let product = protect_virtualization(Request {
        image,
        rva,
        external_entries: entries,
        seed: seed.get(),
    })
    .context("virtualization failed")?;
    let report = Report {
        schema_version: "1.0",
        mode: "virtualization",
        input: super::protect::FileInfo {
            path: input.display().to_string(),
            size: input_size,
        },
        output: super::protect::FileInfo {
            path: output.display().to_string(),
            size: product.image.len() as u64,
        },
        seed: product.seed,
        variant: product.variant,
        original: product.original.to_string(),
        entry: product.entry.to_string(),
        instance: product.instance.to_string(),
        source_length: product.source_length,
    };
    let text = if json {
        serde_json::to_string_pretty(&report)
            .context("failed to serialize virtualization report")?
    } else {
        format!(
            "Virtualized {} → {}\nSeed: {} (variant {})\nOutput: {} ({} bytes)",
            report.original,
            report.entry,
            report.seed,
            report.variant,
            report.output.path,
            report.output.size
        )
    };
    super::publish_atomically(output, &product.image)?;
    println!("{text}");
    Ok(())
}
