//! `vmp` — the protector's CLI layer.
//!
//! `inspect` and `validate` describe the container, `disasm` describes one
//! function's code, and `protect` rewrites an image and writes it back out. The
//! remaining protection command (`verify`) arrives in a later stage.

mod disasm;
mod protect;
mod report;

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use vmp_compiler::{
    protect_mutation, Error as CompilerError, MutationRequest, Seed, SymbolSelection,
};
use vmp_pe::PeFile;
use vmp_types::Rva;

use crate::disasm::DisasmReport;
use crate::protect::ProtectReport;
use crate::report::InspectReport;

#[derive(Parser)]
#[command(
    name = "vmp",
    about = "Windows x64 PE protector CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a PE and print headers, sections, directories and features.
    Inspect {
        /// Path to the input PE file.
        input: PathBuf,
        /// Emit stable machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Check that a PE parses; return a non-zero code on error.
    Validate {
        /// Path to the input PE file.
        input: PathBuf,
    },
    /// Decode one function and print its basic blocks and references.
    Disasm {
        /// Path to the input PE file.
        input: PathBuf,
        /// RVA of the function entry; defaults to the image entry point.
        /// Accepts `0x`-prefixed hex.
        #[arg(long, value_parser = parse_rva)]
        rva: Option<Rva>,
        /// Report which registers and flags are free after each instruction,
        /// which is what a mutation is allowed to overwrite there.
        #[arg(long)]
        liveness: bool,
        /// Emit stable machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Mutate functions into an appended section and write a protected PE.
    Protect {
        /// Path to the input PE file.
        input: PathBuf,
        /// Path to write the protected PE to.
        #[arg(long)]
        output: PathBuf,
        /// RVA of a function entry to protect; repeatable. Without an explicit
        /// selector, SDK markers take precedence over the exception-directory
        /// sweep. Accepts `0x`-prefixed hex.
        #[arg(long, value_parser = parse_rva)]
        rva: Vec<Rva>,
        /// Demangled function name to protect. Without --symbol-index the
        /// name must identify exactly one code symbol.
        #[arg(long)]
        symbol: Option<String>,
        /// Zero-based code-symbol occurrence for --symbol.
        #[arg(long, requires = "symbol")]
        symbol_index: Option<usize>,
        /// Seed for the mutation; omit to generate one from the system CSPRNG.
        #[arg(long)]
        seed: Option<u64>,
        /// Emit stable machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// Parses an RVA given in hex (`0x1000`) or decimal.
fn parse_rva(text: &str) -> Result<Rva, String> {
    let trimmed = text.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => trimmed.parse::<u32>(),
    };
    parsed
        .map(Rva)
        .map_err(|_| format!("`{text}` is not a valid RVA"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Errors go to stderr; the command's result goes to stdout.
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: &Command) -> Result<()> {
    match command {
        Command::Inspect { input, json } => cmd_inspect(input, *json),
        Command::Validate { input } => cmd_validate(input),
        Command::Disasm {
            input,
            rva,
            liveness,
            json,
        } => cmd_disasm(input, *rva, *liveness, *json),
        Command::Protect {
            input,
            output,
            rva,
            symbol,
            symbol_index,
            seed,
            json,
        } => cmd_protect(
            input,
            output,
            rva,
            symbol.as_deref(),
            *symbol_index,
            *seed,
            *json,
        ),
    }
}

fn read_pe(input: &Path) -> Result<(Vec<u8>, PeFile)> {
    let data = std::fs::read(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;
    let pe =
        PeFile::parse(&data).with_context(|| format!("failed to parse PE {}", input.display()))?;
    Ok((data, pe))
}

fn cmd_inspect(input: &Path, json: bool) -> Result<()> {
    let (data, pe) = read_pe(input)?;
    let report = InspectReport::from_pe(&input.display().to_string(), data.len() as u64, &pe);

    if json {
        let text = serde_json::to_string_pretty(&report)
            .context("failed to serialize inspect report as JSON")?;
        println!("{text}");
    } else {
        print_text_report(&report);
    }
    Ok(())
}

fn cmd_validate(input: &Path) -> Result<()> {
    let (_data, pe) = read_pe(input)?;
    println!(
        "ok: valid {} PE, {} section(s), entry {}",
        pe.architecture,
        pe.sections.len(),
        pe.optional.entry_point
    );
    Ok(())
}

fn cmd_disasm(input: &Path, rva: Option<Rva>, liveness: bool, json: bool) -> Result<()> {
    let (data, pe) = read_pe(input)?;
    let entry = rva.unwrap_or_else(|| pe.entry_point());
    let image = vmp_x86::Image::new(&pe, &data);

    let function = vmp_x86::decode_function(image, entry)
        .with_context(|| format!("failed to decode the function at {entry}"))?;

    let report = DisasmReport::build(
        &input.display().to_string(),
        data.len() as u64,
        &image,
        &function,
        liveness,
    );

    if json {
        let text = serde_json::to_string_pretty(&report)
            .context("failed to serialize disasm report as JSON")?;
        println!("{text}");
    } else {
        disasm::print_text(&report);
    }

    // A function the decoder could not vouch for is a diagnostic result, not a
    // failure: the listing is still worth printing. The exit code says so.
    if function.is_complete() {
        Ok(())
    } else {
        Err(anyhow!(
            "the function at {entry} has {} unresolved issue(s) and cannot be protected",
            function.issues.len()
        ))
    }
}

fn cmd_protect(
    input: &Path,
    output: &Path,
    rva: &[Rva],
    symbol: Option<&str>,
    symbol_index: Option<usize>,
    seed: Option<u64>,
    json: bool,
) -> Result<()> {
    let data = std::fs::read(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;
    let input_size = data.len() as u64;
    let (map, pdb) = if symbol.is_some() {
        let map_path = input.with_extension("map");
        if let Some(bytes) =
            read_optional_bounded(&map_path, vmp_compiler::MAX_SIDECAR_INPUT_BYTES)?
        {
            let map = String::from_utf8(bytes).with_context(|| {
                format!("MAP sidecar {} is not valid UTF-8", map_path.display())
            })?;
            (Some(map), None)
        } else {
            (
                None,
                read_optional_bounded(
                    &input.with_extension("pdb"),
                    vmp_compiler::MAX_SIDECAR_INPUT_BYTES,
                )?,
            )
        }
    } else {
        (None, None)
    };
    let symbol = match symbol {
        Some(name) => Some(SymbolSelection {
            name: try_owned_cli(name)?,
            occurrence: symbol_index,
        }),
        None => None,
    };
    let mut rvas = Vec::new();
    rvas.try_reserve_exact(rva.len())
        .context("failed to retain explicit --rva selections")?;
    rvas.extend_from_slice(rva);
    let seed = protection_seed(seed, |bytes| {
        getrandom::fill(bytes).map_err(|error| anyhow!("system CSPRNG failed: {error}"))
    })?;
    let product = protect_mutation(MutationRequest {
        image: data,
        rvas,
        symbol,
        map,
        pdb,
        seed,
    })
    .map_err(|error| compiler_error(input, error))?;
    let bytes = product.image;
    publish_atomically(output, &bytes)?;

    let report = ProtectReport::build(
        &input.display().to_string(),
        input_size,
        &output.display().to_string(),
        bytes.len() as u64,
        product.seed,
        &product.outcome,
    );

    if json {
        let text = serde_json::to_string_pretty(&report)
            .context("failed to serialize protect report as JSON")?;
        println!("{text}");
    } else {
        protect::print_text(&report);
    }

    Ok(())
}

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_TEMP_FILE_ATTEMPTS: u64 = 128;

trait PublicationFs {
    fn create_new(&mut self, path: &Path) -> io::Result<File>;
    fn write_all(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()>;
    fn sync_all(&mut self, file: &File) -> io::Result<()>;
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&mut self, path: &Path) -> io::Result<()>;
}

struct StdPublicationFs;

impl PublicationFs for StdPublicationFs {
    fn create_new(&mut self, path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        options.open(path)
    }

    fn write_all(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }

    fn sync_all(&mut self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}

fn publish_atomically(output: &Path, bytes: &[u8]) -> Result<()> {
    publish_atomically_with(output, bytes, &mut StdPublicationFs)
}

// Atomicity assumes the output directory is not modified concurrently.
fn publish_atomically_with(output: &Path, bytes: &[u8], fs: &mut impl PublicationFs) -> Result<()> {
    let permissions = publication_destination_permissions(output)?;
    let (temporary, mut file) = create_temporary_output(output, fs)?;
    if let Err(error) = fs.write_all(&mut file, bytes) {
        drop(file);
        let _ = fs.remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to write temporary output for {}", output.display()));
    }
    if let Some(permissions) = permissions {
        if let Err(error) = file.set_permissions(permissions) {
            drop(file);
            let _ = fs.remove_file(&temporary);
            return Err(error).with_context(|| {
                format!(
                    "failed to preserve output permissions for {}",
                    output.display()
                )
            });
        }
    }
    if let Err(error) = fs.sync_all(&file) {
        drop(file);
        let _ = fs.remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to sync temporary output for {}", output.display()));
    }
    drop(file);
    if let Err(error) = fs.rename(&temporary, output) {
        let _ = fs.remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to publish output file {}", output.display()));
    }
    Ok(())
}

fn publication_destination_permissions(output: &Path) -> Result<Option<std::fs::Permissions>> {
    let metadata = match std::fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect output destination {}", output.display())
            });
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(anyhow!(
            "output destination {} is a symbolic link",
            output.display()
        ));
    }
    if metadata.is_dir() {
        return Err(anyhow!(
            "output destination {} is a directory",
            output.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow!(
            "output destination {} is not a regular file",
            output.display()
        ));
    }
    let permissions = metadata.permissions();
    if permissions.readonly() {
        return Err(anyhow!(
            "output destination {} is read-only",
            output.display()
        ));
    }
    Ok(Some(permissions))
}

fn create_temporary_output(output: &Path, fs: &mut impl PublicationFs) -> Result<(PathBuf, File)> {
    let file_name = output
        .file_name()
        .ok_or_else(|| anyhow!("output path {} has no file name", output.display()))?;
    for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temporary = output.with_file_name(temporary_name);
        match fs.create_new(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create temporary output for {}", output.display())
                });
            }
        }
    }
    Err(anyhow!(
        "failed to create a unique temporary output for {} after {MAX_TEMP_FILE_ATTEMPTS} attempts",
        output.display()
    ))
}

fn compiler_error(input: &Path, error: CompilerError) -> anyhow::Error {
    match &error {
        CompilerError::Resolve(_) => anyhow::Error::new(error)
            .context(format!("failed to resolve --symbol in {}", input.display())),
        CompilerError::AmbiguousSymbol { last, .. } => {
            let context = format!(
                "failed to resolve --symbol in {}; pass --symbol-index <0..{last}>",
                input.display()
            );
            anyhow::Error::new(error).context(context)
        }
        CompilerError::Symbols(_) => anyhow::Error::new(error)
            .context(format!("failed to load symbols for {}", input.display())),
        CompilerError::NoFunctionEntries => anyhow!(
            "nothing to protect: {} declares no exception directory entries, \
             so the functions have to be named with --rva",
            input.display()
        ),
        _ => anyhow::Error::new(error).context(format!("failed to protect {}", input.display())),
    }
}

fn protection_seed(
    explicit: Option<u64>,
    fill: impl FnOnce(&mut [u8; 8]) -> Result<()>,
) -> Result<Seed> {
    if let Some(value) = explicit {
        return Ok(Seed::new(value));
    }

    let mut bytes = [0u8; 8];
    fill(&mut bytes).context("failed to generate a Mutation seed")?;
    Ok(Seed::new(u64::from_le_bytes(bytes)))
}

fn try_owned_cli(value: &str) -> Result<String> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(value.len())
        .context("failed to retain --symbol")?;
    retained.push_str(value);
    Ok(retained)
}

fn read_optional_bounded(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut retained = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = match file.read(&mut chunk) {
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read == 0 {
            return Ok(Some(retained));
        }
        let attempted = retained
            .len()
            .checked_add(read)
            .ok_or_else(|| anyhow!("sidecar {} size overflows", path.display()))?;
        if attempted > limit {
            return Err(anyhow!(
                "sidecar {} exceeds the {}-byte input limit",
                path.display(),
                limit
            ));
        }
        retained
            .try_reserve_exact(read)
            .with_context(|| format!("failed to retain sidecar {}", path.display()))?;
        retained.extend_from_slice(&chunk[..read]);
    }
}

fn print_text_report(r: &InspectReport) {
    println!("File:            {} ({} bytes)", r.file.path, r.file.size);
    println!(
        "Architecture:    {} (machine {})",
        r.architecture, r.machine
    );
    println!("Kind:            {}", if r.is_dll { "DLL" } else { "EXE" });
    println!("Entry point:     {} (RVA)", r.entry_point);
    println!("Image base:      {}", r.image_base);
    println!(
        "Subsystem:       {} ({})",
        r.subsystem.name, r.subsystem.value
    );
    println!(
        "Alignment:       section {:#x}, file {:#x}",
        r.section_alignment, r.file_alignment
    );
    println!(
        "Sizes:           image {:#x}, headers {:#x}",
        r.size_of_image, r.size_of_headers
    );
    println!("Checksum:        {}", r.checksum);
    let c = &r.dll_characteristics;
    println!(
        "DllCharacter.:   {} [ASLR={} DEP={} HighEntropy={} GuardCF={}]",
        c.raw, c.dynamic_base, c.nx_compat, c.high_entropy_va, c.guard_cf
    );

    println!("\nSections ({}):", r.sections.len());
    for s in &r.sections {
        println!(
            "  {:<8} va={} vsize={:#x} raw={} rsize={:#x} {} {}",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.pointer_to_raw_data,
            s.size_of_raw_data,
            s.permissions,
            s.characteristics
        );
    }

    println!("\nData directories (present):");
    for d in r.data_directories.iter().filter(|d| d.present) {
        // The security directory's address is a file offset, not an RVA
        match &d.file_offset {
            Some(off) => println!(
                "  [{:>2}] {:<13} off={} size={:#x}",
                d.index, d.name, off, d.size
            ),
            None => println!(
                "  [{:>2}] {:<13} va={} size={:#x}",
                d.index, d.name, d.virtual_address, d.size
            ),
        }
    }

    let f = &r.features;
    println!("\nFeatures:");
    println!(
        "  exports={} imports={} resources={} tls={}",
        f.has_exports, f.has_imports, f.has_resources, f.has_tls
    );
    println!(
        "  base_relocations={} load_config={} delay_imports={}",
        f.has_base_relocations, f.has_load_config, f.has_delay_imports
    );
    println!(
        "  exception_directory (unwind)={}",
        f.has_exception_directory
    );
    println!("  control_flow_guard={}", f.control_flow_guard);
    if let Some(gf) = &f.guard_flags {
        println!("  guard_flags={gf}");
    }
    println!("  dotnet={}", f.is_dotnet);

    if !r.warnings.is_empty() {
        println!("\nWarnings:");
        for w in &r.warnings {
            println!("  ! {w}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PublicationFailure {
        None,
        Create,
        Write,
        Sync,
        Rename,
    }

    struct FaultingPublicationFs {
        failure: PublicationFailure,
    }

    impl PublicationFs for FaultingPublicationFs {
        fn create_new(&mut self, path: &Path) -> io::Result<File> {
            if self.failure == PublicationFailure::Create {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected create failure",
                ));
            }
            OpenOptions::new().write(true).create_new(true).open(path)
        }

        fn write_all(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
            if self.failure == PublicationFailure::Write {
                std::io::Write::write_all(file, &bytes[..bytes.len().min(4)])?;
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "injected write failure",
                ));
            }
            std::io::Write::write_all(file, bytes)
        }

        fn sync_all(&mut self, file: &File) -> io::Result<()> {
            if self.failure == PublicationFailure::Sync {
                return Err(io::Error::other("injected sync failure"));
            }
            file.sync_all()
        }

        fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
            if self.failure == PublicationFailure::Rename {
                return Err(io::Error::other("injected rename failure"));
            }
            std::fs::rename(from, to)
        }

        fn remove_file(&mut self, path: &Path) -> io::Result<()> {
            std::fs::remove_file(path)
        }
    }

    fn corpus_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-symbols/test-corpus")
            .join(name)
    }

    #[test]
    fn automatic_static_sdk_protection_writes_a_relocated_marker_region() {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
        let mut data = std::fs::read(&source).expect("required SDK corpus must read");
        let pe = PeFile::parse(&data).expect("required SDK corpus must parse");
        let unwind_rva = pe
            .exception_table
            .as_ref()
            .expect("SDK corpus has exception data")
            .functions()
            .find(|function| function.begin == Rva(0x1000))
            .expect("SDK marker function has a runtime entry")
            .unwind_info;
        let unwind_offset = pe
            .rva_to_offset(unwind_rva)
            .expect("unwind info is file-backed")
            .get() as usize;
        data[unwind_offset] &= 0x07;
        let begin_offset = pe
            .rva_to_offset(Rva(0x1027))
            .expect("static Begin site is file-backed")
            .get() as usize;
        let end_offset = pe
            .rva_to_offset(Rva(0x103f))
            .expect("static End site is file-backed")
            .get() as usize;
        data[begin_offset..begin_offset + 18].copy_from_slice(b"\xeb\x10VMProtect begin\x02");
        data[end_offset..end_offset + 16].copy_from_slice(b"\xeb\x0eVMProtect end\0");

        let directory = temporary_fixture_dir("automatic-sdk");
        let input = directory.join("sdk.exe");
        let output = directory.join("sdk-protected.exe");
        std::fs::write(&input, &data).expect("adapted SDK fixture must write");
        cmd_protect(&input, &output, &[], None, None, Some(1), false)
            .expect("automatic SDK protection must succeed");

        let bytes = std::fs::read(&output).expect("protected SDK output must read");
        let pe = PeFile::parse(&bytes).expect("protected SDK output must reparse");
        assert!(pe.sections.iter().any(|section| section.name == ".vmpc"));
        let original_entry = pe
            .rva_to_offset(Rva(0x1000))
            .expect("original marker function remains file-backed")
            .get() as usize;
        assert_eq!(
            &bytes[original_entry..original_entry + 5],
            &data[original_entry..original_entry + 5],
            "region-only protection must preserve the covering function entry"
        );
        let begin = pe
            .rva_to_offset(Rva(0x1027))
            .expect("SDK Begin remains file-backed")
            .get() as usize;
        assert_eq!(bytes[begin], 0xe9, "SDK Begin must redirect");
        assert!(bytes[begin + 5..begin + 18]
            .iter()
            .all(|byte| *byte == 0x90));
    }

    fn temporary_fixture_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vmp-cli-{label}-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&path).expect("temporary fixture directory must be created");
        path
    }

    fn directory_entry_count(path: &Path) -> usize {
        std::fs::read_dir(path)
            .expect("fixture directory must read")
            .count()
    }

    fn assert_existing_output_is_unchanged(directory: &Path, output: &Path, entries: usize) {
        assert_eq!(
            std::fs::read(output).expect("sentinel output must remain readable"),
            b"existing output"
        );
        assert_eq!(
            directory_entry_count(directory),
            entries,
            "failed publication left a sibling temporary file"
        );
    }

    #[test]
    fn publication_create_failure_preserves_destination() {
        let directory = temporary_fixture_dir("publication-create-failure");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let entries_before = directory_entry_count(&directory);
        let mut fs = FaultingPublicationFs {
            failure: PublicationFailure::Create,
        };

        let error = publish_atomically_with(&output, b"complete new output", &mut fs)
            .expect_err("injected create failure must abort publication");

        assert!(error.to_string().contains("create temporary output"));
        assert_existing_output_is_unchanged(&directory, &output, entries_before);
    }

    #[test]
    fn publication_write_failure_preserves_destination_and_removes_temporary_file() {
        let directory = temporary_fixture_dir("publication-write-failure");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let entries_before = directory_entry_count(&directory);
        let mut fs = FaultingPublicationFs {
            failure: PublicationFailure::Write,
        };

        let error = publish_atomically_with(&output, b"complete new output", &mut fs)
            .expect_err("injected write failure must abort publication");

        assert!(error.to_string().contains("write temporary output"));
        assert_existing_output_is_unchanged(&directory, &output, entries_before);
    }

    #[test]
    fn publication_sync_failure_preserves_destination_and_removes_temporary_file() {
        let directory = temporary_fixture_dir("publication-sync-failure");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let entries_before = directory_entry_count(&directory);
        let mut fs = FaultingPublicationFs {
            failure: PublicationFailure::Sync,
        };

        let error = publish_atomically_with(&output, b"complete new output", &mut fs)
            .expect_err("injected sync failure must abort publication");

        assert!(error.to_string().contains("sync temporary output"));
        assert_existing_output_is_unchanged(&directory, &output, entries_before);
    }

    #[test]
    fn publication_rename_failure_preserves_destination_and_removes_temporary_file() {
        let directory = temporary_fixture_dir("publication-rename-failure");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let entries_before = directory_entry_count(&directory);
        let mut fs = FaultingPublicationFs {
            failure: PublicationFailure::Rename,
        };

        let error = publish_atomically_with(&output, b"complete new output", &mut fs)
            .expect_err("injected rename failure must abort publication");

        assert!(error.to_string().contains("publish output file"));
        assert_existing_output_is_unchanged(&directory, &output, entries_before);
    }

    #[test]
    fn successful_publication_replaces_destination_byte_exactly() {
        let directory = temporary_fixture_dir("publication-success");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let entries_before = directory_entry_count(&directory);
        let mut fs = FaultingPublicationFs {
            failure: PublicationFailure::None,
        };

        publish_atomically_with(&output, b"complete new output", &mut fs)
            .expect("complete temporary output must publish");

        assert_eq!(
            std::fs::read(&output).expect("published output must read"),
            b"complete new output"
        );
        assert_eq!(directory_entry_count(&directory), entries_before);
    }

    #[test]
    fn publication_rejects_a_readonly_destination_without_changing_it() {
        let directory = temporary_fixture_dir("publication-readonly");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        let mut permissions = std::fs::metadata(&output)
            .expect("sentinel metadata must read")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&output, permissions).expect("sentinel permissions must be set");
        let entries_before = directory_entry_count(&directory);

        let error = publish_atomically(&output, b"complete new output")
            .expect_err("a readonly destination must be rejected");

        assert!(error.to_string().contains("is read-only"));
        assert_eq!(
            std::fs::read(&output).expect("readonly output must remain readable"),
            b"existing output"
        );
        assert!(
            std::fs::metadata(&output)
                .expect("readonly output metadata must read")
                .permissions()
                .readonly(),
            "publication changed the readonly destination attribute"
        );
        assert_eq!(directory_entry_count(&directory), entries_before);
    }

    #[cfg(unix)]
    #[test]
    fn successful_publication_preserves_existing_destination_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_fixture_dir("publication-permissions");
        let output = directory.join("protected.exe");
        std::fs::write(&output, b"existing output").expect("sentinel output must write");
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o6751))
            .expect("sentinel permissions must be set");

        publish_atomically(&output, b"complete new output")
            .expect("complete temporary output must publish");

        let mode = std::fs::metadata(&output)
            .expect("published output metadata must read")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o6751);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_publication_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_fixture_dir("publication-new-permissions");
        let output = directory.join("protected.exe");

        publish_atomically(&output, b"complete new output")
            .expect("new output must publish from a restricted temporary file");

        let mode = std::fs::metadata(&output)
            .expect("published output metadata must read")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn successful_cli_publication_matches_the_compiler_product_byte_exactly() {
        let input = corpus_path("foo.exe");
        let source = std::fs::read(&input).expect("required PE corpus must read");
        let expected = protect_mutation(MutationRequest {
            image: source,
            rvas: Vec::new(),
            symbol: None,
            map: None,
            pdb: None,
            seed: Seed::new(1),
        })
        .expect("required corpus must produce a Mutation product");
        let directory = temporary_fixture_dir("publication-compiler-product");
        let output = directory.join("protected.exe");

        cmd_protect(&input, &output, &[], None, None, Some(1), false)
            .expect("CLI must publish the complete Mutation product");

        assert_eq!(
            std::fs::read(&output).expect("published output must read"),
            expected.image
        );
        assert_eq!(directory_entry_count(&directory), 1);
    }

    #[test]
    fn publication_rejects_a_directory_destination_without_leaving_a_temporary_file() {
        let directory = temporary_fixture_dir("publication-directory-destination");
        let output = directory.join("protected.exe");
        std::fs::create_dir(&output).expect("output directory must be created");
        let entries_before = directory_entry_count(&directory);

        let error = publish_atomically(&output, b"complete new output")
            .expect_err("a directory destination must be rejected");

        assert!(error.to_string().contains("is a directory"));
        assert!(output.is_dir(), "publication replaced the output directory");
        assert_eq!(directory_entry_count(&directory), entries_before);
    }

    #[cfg(unix)]
    #[test]
    fn publication_rejects_a_symbolic_link_destination_without_replacing_it() {
        use std::os::unix::fs::symlink;

        let directory = temporary_fixture_dir("publication-symlink-destination");
        let target = directory.join("target.exe");
        let output = directory.join("protected.exe");
        std::fs::write(&target, b"symlink target").expect("symlink target must write");
        symlink(&target, &output).expect("output symlink must be created");
        let entries_before = directory_entry_count(&directory);

        let error = publish_atomically(&output, b"complete new output")
            .expect_err("a symbolic-link destination must be rejected");

        assert!(error.to_string().contains("symbolic link"));
        assert!(
            std::fs::symlink_metadata(&output)
                .expect("output symlink metadata must remain readable")
                .file_type()
                .is_symlink(),
            "publication replaced the destination symlink"
        );
        assert_eq!(
            std::fs::read(&target).expect("symlink target must remain readable"),
            b"symlink target"
        );
        assert_eq!(directory_entry_count(&directory), entries_before);
    }

    #[test]
    fn readable_map_stops_before_unavailable_pdb() {
        let directory = temporary_fixture_dir("lazy-map");
        let input = directory.join("foo.exe");
        std::fs::copy(corpus_path("foo.exe"), &input).expect("PE fixture must copy");
        std::fs::write(input.with_extension("map"), b"").expect("MAP fixture must write");
        std::fs::create_dir(input.with_extension("pdb"))
            .expect("unreadable PDB stand-in must be created");
        let output = directory.join("protected.exe");
        let error = cmd_protect(&input, &output, &[], Some("main"), None, Some(1), false)
            .expect_err("empty readable MAP must stop with no main symbol");
        assert!(error.to_string().contains("failed to resolve --symbol"));
        assert!(!output.exists());
    }

    #[test]
    fn unavailable_sidecars_fall_through_without_io_error() {
        let directory = temporary_fixture_dir("unavailable-sidecars");
        let input = directory.join("foo.exe");
        std::fs::copy(corpus_path("foo.exe"), &input).expect("PE fixture must copy");
        std::fs::create_dir(input.with_extension("map"))
            .expect("unavailable MAP stand-in must be created");
        std::fs::create_dir(input.with_extension("pdb"))
            .expect("unavailable PDB stand-in must be created");
        let output = directory.join("protected.exe");
        let error = cmd_protect(&input, &output, &[], Some("main"), None, Some(1), false)
            .expect_err("native fallback has no main symbol");
        assert!(error.to_string().contains("failed to resolve --symbol"));
        assert!(!output.exists());
    }

    #[test]
    fn bounded_sidecar_reader_rejects_one_over() {
        let directory = temporary_fixture_dir("bounded-sidecar");
        let sidecar = directory.join("oversized.pdb");
        std::fs::write(&sidecar, b"123456789").expect("sidecar fixture must write");
        let error =
            read_optional_bounded(&sidecar, 8).expect_err("one-over sidecar must be rejected");
        assert!(error.to_string().contains("8-byte input limit"));
    }

    #[test]
    fn an_explicit_seed_does_not_read_the_system_rng() {
        let seed = protection_seed(Some(42), |_| -> Result<()> {
            panic!("an explicit seed must not read system randomness")
        })
        .expect("an explicit seed is infallible");

        assert_eq!(seed, Seed::new(42));
    }

    #[test]
    fn an_omitted_seed_uses_all_system_random_bytes() {
        let seed = protection_seed(None, |bytes| {
            *bytes = [1, 2, 3, 4, 5, 6, 7, 8];
            Ok(())
        })
        .expect("the supplied system RNG succeeds");

        assert_eq!(seed, Seed::new(0x0807_0605_0403_0201));
    }

    #[test]
    fn a_system_rng_failure_is_not_replaced_with_a_fixed_seed() {
        let error = protection_seed(None, |_| Err(anyhow!("system RNG unavailable")))
            .expect_err("an unavailable system RNG must fail closed");

        assert!(error
            .to_string()
            .contains("failed to generate a Mutation seed"));
        assert!(error
            .chain()
            .any(|cause| cause.to_string().contains("system RNG unavailable")));
    }

    #[test]
    fn malformed_input_error_names_the_input_path() {
        let directory = temporary_fixture_dir("malformed-input");
        let input = directory.join("broken.exe");
        let output = directory.join("protected.exe");
        std::fs::write(&input, b"not a PE").expect("malformed fixture must write");

        let error = cmd_protect(&input, &output, &[], None, None, Some(1), false)
            .expect_err("malformed PE must fail before output publication");

        assert!(error.to_string().contains(&input.display().to_string()));
        assert!(!output.exists());
    }

    #[test]
    fn automatic_empty_selection_names_the_input_and_suggests_rva() {
        let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vmp-pe/test-corpus/win32-app-test1-i386");
        let output = temporary_fixture_dir("no-function-entries").join("protected.exe");

        let error = cmd_protect(&input, &output, &[], None, None, Some(1), false)
            .expect_err("an image without exception entries must require explicit selection");

        let message = error.to_string();
        assert!(message.contains(&input.display().to_string()));
        assert!(message.contains("--rva"));
        assert!(!output.exists());
    }

    #[test]
    fn mixed_explicit_failure_preserves_existing_output() {
        let input = corpus_path("foo.exe");
        let data = std::fs::read(&input).expect("required PE corpus must read");
        let sweep = protect_mutation(MutationRequest {
            image: data,
            rvas: Vec::new(),
            symbol: None,
            map: None,
            pdb: None,
            seed: Seed::default(),
        })
        .expect("required corpus sweep must protect at least one function");
        let protected = sweep
            .outcome
            .protected
            .first()
            .expect("required corpus must contain a protectable function")
            .original;
        let skipped = sweep
            .outcome
            .skipped
            .first()
            .expect("required corpus must contain an ineligible function")
            .rva;
        let output = temporary_fixture_dir("prewrite-gate").join("existing.exe");
        std::fs::write(&output, b"sentinel").expect("sentinel output must write");
        cmd_protect(
            &input,
            &output,
            &[protected, skipped],
            None,
            None,
            None,
            false,
        )
        .expect_err("mixed explicit request must fail before writing");
        assert_eq!(
            std::fs::read(&output).expect("sentinel output must remain readable"),
            b"sentinel"
        );
    }

    #[test]
    fn symbol_index_requires_symbol() {
        assert!(Cli::try_parse_from([
            "vmp",
            "protect",
            "input.exe",
            "--output",
            "output.exe",
            "--symbol-index",
            "0",
        ])
        .is_err());
    }

    #[test]
    fn required_pdb_corpus_resolves_main_by_name() {
        let input = corpus_path("foo.exe");
        let output = temporary_fixture_dir("pdb-main").join("protected.exe");
        cmd_protect(&input, &output, &[], Some("main"), None, Some(1), false)
            .expect("main must resolve and be protected");
        let bytes = std::fs::read(output).expect("protected symbol output must read");
        PeFile::parse(&bytes).expect("protected symbol output must reparse");
    }

    #[test]
    fn required_pdb_corpus_honors_zero_based_occurrence() {
        let input = corpus_path("foo.exe");
        let directory = temporary_fixture_dir("pdb-occurrence");
        let output = directory.join("protected.exe");
        cmd_protect(&input, &output, &[], Some("main"), Some(0), Some(1), false)
            .expect("main occurrence zero must resolve and protect");
        let out_of_range = directory.join("out-of-range.exe");
        assert!(cmd_protect(
            &input,
            &out_of_range,
            &[],
            Some("main"),
            Some(1),
            Some(1),
            false,
        )
        .is_err());
        assert!(!out_of_range.exists());
    }

    #[test]
    fn unknown_symbol_fails_before_creating_output() {
        let input = corpus_path("foo.exe");
        let output = std::env::temp_dir().join(format!(
            "vmp-unknown-symbol-{}-{}.exe",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&output);
        let error = cmd_protect(
            &input,
            &output,
            &[],
            Some("__vmp_symbol_that_does_not_exist__"),
            None,
            Some(1),
            false,
        )
        .expect_err("unknown explicit symbol must fail");
        assert!(error.to_string().contains("failed to resolve --symbol"));
        assert!(!output.exists(), "selector failure created partial output");
    }
}
