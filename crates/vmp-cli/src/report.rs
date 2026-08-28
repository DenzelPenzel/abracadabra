//! The stable, versioned `inspect` report.
//!
//! The DTO is deliberately decoupled from the internal `vmp-pe` structures:
//! their fields may change, but the CLI's JSON contract must stay stable.

use serde::Serialize;
use vmp_pe::{dll_characteristics, DataDirectory, DirectoryAddress, PeFile};

/// JSON schema version. Bumped on incompatible changes to the contract.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Serialize)]
pub struct InspectReport {
    pub schema_version: &'static str,
    pub file: FileInfo,
    pub architecture: String,
    pub machine: String,
    pub is_dll: bool,
    pub entry_point: String,
    pub image_base: String,
    pub subsystem: Subsystem,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: String,
    pub dll_characteristics: DllCharacteristics,
    pub data_directories: Vec<DirectoryEntry>,
    pub sections: Vec<SectionEntry>,
    pub features: FeaturesReport,
    /// Human-readable warnings about properties that cannot be protected.
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct Subsystem {
    pub value: u16,
    pub name: &'static str,
}

#[derive(Serialize)]
pub struct DllCharacteristics {
    pub raw: String,
    pub high_entropy_va: bool,
    pub dynamic_base: bool,
    pub nx_compat: bool,
    pub guard_cf: bool,
}

#[derive(Serialize)]
pub struct DirectoryEntry {
    pub index: usize,
    pub name: &'static str,
    /// Raw value of the header's `VirtualAddress` field. For every directory
    /// except `security` this is an RVA
    pub virtual_address: String,
    /// The security directory's `VirtualAddress` actually holds a physical
    /// file offset; it is duplicated here under its true meaning
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<String>,
    pub size: u32,
    pub present: bool,
}

#[derive(Serialize)]
pub struct SectionEntry {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: u32,
    pub pointer_to_raw_data: String,
    pub size_of_raw_data: u32,
    pub permissions: String,
    pub characteristics: String,
}

#[derive(Serialize)]
pub struct FeaturesReport {
    pub has_exports: bool,
    pub has_imports: bool,
    pub has_resources: bool,
    pub has_exception_directory: bool,
    pub has_base_relocations: bool,
    pub has_tls: bool,
    pub has_load_config: bool,
    pub has_delay_imports: bool,
    pub is_dotnet: bool,
    pub control_flow_guard: bool,
    pub guard_flags: Option<String>,
}

fn hex32(v: u32) -> String {
    format!("0x{v:08x}")
}

fn hex64(v: u64) -> String {
    format!("0x{v:x}")
}

fn subsystem_name(value: u16) -> &'static str {
    match value {
        0 => "unknown",
        1 => "native",
        2 => "windows-gui",
        3 => "windows-cui",
        5 => "os2-cui",
        7 => "posix-cui",
        9 => "windows-ce-gui",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        13 => "efi-rom",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => "other",
    }
}

fn directory_name(index: usize) -> &'static str {
    match index {
        0 => "export",
        1 => "import",
        2 => "resource",
        3 => "exception",
        4 => "security",
        5 => "basereloc",
        6 => "debug",
        7 => "architecture",
        8 => "global-ptr",
        9 => "tls",
        10 => "load-config",
        11 => "bound-import",
        12 => "iat",
        13 => "delay-import",
        14 => "clr",
        15 => "reserved",
        _ => "unknown",
    }
}

impl InspectReport {
    /// Builds the report from a parsed PE.
    pub fn from_pe(path: &str, size: u64, pe: &PeFile) -> InspectReport {
        let opt = &pe.optional;
        let dllc = opt.dll_characteristics;

        let data_directories = pe
            .data_directories
            .iter()
            .enumerate()
            .map(|(index, d): (usize, &DataDirectory)| {
                let file_offset = match d.address {
                    DirectoryAddress::FileOffset(off) => Some(format!("0x{:08x}", off.get())),
                    DirectoryAddress::Rva(_) => None,
                };
                DirectoryEntry {
                    index,
                    name: directory_name(index),
                    virtual_address: format!("0x{:08x}", d.address.raw()),
                    file_offset,
                    size: d.size,
                    present: d.is_present(),
                }
            })
            .collect();

        let sections = pe
            .sections
            .iter()
            .map(|s| SectionEntry {
                name: s.name.clone(),
                virtual_address: hex32(s.virtual_address.get()),
                virtual_size: s.virtual_size,
                pointer_to_raw_data: hex64(s.pointer_to_raw_data.get()),
                size_of_raw_data: s.size_of_raw_data,
                permissions: s.permissions.as_rwx(),
                characteristics: hex32(s.characteristics),
            })
            .collect();

        let f = &pe.features;
        let features = FeaturesReport {
            has_exports: f.has_exports,
            has_imports: f.has_imports,
            has_resources: f.has_resources,
            has_exception_directory: f.has_exception_directory,
            has_base_relocations: f.has_base_relocations,
            has_tls: f.has_tls,
            has_load_config: f.has_load_config,
            has_delay_imports: f.has_delay_imports,
            is_dotnet: f.is_dotnet,
            control_flow_guard: f.control_flow_guard,
            guard_flags: f.guard_flags.map(hex32),
        };

        // IMAGE_FILE_DLL = 0x2000 in the COFF characteristics.
        let is_dll = pe.coff.characteristics & 0x2000 != 0;

        InspectReport {
            schema_version: SCHEMA_VERSION,
            file: FileInfo {
                path: path.to_owned(),
                size,
            },
            architecture: pe.architecture.to_string(),
            machine: format!("0x{:04x}", pe.coff.machine),
            is_dll,
            entry_point: hex32(opt.entry_point.get()),
            image_base: hex64(opt.image_base.get()),
            subsystem: Subsystem {
                value: opt.subsystem,
                name: subsystem_name(opt.subsystem),
            },
            section_alignment: opt.section_alignment,
            file_alignment: opt.file_alignment,
            size_of_image: opt.size_of_image,
            size_of_headers: opt.size_of_headers,
            checksum: hex32(opt.checksum),
            dll_characteristics: DllCharacteristics {
                raw: format!("0x{dllc:04x}"),
                high_entropy_va: dllc & dll_characteristics::HIGH_ENTROPY_VA != 0,
                dynamic_base: dllc & dll_characteristics::DYNAMIC_BASE != 0,
                nx_compat: dllc & dll_characteristics::NX_COMPAT != 0,
                guard_cf: dllc & dll_characteristics::GUARD_CF != 0,
            },
            data_directories,
            sections,
            features,
            warnings: build_warnings(pe),
        }
    }
}

/// Collects warnings about properties the MVP cannot protect.
fn build_warnings(pe: &PeFile) -> Vec<String> {
    use vmp_types::Architecture;
    let mut warnings = Vec::new();
    let f = &pe.features;

    if pe.architecture == Architecture::X86 {
        warnings
            .push("x86 input: MVP targets Windows x64; protection is not yet supported".to_owned());
    }
    if f.control_flow_guard {
        warnings.push(
            "Control Flow Guard is enabled: protection is fail-closed until CFG support (Stage 9)"
                .to_owned(),
        );
    }
    if f.is_dotnet {
        warnings.push(".NET/CLR image: managed binaries are out of MVP scope".to_owned());
    }
    if f.has_tls {
        warnings.push(
            "TLS directory present: TLS callbacks require care and are not handled by MVP"
                .to_owned(),
        );
    }
    if pe.architecture == Architecture::X64 && !f.has_exception_directory {
        warnings.push(
            "no exception directory: unusual for x64 and required for correct unwinding".to_owned(),
        );
    }
    warnings
}
