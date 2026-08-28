//! A safe Windows PE parser (PE32 and PE32+).
//!
//! [`PeFile::parse`] reads the DOS/COFF/optional headers, the data directories,
//! the section table and the alignment profile that decides how the loader maps
//! all of it. It also builds the structured loader directories eagerly — base
//! relocations, thread local storage and x64 unwind data — so an image whose
//! metadata cannot be read is refused instead of half-understood.
//!
//! [`PeImage`] rewrites an image without moving anything that already exists:
//!
//! - [`PeImage::add_section`] appends initialized bytes;
//! - [`PeImage::add_section_with_directories`] additionally re-points data
//!   directories at content inside the new section;
//! - [`PeImage::extend_base_relocations`], [`PeImage::relocate_tls`] and
//!   [`PeImage::extend_exception_table`] express the three rewrites a protector
//!   needs, including the base relocations a moved TLS directory requires.
//!
//! Every mutation builds a candidate, reparses it, checks it against the planned
//! layout *and* the planned directory models, and only then replaces the owned
//! image — so a failure at any stage leaves the image byte-for-byte untouched.
//! Malformed or unsupported input returns [`PeError`] but never panics.

pub mod codeview;
pub mod coff;
mod error;
pub mod exception;
pub mod exports;
pub mod imports;
pub mod markers;
mod reader;
pub mod relocations;
#[cfg(test)]
mod testing;
pub mod tls;
mod writer;

pub use coff::{CoffStorageClass, CoffSymbol};
pub use error::PeError;
pub use exception::{
    ExceptionTable, FunctionEntry, RuntimeFunction, UnwindInfo, UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER,
};
pub use exports::{ExportEntry, ExportTarget, Exports};
pub use imports::{ImportTarget, ImportedFunction, ImportedLibrary, Imports};
pub use relocations::{BaseRelocations, Fixup, FixupKind};
pub use tls::TlsDirectory;
pub use writer::{DirectoryPlacement, NewFunction, NewSection, PeImage};

use reader::Reader;
use vmp_types::{Architecture, FileOffset, ImageBase, Rva, SectionPermissions};

/// DOS header signature `MZ`.
const DOS_MAGIC: u16 = 0x5a4d;
/// NT headers signature `PE\0\0`.
const PE_SIGNATURE: u32 = 0x0000_4550;
/// Optional header magic for PE32.
const OPT_MAGIC_PE32: u16 = 0x010b;
/// Optional header magic for PE32+.
const OPT_MAGIC_PE32PLUS: u16 = 0x020b;
/// Bytes in one `IMAGE_SECTION_HEADER`.
pub(crate) const SECTION_HEADER_SIZE: u64 = 40;
/// Bytes in one `IMAGE_DATA_DIRECTORY` entry.
pub(crate) const DIRECTORY_ENTRY_SIZE: u64 = 8;
/// Page size on both supported architectures. Images aligned below it are
/// mapped one-to-one by the loader.
pub(crate) const PAGE_SIZE: u32 = 0x1000;
/// Smallest `FileAlignment` the PE specification allows for page-aligned
/// images.
const MIN_FILE_ALIGNMENT: u32 = 0x200;
/// Largest `FileAlignment` the PE specification allows.
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;

/// Data directory indices (`IMAGE_DIRECTORY_ENTRY_*`).
pub mod directory {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBAL_PTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR: usize = 14;
    /// Maximum number of entries the Windows loader honours.
    pub const MAX: usize = 16;
}

/// `IMAGE_DLLCHARACTERISTICS_*` flags of interest to inspect.
pub mod dll_characteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040; // ASLR
    pub const NX_COMPAT: u16 = 0x0100; // DEP
    pub const GUARD_CF: u16 = 0x4000; // Control Flow Guard
}

/// `GuardFlags` bits from the load config, for decoding [`Features::guard_flags`].
/// Only the function table indicates active CFG: instrumentation is emitted by
/// the compiler either way.
pub mod guard_flags {
    pub const CF_INSTRUMENTED: u32 = 0x0000_0100;
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
}

/// Parsed DOS header (only `e_lfanew` is needed).
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_lfanew: u32,
}

/// COFF file header (`IMAGE_FILE_HEADER`).
#[derive(Debug, Clone, Copy)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: FileOffset,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Key optional header fields, normalised across PE32 and PE32+.
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader {
    pub magic: u16,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub entry_point: Rva,
    pub image_base: ImageBase,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
}

impl OptionalHeader {
    pub fn is_pe32_plus(&self) -> bool {
        self.magic == OPT_MAGIC_PE32PLUS
    }
}

/// Where a data directory entry points.
///
/// Every directory holds an RVA except the security directory (certificate
/// table), whose `VirtualAddress` header field is a physical file offset by
/// the PE specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectoryAddress {
    Rva(Rva),
    FileOffset(FileOffset),
}

impl DirectoryAddress {
    /// The raw value of the header's `VirtualAddress` field
    pub const fn raw(self) -> u64 {
        match self {
            DirectoryAddress::Rva(rva) => rva.get() as u64,
            DirectoryAddress::FileOffset(off) => off.get(),
        }
    }

    /// The address as an RVA; `None` for the security directory
    pub const fn rva(self) -> Option<Rva> {
        match self {
            DirectoryAddress::Rva(rva) => Some(rva),
            DirectoryAddress::FileOffset(_) => None,
        }
    }

    /// The address as a file offset; `None` for RVA-based directories
    pub const fn file_offset(self) -> Option<FileOffset> {
        match self {
            DirectoryAddress::Rva(_) => None,
            DirectoryAddress::FileOffset(off) => Some(off),
        }
    }
}

/// A single data directory entry.
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub address: DirectoryAddress,
    pub size: u32,
}

impl DataDirectory {
    pub fn is_present(&self) -> bool {
        self.size != 0 && self.address.raw() != 0
    }
}

/// Section header (`IMAGE_SECTION_HEADER`).
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: Rva,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: FileOffset,
    pub characteristics: u32,
    pub permissions: SectionPermissions,
}

impl Section {
    /// Loaded virtual extent. Windows uses `SizeOfRawData` for image sections
    /// whose `VirtualSize` field is zero.
    pub(crate) fn effective_virtual_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.size_of_raw_data
        } else {
            self.virtual_size
        }
    }

    /// Exclusive end of the loaded virtual extent, or `None` when the header
    /// fields overflow.
    ///
    /// Every "is this address inside the image" question in the crate resolves
    /// through this, so the treatment of a zero `VirtualSize` and of overflow is
    /// decided in exactly one place.
    pub(crate) fn virtual_end(&self) -> Option<u32> {
        self.virtual_address
            .get()
            .checked_add(self.effective_virtual_size())
    }

    /// Exclusive end of the raw data in the file, or `None` on overflow.
    pub(crate) fn raw_end(&self) -> Option<u64> {
        self.pointer_to_raw_data
            .get()
            .checked_add(u64::from(self.size_of_raw_data))
    }

    /// Whether the section contains the given RVA in its loaded virtual range.
    /// Raw file-alignment padding beyond `VirtualSize` is not part of that
    /// range and must not shadow the following section.
    fn contains_rva(&self, rva: Rva) -> bool {
        let Some(end) = self.virtual_end() else {
            return false;
        };
        rva.get() >= self.virtual_address.get() && rva.get() < end
    }
}

/// Derived feature set of the input file.
///
/// The directory flags report whether a directory is present; the fields that
/// matter for deciding "can this file be protected safely" are called out
/// separately (CFG and unwind data are handled fail-closed in later stages).
#[derive(Debug, Clone, Copy)]
pub struct Features {
    pub has_exports: bool,
    pub has_imports: bool,
    pub has_resources: bool,
    /// Exception directory (`.pdata`) — x64 unwind data.
    pub has_exception_directory: bool,
    pub has_base_relocations: bool,
    pub has_tls: bool,
    pub has_load_config: bool,
    pub has_delay_imports: bool,
    /// CLR header — a managed (.NET) image.
    pub is_dotnet: bool,
    /// Whether the loader enforces Control Flow Guard: the image opts in through
    /// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`, or ships the function table
    /// enforcement reads. Instrumentation on its own is not enforcement.
    pub control_flow_guard: bool,
    /// Raw `GuardFlags` value from the load config, if it could be read.
    pub guard_flags: Option<u32>,
}

/// A parsed PE file: headers, sections and the structured loader directories.
///
/// The directory models are built during [`PeFile::parse`], not on demand, so a
/// file whose loader metadata cannot be read is rejected outright rather than
/// half-understood. Each is `None` only when the image declares no such
/// directory.
#[derive(Debug, Clone)]
pub struct PeFile {
    pub architecture: Architecture,
    pub dos: DosHeader,
    pub coff: CoffHeader,
    pub optional: OptionalHeader,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
    pub features: Features,
    pub base_relocations: Option<BaseRelocations>,
    pub tls: Option<TlsDirectory>,
    pub exception_table: Option<ExceptionTable>,
    pub imports: Option<Imports>,
    pub exports: Option<Exports>,
}

impl PeFile {
    /// Parses a PE from the full file image.
    pub fn parse(data: &[u8]) -> Result<PeFile, PeError> {
        let r = Reader::new(data);

        // --- DOS header -----------------------------------------------------
        let dos_magic = r.u16(0)?;
        if dos_magic != DOS_MAGIC {
            return Err(PeError::BadDosSignature { found: dos_magic });
        }
        let e_lfanew = r.u32(0x3c)?;
        let dos = DosHeader { e_lfanew };

        // --- PE signature ---------------------------------------------------
        let nt = u64::from(e_lfanew);
        let signature = r.u32(nt)?;
        if signature != PE_SIGNATURE {
            return Err(PeError::BadPeSignature {
                offset: nt,
                found: signature,
            });
        }

        // --- COFF file header ----------------------------------------------
        let coff_off = nt + 4;
        let machine = r.u16(coff_off)?;
        let architecture =
            Architecture::from_machine(machine).ok_or(PeError::UnsupportedMachine { machine })?;
        let coff = CoffHeader {
            machine,
            number_of_sections: r.u16(coff_off + 2)?,
            time_date_stamp: r.u32(coff_off + 4)?,
            pointer_to_symbol_table: FileOffset(u64::from(r.u32(coff_off + 8)?)),
            number_of_symbols: r.u32(coff_off + 12)?,
            size_of_optional_header: r.u16(coff_off + 16)?,
            characteristics: r.u16(coff_off + 18)?,
        };

        // --- Optional header ------------------------------------------------
        let opt_off = coff_off + 20;
        let optional = parse_optional_header(&r, opt_off, coff.size_of_optional_header)?;
        if matches!(
            (architecture, optional.is_pe32_plus()),
            (Architecture::X64, false) | (Architecture::X86, true)
        ) {
            return Err(PeError::MachineOptionalHeaderMismatch {
                machine,
                magic: optional.magic,
            });
        }

        // `rva_to_offset` maps RVAs below SizeOfHeaders one-to-one into the
        // file, so a header region larger than the file itself must be
        // rejected up front rather than produce out-of-file offsets later
        let file_size = data.len() as u64;
        if u64::from(optional.size_of_headers) > file_size {
            return Err(PeError::HeadersExceedFile {
                size_of_headers: optional.size_of_headers,
                file_size,
            });
        }

        // --- Data directories ----------------------------------------------
        // The directories follow immediately after the fixed part of the
        // optional header.
        let dir_off = opt_off + optional_header_fixed_size(optional.magic);
        let dir_count = (optional.number_of_rva_and_sizes as usize).min(directory::MAX);
        // The directories must stay inside the optional header; otherwise the
        // reads below would silently overlap the section table
        let dirs_end =
            optional_header_fixed_size(optional.magic) + (dir_count as u64) * DIRECTORY_ENTRY_SIZE;
        if dirs_end > u64::from(coff.size_of_optional_header) {
            return Err(PeError::DirectoriesExceedOptionalHeader {
                count: dir_count as u32,
                size: coff.size_of_optional_header,
            });
        }
        let mut data_directories = Vec::with_capacity(dir_count);
        for i in 0..dir_count {
            let base = dir_off + (i as u64) * DIRECTORY_ENTRY_SIZE;
            let raw = r.u32(base)?;
            // The certificate table is the one directory whose VirtualAddress
            // field holds a physical file offset instead of an RVA
            let address = if i == directory::SECURITY {
                DirectoryAddress::FileOffset(FileOffset(u64::from(raw)))
            } else {
                DirectoryAddress::Rva(Rva(raw))
            };
            data_directories.push(DataDirectory {
                address,
                size: r.u32(base + 4)?,
            });
        }
        validate_security_directory(&data_directories, file_size)?;

        // --- Section table --------------------------------------------------
        // The section table starts after the whole optional header.
        let sec_off = opt_off + u64::from(coff.size_of_optional_header);
        let section_table_size = u64::from(coff.number_of_sections)
            .checked_mul(SECTION_HEADER_SIZE)
            .ok_or(PeError::Overflow {
                field: "section table size",
            })?;
        let section_table_end =
            sec_off
                .checked_add(section_table_size)
                .ok_or(PeError::Overflow {
                    field: "section table end",
                })?;
        if section_table_end > u64::from(optional.size_of_headers) {
            return Err(PeError::SectionTableExceedsHeaders {
                table_end: section_table_end,
                size_of_headers: optional.size_of_headers,
            });
        }
        let mut sections = Vec::with_capacity(coff.number_of_sections as usize);
        for i in 0..coff.number_of_sections as u64 {
            let base = sec_off + i * SECTION_HEADER_SIZE;
            sections.push(parse_section(&r, base)?);
        }
        validate_section_ranges(
            &sections,
            file_size,
            optional.size_of_headers,
            optional.size_of_image,
        )?;
        validate_alignments(&optional, &sections)?;

        let features = detect_features(&r, &optional, &data_directories, &sections)?;

        // The structured directories need a model to resolve RVAs against, so
        // they are parsed from a header-only file and folded in afterwards
        let mut pe = PeFile {
            architecture,
            dos,
            coff,
            optional,
            data_directories,
            sections,
            features,
            base_relocations: None,
            tls: None,
            exception_table: None,
            imports: None,
            exports: None,
        };
        pe.base_relocations = BaseRelocations::parse(&pe, data)?;
        pe.tls = TlsDirectory::parse(&pe, data)?;
        pe.exception_table = ExceptionTable::parse(&pe, data)?;
        pe.imports = Imports::parse(&pe, data)?;
        pe.exports = Exports::parse(&pe, data)?;
        Ok(pe)
    }

    /// Returns the data directory at `index` if it is present in the table.
    pub fn data_directory(&self, index: usize) -> Option<DataDirectory> {
        self.data_directories.get(index).copied()
    }

    /// The entry point as an RVA.
    pub fn entry_point(&self) -> Rva {
        self.optional.entry_point
    }

    /// Computes the image's PE checksum over `data`.
    ///
    /// The stored `CheckSum` field is treated as zero, exactly as the documented
    /// algorithm requires, so the result can be compared against the stored value
    /// to decide whether it is current.
    pub fn compute_checksum(&self, data: &[u8]) -> Result<u32, PeError> {
        // The field sits 64 bytes into the optional header, which follows the
        // 4-byte signature and the 20-byte COFF header
        let offset = u64::from(self.dos.e_lfanew)
            .checked_add(88)
            .ok_or(PeError::Overflow {
                field: "checksum field offset",
            })?;
        writer::pe_checksum(data, offset)
    }

    /// Whether `[rva, rva + size)` lies inside one section's loaded extent.
    ///
    /// This is virtual coverage, not file backing: a section's zero-filled tail
    /// is mapped memory the loader may write to even though no file bytes back
    /// it.
    pub fn covers_virtual_range(&self, rva: Rva, size: u32) -> bool {
        let Some(end) = rva.get().checked_add(size) else {
            return false;
        };
        self.sections
            .iter()
            .any(|section| match section.virtual_end() {
                Some(section_end) => {
                    rva.get() >= section.virtual_address.get() && end <= section_end
                }
                None => false,
            })
    }

    /// The section whose loaded virtual range covers `rva`.
    ///
    /// Callers that need to know whether an address is code — the decoder, for
    /// one — resolve it through here so that "which section owns this address"
    /// has a single answer, including the treatment of a zero `VirtualSize`.
    pub fn section_at(&self, rva: Rva) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.contains_rva(rva))
    }

    /// Returns every byte that is mapped contiguously from `rva` onwards.
    ///
    /// The slice stops at the end of the header region or of the section's raw
    /// data, whichever contains the address, so any walk over the result is
    /// bounded by the file layout instead of by a caller-chosen limit.
    pub fn mapped_from<'a>(&self, data: &'a [u8], rva: Rva) -> Result<&'a [u8], PeError> {
        // One resolution decides both the file offset and how far the containing
        // region reaches, so the two can never disagree about which region holds
        // the address.
        let (offset, available) = self.resolve_rva(rva)?;
        let start = usize::try_from(offset.get()).map_err(|_| PeError::Truncated {
            offset: offset.get(),
            needed: 1,
            available: data.len() as u64,
        })?;
        let end = usize::try_from(offset.get().saturating_add(available)).unwrap_or(usize::MAX);
        data.get(start..end.min(data.len()))
            .ok_or(PeError::Truncated {
                offset: offset.get(),
                needed: available,
                available: data.len() as u64,
            })
    }

    /// Returns exactly `size` bytes mapped at `rva`.
    pub fn mapped_range<'a>(
        &self,
        data: &'a [u8],
        rva: Rva,
        size: u32,
    ) -> Result<&'a [u8], PeError> {
        let mapped = self.mapped_from(data, rva)?;
        mapped
            .get(..usize::try_from(size).unwrap_or(usize::MAX))
            .ok_or(PeError::Truncated {
                offset: u64::from(rva.get()),
                needed: u64::from(size),
                available: mapped.len() as u64,
            })
    }

    /// Returns the file-backed bytes of a data directory, or `None` when the
    /// directory is absent.
    ///
    /// A present directory that is not fully backed by file data is an error:
    /// the loader would read bytes that do not exist in the image.
    pub fn directory_bytes<'a>(
        &self,
        data: &'a [u8],
        index: usize,
    ) -> Result<Option<&'a [u8]>, PeError> {
        let Some(entry) = self.data_directory(index) else {
            return Ok(None);
        };
        if !entry.is_present() {
            return Ok(None);
        }
        let rva = entry.address.rva().ok_or(PeError::MalformedDirectory {
            directory: index,
            reason: "entry is a file offset, not an RVA",
        })?;
        self.mapped_range(data, rva, entry.size)
            .map(Some)
            .map_err(|_| PeError::MalformedDirectory {
                directory: index,
                reason: "the declared range is not backed by file data",
            })
    }

    /// Reads a NUL-terminated byte string at `rva`.
    ///
    /// The search is bounded by the mapped raw data holding `rva`, so a missing
    /// terminator is a typed error rather than an unbounded scan.
    pub fn mapped_cstr<'a>(&self, data: &'a [u8], rva: Rva) -> Result<&'a [u8], PeError> {
        let mapped = self.mapped_from(data, rva)?;
        let end = mapped
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(PeError::UnterminatedString {
                rva: u64::from(rva.get()),
            })?;
        Ok(&mapped[..end])
    }

    /// Reads the NUL-terminated name at `rva` and decodes it as (lossy) UTF-8.
    ///
    /// PE name tables are nominally ASCII, but nothing in the format enforces
    /// it, so an ill-formed byte becomes a replacement character rather than an
    /// error: the name is descriptive, and refusing the whole image over one
    /// stray byte would be stricter than the loader.
    pub fn mapped_string(&self, data: &[u8], rva: Rva) -> Result<String, PeError> {
        Ok(String::from_utf8_lossy(self.mapped_cstr(data, rva)?).into_owned())
    }

    /// Translates an RVA to a physical file offset.
    ///
    /// An RVA inside the header region maps one-to-one; otherwise the section
    /// whose raw data covers the address is located.
    pub fn rva_to_offset(&self, rva: Rva) -> Result<FileOffset, PeError> {
        self.resolve_rva(rva).map(|(offset, _)| offset)
    }

    /// Resolves `rva` to its file offset and to how many file-backed bytes
    /// follow it contiguously in the region that holds it.
    ///
    /// This is the crate's single RVA→file mapping: everything that needs an
    /// offset, a length, or just "is it mapped" goes through here, so there is
    /// one answer to which region owns an address.
    fn resolve_rva(&self, rva: Rva) -> Result<(FileOffset, u64), PeError> {
        let unmapped = || PeError::UnmappedRva {
            rva: u64::from(rva.get()),
        };
        if rva.get() < self.optional.size_of_headers {
            let available =
                u64::from(self.optional.size_of_headers).saturating_sub(u64::from(rva.get()));
            return Ok((FileOffset(u64::from(rva.get())), available));
        }
        let section = self
            .sections
            .iter()
            .find(|section| section.contains_rva(rva))
            .ok_or_else(unmapped)?;
        // An offset into the section's raw data only exists if the RVA fits
        // within size_of_raw_data (not the purely virtual tail).
        let delta = rva.get() - section.virtual_address.get();
        if delta >= section.size_of_raw_data {
            return Err(unmapped());
        }
        let offset = section
            .pointer_to_raw_data
            .get()
            .checked_add(u64::from(delta))
            .ok_or(PeError::Overflow {
                field: "rva_to_offset",
            })?;
        let available = u64::from(section.size_of_raw_data).saturating_sub(u64::from(delta));
        Ok((FileOffset(offset), available))
    }
}

/// Fixed length (without data directories) of the optional header, by magic.
pub(crate) fn optional_header_fixed_size(magic: u16) -> u64 {
    match magic {
        OPT_MAGIC_PE32PLUS => 112,
        _ => 96, // PE32
    }
}

fn parse_optional_header(
    r: &Reader<'_>,
    off: u64,
    size_of_optional_header: u16,
) -> Result<OptionalHeader, PeError> {
    let magic = r.u16(off)?;
    if magic != OPT_MAGIC_PE32 && magic != OPT_MAGIC_PE32PLUS {
        return Err(PeError::UnsupportedOptionalMagic { magic });
    }
    if u64::from(size_of_optional_header) < optional_header_fixed_size(magic) {
        return Err(PeError::OptionalHeaderTooSmall {
            size: size_of_optional_header,
            magic,
        });
    }

    let entry_point = Rva(r.u32(off + 16)?);

    // ImageBase, and the placement of the later fields, depend on the bitness.
    let (image_base, tail) = if magic == OPT_MAGIC_PE32PLUS {
        // PE32+: no BaseOfData; ImageBase is a u64 at offset 24.
        (ImageBase(r.u64(off + 24)?), off + 24 + 8)
    } else {
        // PE32: ImageBase is a u32 at offset 28 (after BaseOfData).
        (ImageBase(u64::from(r.u32(off + 28)?)), off + 28 + 4)
    };

    // From `tail` (SectionAlignment) the fields have the same width and offset
    // in both PE32 and PE32+, up to and including DllCharacteristics.
    // tail + 0x08..0x18 are OS/Image/Subsystem versions (u16) and Win32VersionValue.
    let section_alignment = r.u32(tail)?; // tail + 0x00
    let file_alignment = r.u32(tail + 4)?; // tail + 0x04
    let size_of_image = r.u32(tail + 24)?; // tail + 0x18
    let size_of_headers = r.u32(tail + 28)?; // tail + 0x1c
    let checksum = r.u32(tail + 32)?; // tail + 0x20
    let subsystem = r.u16(tail + 36)?; // tail + 0x24
    let dll_characteristics = r.u16(tail + 38)?; // tail + 0x26

    // Next come four stack/heap size fields (u32 in PE32, u64 in PE32+), then
    // LoaderFlags(u32) and NumberOfRvaAndSizes(u32). The width difference
    // shifts NumberOfRvaAndSizes by 16 bytes between the two formats.
    let number_of_rva_and_sizes = if magic == OPT_MAGIC_PE32PLUS {
        r.u32(tail + 76)? // tail + 0x4c
    } else {
        r.u32(tail + 60)? // tail + 0x3c
    };

    Ok(OptionalHeader {
        magic,
        size_of_code: r.u32(off + 4)?,
        size_of_initialized_data: r.u32(off + 8)?,
        size_of_uninitialized_data: r.u32(off + 12)?,
        entry_point,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        number_of_rva_and_sizes,
    })
}

fn parse_section(r: &Reader<'_>, base: u64) -> Result<Section, PeError> {
    let raw_name = r.bytes(base, 8)?;
    // Name is up to 8 bytes, NUL-padded; tolerate invalid UTF-8.
    let end = raw_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_name.len());
    let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
    let characteristics = r.u32(base + 36)?;
    Ok(Section {
        name,
        virtual_size: r.u32(base + 8)?,
        virtual_address: Rva(r.u32(base + 12)?),
        size_of_raw_data: r.u32(base + 16)?,
        pointer_to_raw_data: FileOffset(u64::from(r.u32(base + 20)?)),
        characteristics,
        permissions: SectionPermissions::from_characteristics(characteristics),
    })
}

fn validate_security_directory(
    directories: &[DataDirectory],
    file_size: u64,
) -> Result<(), PeError> {
    let Some(security) = directories.get(directory::SECURITY).copied() else {
        return Ok(());
    };
    let offset = security
        .address
        .file_offset()
        .ok_or(PeError::MalformedSecurityDirectory {
            reason: "entry is not file-offset typed",
        })?
        .get();
    match (offset, security.size) {
        (0, 0) => return Ok(()),
        (0, _) | (_, 0) => {
            return Err(PeError::MalformedSecurityDirectory {
                reason: "offset and size must both be zero or both be non-zero",
            });
        }
        _ => {}
    }
    if !offset.is_multiple_of(DIRECTORY_ENTRY_SIZE) {
        return Err(PeError::MalformedSecurityDirectory {
            reason: "certificate table offset is not 8-byte aligned",
        });
    }
    let end = offset.checked_add(u64::from(security.size)).ok_or(
        PeError::MalformedSecurityDirectory {
            reason: "certificate table range overflows",
        },
    )?;
    if end > file_size {
        return Err(PeError::MalformedSecurityDirectory {
            reason: "certificate table range exceeds the file",
        });
    }
    Ok(())
}

fn validate_section_ranges(
    sections: &[Section],
    file_size: u64,
    size_of_headers: u32,
    size_of_image: u32,
) -> Result<(), PeError> {
    let mut raw_ranges = Vec::with_capacity(sections.len());
    let mut virtual_ranges = Vec::with_capacity(sections.len());

    for (index, section) in sections.iter().enumerate() {
        if section.size_of_raw_data != 0 {
            let start = section.pointer_to_raw_data.get();
            let end = start
                .checked_add(u64::from(section.size_of_raw_data))
                .ok_or(PeError::Overflow {
                    field: "section raw range",
                })?;
            let headers_end = u64::from(size_of_headers);
            if start < headers_end {
                return Err(PeError::SectionRawDataOverlapsHeaders {
                    index,
                    start,
                    end,
                    headers_end,
                });
            }
            if end > file_size {
                return Err(PeError::SectionRawDataOutOfBounds {
                    index,
                    start,
                    end,
                    file_size,
                });
            }
            raw_ranges.push((start, end, index));
        }

        let virtual_size = section.effective_virtual_size();
        if virtual_size != 0 {
            let start_rva = section.virtual_address.get();
            let end_rva = start_rva
                .checked_add(virtual_size)
                .ok_or(PeError::Overflow {
                    field: "section RVA range",
                })?;
            let start = u64::from(start_rva);
            let end = u64::from(end_rva);
            let headers_end = u64::from(size_of_headers);
            if start < headers_end {
                return Err(PeError::SectionOverlapsHeaders {
                    index,
                    start,
                    end,
                    headers_end,
                });
            }
            let image_end = u64::from(size_of_image);
            if end > image_end {
                return Err(PeError::SectionExceedsImage {
                    index,
                    start,
                    end,
                    size_of_image: image_end,
                });
            }
            virtual_ranges.push((start, end, index));
        }
    }

    validate_non_overlapping(&mut raw_ranges, "file")?;
    validate_non_overlapping(&mut virtual_ranges, "RVA")
}

/// Validates the image's alignment profile and every layout field derived from
/// it.
///
/// The parser owns these checks because the whole model is ambiguous without
/// them: `rva_to_offset`, overlap detection and any writer arithmetic all assume
/// that the declared alignments describe how the loader actually maps the file.
/// The narrower question of which profiles can be *rewritten* stays in
/// [`writer`].
fn validate_alignments(optional: &OptionalHeader, sections: &[Section]) -> Result<(), PeError> {
    let section_alignment = optional.section_alignment;
    let file_alignment = optional.file_alignment;

    // Zero or non-power-of-two alignments come first: every rule below divides
    // by these values
    for (field, value) in [
        ("SectionAlignment", section_alignment),
        ("FileAlignment", file_alignment),
    ] {
        if value == 0 || !value.is_power_of_two() {
            return Err(PeError::InvalidAlignment { field, value });
        }
    }

    let incompatible = |reason| PeError::IncompatibleAlignments {
        section_alignment,
        file_alignment,
        reason,
    };
    if section_alignment < file_alignment {
        return Err(incompatible("SectionAlignment must not be the smaller one"));
    }
    if section_alignment < PAGE_SIZE {
        // Below a page the loader maps the file one-to-one, which only has a
        // single consistent reading when both alignments agree
        if file_alignment != section_alignment {
            return Err(incompatible(
                "a sub-page SectionAlignment requires FileAlignment to match it",
            ));
        }
    } else if !(MIN_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment) {
        return Err(incompatible(
            "FileAlignment must be between 0x200 and 0x10000",
        ));
    }

    for (index, section) in sections.iter().enumerate() {
        let misaligned = |field, value: u64, alignment| PeError::MisalignedSection {
            index,
            field,
            value,
            alignment,
        };
        if !section
            .virtual_address
            .get()
            .is_multiple_of(section_alignment)
        {
            return Err(misaligned(
                "VirtualAddress",
                u64::from(section.virtual_address.get()),
                section_alignment,
            ));
        }
        // A section without raw data keeps whatever PointerToRawData the linker
        // left behind; nothing is mapped from it, so it carries no alignment
        if section.size_of_raw_data == 0 {
            continue;
        }
        if !section
            .pointer_to_raw_data
            .get()
            .is_multiple_of(u64::from(file_alignment))
        {
            return Err(misaligned(
                "PointerToRawData",
                section.pointer_to_raw_data.get(),
                file_alignment,
            ));
        }
        if !section.size_of_raw_data.is_multiple_of(file_alignment) {
            return Err(misaligned(
                "SizeOfRawData",
                u64::from(section.size_of_raw_data),
                file_alignment,
            ));
        }
    }

    if !optional.size_of_image.is_multiple_of(section_alignment) {
        return Err(PeError::Misaligned {
            field: "SizeOfImage",
            value: u64::from(optional.size_of_image),
            alignment: section_alignment,
        });
    }
    Ok(())
}

fn validate_non_overlapping(
    ranges: &mut [(u64, u64, usize)],
    space: &'static str,
) -> Result<(), PeError> {
    ranges.sort_unstable_by_key(|&(start, end, index)| (start, end, index));

    let Some(&(_, mut previous_end, mut previous_index)) = ranges.first() else {
        return Ok(());
    };

    for &(start, end, index) in &ranges[1..] {
        if start < previous_end {
            return Err(PeError::OverlappingSections {
                space,
                first: previous_index,
                second: index,
            });
        }
        previous_end = end;
        previous_index = index;
    }

    Ok(())
}

fn detect_features(
    r: &Reader<'_>,
    optional: &OptionalHeader,
    dirs: &[DataDirectory],
    sections: &[Section],
) -> Result<Features, PeError> {
    let present = |index: usize| dirs.get(index).is_some_and(DataDirectory::is_present);

    let has_load_config = present(directory::LOAD_CONFIG);
    let guard_flags = if has_load_config {
        read_guard_flags(r, optional, dirs, sections)?
    } else {
        None
    };

    // Without the opt-in bit the kernel builds no CFG bitmap for the image and
    // the check pointer stays a nop, however much instrumentation the code
    // carries — every image linked against an instrumented MSVC CRT has
    // `CF_INSTRUMENTED`. The function table counts because it is the metadata
    // enforcement reads, so appended code must not be missing from it.
    let cfg_from_dll = optional.dll_characteristics & dll_characteristics::GUARD_CF != 0;
    let cfg_from_table =
        guard_flags.is_some_and(|f| f & guard_flags::CF_FUNCTION_TABLE_PRESENT != 0);

    Ok(Features {
        has_exports: present(directory::EXPORT),
        has_imports: present(directory::IMPORT),
        has_resources: present(directory::RESOURCE),
        has_exception_directory: present(directory::EXCEPTION),
        has_base_relocations: present(directory::BASERELOC),
        has_tls: present(directory::TLS),
        has_load_config,
        has_delay_imports: present(directory::DELAY_IMPORT),
        is_dotnet: present(directory::CLR),
        control_flow_guard: cfg_from_dll || cfg_from_table,
        guard_flags,
    })
}

/// Reads `GuardFlags` from a structurally valid load-config directory.
///
/// Older load-config versions that end before `GuardFlags` are valid and return
/// `None`. Once the structure declares that field, it must be fully mapped.
fn read_guard_flags(
    r: &Reader<'_>,
    optional: &OptionalHeader,
    dirs: &[DataDirectory],
    sections: &[Section],
) -> Result<Option<u32>, PeError> {
    let dir = dirs
        .get(directory::LOAD_CONFIG)
        .copied()
        .ok_or(PeError::MalformedLoadConfig {
            reason: "directory entry is missing",
        })?;
    if !dir.is_present() {
        return Ok(None);
    }
    let base_rva = dir.address.rva().ok_or(PeError::MalformedLoadConfig {
        reason: "directory address is not an RVA",
    })?;
    if dir.size < 4 {
        return Err(PeError::MalformedLoadConfig {
            reason: "directory is too small for its Size field",
        });
    }
    let base_off = rva_range_to_offset_in(sections, optional.size_of_headers, base_rva, 4).ok_or(
        PeError::MalformedLoadConfig {
            reason: "Size field is not backed by file data",
        },
    )?;
    let structure_size = r
        .u32(base_off.get())
        .map_err(|_| PeError::MalformedLoadConfig {
            reason: "Size field is truncated",
        })?;
    if structure_size < 4 {
        return Err(PeError::MalformedLoadConfig {
            reason: "structure Size is smaller than its own field",
        });
    }

    // The data-directory size is not a reliable version bound for legacy
    // images. Real pre-Win8 IMAGE_LOAD_CONFIG_DIRECTORY32 files can keep an
    // older directory size while the structure's own Size covers later fields.
    // Use the internal Size to decide whether GuardFlags is declared, then
    // independently require the exact field bytes to be mapped below.
    let guard_flags_offset: u32 = if optional.is_pe32_plus() { 0x90 } else { 0x58 };
    let guard_flags_end =
        guard_flags_offset
            .checked_add(4)
            .ok_or(PeError::MalformedLoadConfig {
                reason: "GuardFlags offset overflows",
            })?;
    if structure_size < guard_flags_end {
        return Ok(None);
    }

    let field_rva =
        base_rva
            .checked_add(guard_flags_offset)
            .ok_or(PeError::MalformedLoadConfig {
                reason: "GuardFlags RVA overflows",
            })?;
    let file_off = rva_range_to_offset_in(sections, optional.size_of_headers, field_rva, 4).ok_or(
        PeError::MalformedLoadConfig {
            reason: "GuardFlags is not backed by file data",
        },
    )?;
    r.u32(file_off.get())
        .map(Some)
        .map_err(|_| PeError::MalformedLoadConfig {
            reason: "GuardFlags is truncated",
        })
}

/// Maps a complete RVA range into one contiguous raw range.
fn rva_range_to_offset_in(
    sections: &[Section],
    size_of_headers: u32,
    rva: Rva,
    size: u32,
) -> Option<FileOffset> {
    let start = u64::from(rva.get());
    let end = start.checked_add(u64::from(size))?;
    if start < u64::from(size_of_headers) && end <= u64::from(size_of_headers) {
        return Some(FileOffset(start));
    }

    for section in sections {
        let section_start = u64::from(section.virtual_address.get());
        let Some(delta) = start.checked_sub(section_start) else {
            continue;
        };
        let range_end = delta.checked_add(u64::from(size))?;
        if range_end <= u64::from(section.effective_virtual_size())
            && range_end <= u64::from(section.size_of_raw_data)
        {
            return section.pointer_to_raw_data.checked_add(delta);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(PeFile::parse(&[]), Err(PeError::Truncated { .. })));
    }

    #[test]
    fn rejects_bad_dos_magic() {
        let data = [0u8; 512];
        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::BadDosSignature { .. })
        ));
    }

    #[test]
    fn optional_header_fixed_sizes() {
        assert_eq!(optional_header_fixed_size(OPT_MAGIC_PE32PLUS), 112);
        assert_eq!(optional_header_fixed_size(OPT_MAGIC_PE32), 96);
    }

    #[test]
    fn parses_minimal_synthetic_pe32_plus() {
        let data = minimal_pe64(0x200);
        let pe = PeFile::parse(&data).expect("synthetic image must parse");

        assert_eq!(pe.architecture, Architecture::X64);
        assert!(pe.optional.is_pe32_plus());
        assert_eq!(pe.entry_point(), Rva(0x1000));
        assert_eq!(pe.optional.image_base, ImageBase(0x1_4000_0000));
        assert_eq!(pe.data_directories.len(), 16);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
        assert!(pe.sections[0].permissions.execute);

        // An RVA in the header region maps one-to-one; a section RVA maps
        // into the raw data
        let header_off = pe.rva_to_offset(Rva(0x100)).expect("header RVA maps");
        assert_eq!(header_off, FileOffset(0x100));
        let text_off = pe.rva_to_offset(Rva(0x1010)).expect(".text RVA maps");
        assert_eq!(text_off, FileOffset(0x210));
    }

    #[test]
    fn rejects_x64_machine_with_pe32_optional_header() {
        let mut data = minimal_pe32(0x200);
        put_u16(&mut data, 0x44, Architecture::MACHINE_AMD64);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MachineOptionalHeaderMismatch {
                machine: Architecture::MACHINE_AMD64,
                magic: OPT_MAGIC_PE32,
            })
        ));
    }

    #[test]
    fn rejects_x86_machine_with_pe32_plus_optional_header() {
        let mut data = minimal_pe64(0x200);
        put_u16(&mut data, 0x44, Architecture::MACHINE_I386);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MachineOptionalHeaderMismatch {
                machine: Architecture::MACHINE_I386,
                magic: OPT_MAGIC_PE32PLUS,
            })
        ));
    }

    #[test]
    fn rejects_size_of_headers_past_end_of_file() {
        // A header RVA below this bogus SizeOfHeaders would otherwise map to
        // a file offset far past the 0x400-byte buffer
        let data = minimal_pe64(0x5000_0000);
        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::HeadersExceedFile { .. })
        ));
    }

    #[test]
    fn rejects_size_of_headers_smaller_than_section_table() {
        let data = minimal_pe64(0x100);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::SectionTableExceedsHeaders { .. })
        ));
    }

    #[test]
    fn rejects_raw_section_range_overlapping_headers() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 20, 0x100);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::SectionRawDataOverlapsHeaders { index: 0, .. })
        ));
    }

    #[test]
    fn security_directory_is_a_file_offset() {
        let mut data = minimal_pe64(0x200);
        // Directory entries start right after the 112-byte fixed header
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::SECURITY * 8, 0x300);
        put_u32(&mut data, dirs + directory::SECURITY * 8 + 4, 0x40);
        // A directory with no structured model of its own, so this test stays
        // about address typing
        put_u32(&mut data, dirs + directory::RESOURCE * 8, 0x1000);
        put_u32(&mut data, dirs + directory::RESOURCE * 8 + 4, 0x10);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");

        let security = pe.data_directory(directory::SECURITY).expect("in table");
        assert!(security.is_present());
        assert_eq!(
            security.address,
            DirectoryAddress::FileOffset(FileOffset(0x300))
        );
        assert_eq!(security.address.rva(), None);
        assert_eq!(security.address.raw(), 0x300);

        // Every other directory stays RVA-typed
        let resource = pe.data_directory(directory::RESOURCE).expect("in table");
        assert_eq!(resource.address.rva(), Some(Rva(0x1000)));
        assert!(pe.features.has_resources);
    }

    #[test]
    fn rejects_half_present_security_directory() {
        let dirs = 0x58 + 112;
        for (offset, size) in [(0, 8), (0x300, 0)] {
            let mut data = minimal_pe64(0x200);
            put_u32(&mut data, dirs + directory::SECURITY * 8, offset);
            put_u32(&mut data, dirs + directory::SECURITY * 8 + 4, size);

            assert!(matches!(
                PeFile::parse(&data),
                Err(PeError::MalformedSecurityDirectory { .. })
            ));
        }
    }

    #[test]
    fn rejects_security_directory_range_past_eof() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::SECURITY * 8, 0x400);
        put_u32(&mut data, dirs + directory::SECURITY * 8 + 4, 8);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedSecurityDirectory { .. })
        ));
    }

    #[test]
    fn rejects_misaligned_security_directory_offset() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::SECURITY * 8, 0x301);
        put_u32(&mut data, dirs + directory::SECURITY * 8 + 4, 8);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedSecurityDirectory { .. })
        ));
    }

    #[test]
    fn rejects_directories_outside_optional_header() {
        let mut data = minimal_pe64(0x200);
        // Shrink SizeOfOptionalHeader to the fixed part only while still
        // claiming 16 data directories
        put_u16(&mut data, 0x54, 112);
        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::DirectoriesExceedOptionalHeader { .. })
        ));
    }

    #[test]
    fn rejects_raw_section_past_end_of_file() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 16, 0x400);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::SectionRawDataOutOfBounds { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_overlapping_raw_sections() {
        let mut data = minimal_pe64(0x200);
        add_second_section(&mut data, 0x2000, 0x200, 0x300, 0x200);
        put_u32(&mut data, 0x58 + 56, 0x3000); // SizeOfImage

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::OverlappingSections {
                space: "file",
                first: 0,
                second: 1,
            })
        ));
    }

    #[test]
    fn rejects_overlapping_virtual_sections() {
        let mut data = minimal_pe64(0x200);
        add_second_section(&mut data, 0x1100, 0x200, 0x400, 0x200);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::OverlappingSections {
                space: "RVA",
                first: 0,
                second: 1,
            })
        ));
    }

    #[test]
    fn rejects_section_virtual_range_overlapping_headers() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 12, 0); // VirtualAddress
        put_u32(&mut data, 0x148 + 8, 0x1000); // VirtualSize

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::SectionOverlapsHeaders { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_section_beyond_size_of_image() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 12, 0x3000); // VirtualAddress
        put_u32(&mut data, 0x148 + 8, 0x100); // VirtualSize

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::SectionExceedsImage { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_section_virtual_range_past_rva_address_space() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 12, 0xffff_f000);
        put_u32(&mut data, 0x148 + 8, 0x2000);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::Overflow {
                field: "section RVA range"
            })
        ));
    }

    #[test]
    fn rejects_zero_section_alignment() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 32, 0);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::InvalidAlignment {
                field: "SectionAlignment",
                value: 0,
            })
        ));
    }

    #[test]
    fn rejects_zero_file_alignment() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 36, 0);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::InvalidAlignment {
                field: "FileAlignment",
                value: 0,
            })
        ));
    }

    #[test]
    fn rejects_non_power_of_two_alignments() {
        let mut section = minimal_pe64(0x200);
        put_u32(&mut section, 0x58 + 32, 0x3000);
        assert!(matches!(
            PeFile::parse(&section),
            Err(PeError::InvalidAlignment {
                field: "SectionAlignment",
                value: 0x3000,
            })
        ));

        let mut file = minimal_pe64(0x200);
        put_u32(&mut file, 0x58 + 36, 0x300);
        assert!(matches!(
            PeFile::parse(&file),
            Err(PeError::InvalidAlignment {
                field: "FileAlignment",
                value: 0x300,
            })
        ));
    }

    #[test]
    fn rejects_section_alignment_below_file_alignment() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 36, 0x2000); // FileAlignment > SectionAlignment

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::IncompatibleAlignments {
                section_alignment: 0x1000,
                file_alignment: 0x2000,
                ..
            })
        ));
    }

    #[test]
    fn rejects_low_alignment_image_whose_alignments_differ() {
        // Below the page size the loader maps the file one-to-one, so the PE
        // specification requires the two alignments to be equal
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 32, 0x800); // SectionAlignment
        put_u32(&mut data, 0x58 + 36, 0x200); // FileAlignment

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::IncompatibleAlignments {
                section_alignment: 0x800,
                file_alignment: 0x200,
                ..
            })
        ));
    }

    #[test]
    fn rejects_file_alignment_outside_the_specified_range() {
        for file_alignment in [0x100u32, 0x2_0000] {
            let mut data = minimal_pe64(0x200);
            put_u32(&mut data, 0x58 + 32, 0x2_0000); // SectionAlignment >= FileAlignment
            put_u32(&mut data, 0x58 + 36, file_alignment);
            put_u32(&mut data, 0x58 + 56, 0x4_0000); // SizeOfImage
            put_u32(&mut data, 0x148 + 12, 0x2_0000); // .text VirtualAddress

            assert!(
                matches!(
                    PeFile::parse(&data),
                    Err(PeError::IncompatibleAlignments { .. })
                ),
                "FileAlignment {file_alignment:#x} must be rejected"
            );
        }
    }

    #[test]
    fn accepts_low_alignment_image_for_inspection() {
        // A 1:1 mapped image is a valid PE the parser must still describe; only
        // the writer refuses to rewrite that profile
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 32, 0x200); // SectionAlignment
        put_u32(&mut data, 0x58 + 36, 0x200); // FileAlignment
        put_u32(&mut data, 0x58 + 56, 0x400); // SizeOfImage
        put_u32(&mut data, 0x148 + 12, 0x200); // .text VirtualAddress == raw offset

        let pe = PeFile::parse(&data).expect("low-alignment images stay inspectable");
        assert_eq!(pe.optional.section_alignment, 0x200);
    }

    #[test]
    fn rejects_misaligned_section_rva() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 12, 0x1800); // .text VirtualAddress

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MisalignedSection {
                index: 0,
                field: "VirtualAddress",
                value: 0x1800,
                alignment: 0x1000,
            })
        ));
    }

    #[test]
    fn rejects_misaligned_section_raw_offset() {
        let mut data = minimal_pe64(0x200);
        data.resize(0x600, 0);
        put_u32(&mut data, 0x148 + 20, 0x300); // .text PointerToRawData

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MisalignedSection {
                index: 0,
                field: "PointerToRawData",
                value: 0x300,
                alignment: 0x200,
            })
        ));
    }

    #[test]
    fn rejects_misaligned_section_raw_size() {
        let mut data = minimal_pe64(0x200);
        data.resize(0x600, 0);
        put_u32(&mut data, 0x148 + 16, 0x300); // .text SizeOfRawData

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MisalignedSection {
                index: 0,
                field: "SizeOfRawData",
                value: 0x300,
                alignment: 0x200,
            })
        ));
    }

    #[test]
    fn ignores_raw_alignment_of_sections_without_raw_data() {
        // A BSS section keeps a stale PointerToRawData; with SizeOfRawData zero
        // it maps nothing, so the field carries no layout meaning
        let mut data = minimal_pe64(0x200);
        add_second_section(&mut data, 0x2000, 0x1000, 0x301, 0);
        data.truncate(0x400);
        put_u32(&mut data, 0x58 + 56, 0x3000); // SizeOfImage
        put_u32(&mut data, 0x148 + 40 + 36, 0xc000_0080); // BSS

        let pe = PeFile::parse(&data).expect("zero-length raw ranges carry no alignment");
        assert_eq!(pe.sections[1].pointer_to_raw_data, FileOffset(0x301));
    }

    #[test]
    fn rejects_misaligned_size_of_image() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x58 + 56, 0x2200); // SizeOfImage

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::Misaligned {
                field: "SizeOfImage",
                value: 0x2200,
                alignment: 0x1000,
            })
        ));
    }

    #[test]
    fn accepts_old_load_config_without_guard_flags() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x1100);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x80);
        put_u32(&mut data, 0x300, 0x80);

        let pe = PeFile::parse(&data).expect("old load config is valid");
        assert!(pe.features.has_load_config);
        assert_eq!(pe.features.guard_flags, None);
    }

    #[test]
    fn rejects_unmapped_guard_flags_in_load_config() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x11f0);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x94);
        put_u32(&mut data, 0x3f0, 0x94);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedLoadConfig { .. })
        ));
    }

    #[test]
    fn rejects_load_config_in_raw_padding_beyond_virtual_size() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 8, 0x100); // .text VirtualSize
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x1100);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x94);
        put_u32(&mut data, 0x300, 0x94);
        put_u32(&mut data, 0x390, guard_flags::CF_INSTRUMENTED);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedLoadConfig { .. })
        ));
    }

    #[test]
    fn reads_valid_guard_flags() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x1100);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x94);
        put_u32(&mut data, 0x300, 0x94);
        put_u32(&mut data, 0x300 + 0x90, guard_flags::CF_INSTRUMENTED);

        let pe = PeFile::parse(&data).expect("load config is valid");
        assert_eq!(pe.features.guard_flags, Some(guard_flags::CF_INSTRUMENTED));
        assert!(!pe.features.control_flow_guard);
    }

    #[test]
    fn a_guard_cf_function_table_is_control_flow_guard() {
        let mut data = minimal_pe64(0x200);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x1100);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x94);
        put_u32(&mut data, 0x300, 0x94);
        put_u32(
            &mut data,
            0x300 + 0x90,
            guard_flags::CF_FUNCTION_TABLE_PRESENT,
        );

        let pe = PeFile::parse(&data).expect("load config is valid");
        assert!(pe.features.control_flow_guard);
    }

    #[test]
    fn reads_valid_pe32_guard_flags() {
        let mut data = minimal_pe32(0x200);
        let dirs = 0x58 + 96;
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8, 0x1100);
        put_u32(&mut data, dirs + directory::LOAD_CONFIG * 8 + 4, 0x5c);
        put_u32(&mut data, 0x300, 0x5c);
        put_u32(&mut data, 0x300 + 0x58, guard_flags::CF_INSTRUMENTED);

        let pe = PeFile::parse(&data).expect("PE32 load config is valid");
        assert_eq!(pe.features.guard_flags, Some(guard_flags::CF_INSTRUMENTED));
        assert!(!pe.features.control_flow_guard);
    }

    const READ_ONLY_DATA: u32 = 0x4000_0040;

    #[test]
    fn owned_image_noop_is_byte_exact() {
        let original = minimal_pe64(0x200);
        let image = PeImage::from_bytes(original.clone()).expect("image is valid");

        assert_eq!(image.bytes(), original);
        assert_eq!(image.into_bytes(), original);
    }

    #[test]
    fn rejects_invalid_section_names() {
        for name in ["", "123456789", "bad\0name"] {
            let original = minimal_pe64(0x200);
            let mut image = PeImage::from_bytes(original).expect("image is valid");
            assert!(matches!(
                image.add_section(NewSection {
                    name,
                    data: &[1],
                    characteristics: READ_ONLY_DATA,
                }),
                Err(PeError::InvalidSectionName { .. })
            ));
        }
    }

    #[test]
    fn rejects_empty_section() {
        let original = minimal_pe64(0x200);
        let mut image = PeImage::from_bytes(original).expect("image is valid");
        assert!(matches!(
            image.add_section(NewSection {
                name: ".empty",
                data: &[],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::EmptySection)
        ));
    }

    #[test]
    fn owned_image_rejects_zero_file_alignment_at_construction() {
        let mut original = minimal_pe64(0x200);
        put_u32(&mut original, 0x58 + 36, 0);

        assert!(matches!(
            PeImage::from_bytes(original),
            Err(PeError::InvalidAlignment {
                field: "FileAlignment",
                value: 0,
            })
        ));
    }

    #[test]
    fn adds_aligned_data_section_and_reparses() {
        let original = minimal_pe64(0x200);
        let mut image = PeImage::from_bytes(original).expect("image is valid");
        image
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1, 2, 3],
                characteristics: READ_ONLY_DATA,
            })
            .expect("section insertion must succeed");

        let output = image.bytes();
        let reparsed = PeFile::parse(output).expect("writer output must reparse");
        assert_eq!(reparsed.sections.len(), 2);
        assert_eq!(reparsed.coff.number_of_sections, 2);
        assert_eq!(reparsed.optional.size_of_image, 0x3000);
        assert_ne!(reparsed.optional.checksum, 0);

        let section = &reparsed.sections[1];
        assert_eq!(section.name, ".vmpdat");
        assert_eq!(section.virtual_address, Rva(0x2000));
        assert_eq!(section.virtual_size, 3);
        assert_eq!(section.pointer_to_raw_data, FileOffset(0x400));
        assert_eq!(section.size_of_raw_data, 0x200);
        assert_eq!(&output[0x400..0x403], &[1, 2, 3]);
        assert!(output[0x403..0x600].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn candidate_verification_catches_layout_drift() {
        let original = minimal_pe64(0x200);
        let before = PeFile::parse(&original).expect("image is valid");
        let request = NewSection {
            name: ".vmpdat",
            data: &[1, 2, 3],
            characteristics: READ_ONLY_DATA,
        };
        let (candidate, expected) =
            writer::build_with_section(&original, &before, request, &[], Default::default())
                .expect("candidate builds");
        let mut parsed = PeFile::parse(&candidate).expect("candidate parses");
        parsed
            .sections
            .last_mut()
            .expect("new section exists")
            .virtual_address = Rva(0xdead);

        assert!(matches!(
            writer::verify_candidate(&original, &candidate, &before, &parsed, &expected),
            Err(PeError::CandidateVerificationFailed {
                reason: "new section RVA differs from the layout plan"
            })
        ));
    }

    #[test]
    fn candidate_verification_catches_existing_header_changes() {
        let original = minimal_pe64(0x200);
        let before = PeFile::parse(&original).expect("image is valid");
        let request = NewSection {
            name: ".vmpdat",
            data: &[1],
            characteristics: READ_ONLY_DATA,
        };
        let (mut candidate, expected) =
            writer::build_with_section(&original, &before, request, &[], Default::default())
                .expect("candidate builds");
        candidate[0x148] = b'!';
        let parsed = PeFile::parse(&candidate).expect("changed section name still parses");

        assert!(matches!(
            writer::verify_candidate(&original, &candidate, &before, &parsed, &expected),
            Err(PeError::CandidateVerificationFailed {
                reason: "an existing section header changed"
            })
        ));
    }

    #[test]
    fn supports_two_sequential_section_insertions() {
        let original = minimal_pe64(0x200);
        let mut image = PeImage::from_bytes(original).expect("image is valid");
        for (name, byte) in [(".one", 1), (".two", 2)] {
            image
                .add_section(NewSection {
                    name,
                    data: &[byte],
                    characteristics: READ_ONLY_DATA,
                })
                .expect("each insertion succeeds");
        }

        assert_eq!(image.pe().coff.number_of_sections, 3);
        assert_eq!(image.pe().sections[1].name, ".one");
        assert_eq!(image.pe().sections[2].name, ".two");
    }

    #[test]
    fn rejects_size_of_image_mismatch() {
        let mut original = minimal_pe64(0x200);
        put_u32(&mut original, 0x58 + 56, 0x3000);
        let mut image = PeImage::from_bytes(original).expect("image is inspectable");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "SizeOfImage does not match the existing section layout"
            })
        ));
    }

    #[test]
    fn size_of_image_uses_virtual_size_not_larger_raw_size() {
        let mut original = minimal_pe64(0x200);
        put_u32(&mut original, 0x148 + 8, 0x100); // VirtualSize
        put_u32(&mut original, 0x148 + 16, 0x1200); // SizeOfRawData
        original.resize(0x1400, 0);

        let mut image = PeImage::from_bytes(original).expect("image is valid");
        image
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            })
            .expect("linker-style SizeOfImage must be accepted");

        let reparsed = PeFile::parse(image.bytes()).expect("writer output must reparse");
        assert_eq!(reparsed.sections[1].virtual_address, Rva(0x2000));
        assert_eq!(reparsed.optional.size_of_image, 0x3000);
    }

    #[test]
    fn zero_virtual_size_section_is_mapped_as_raw_size() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x148 + 8, 0); // .text VirtualSize
        add_second_section(&mut data, 0x1000, 0x100, 0x400, 0x200);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::OverlappingSections { space: "RVA", .. })
        ));
    }

    #[test]
    fn writer_accounts_for_zero_virtual_size_section() {
        let mut original = minimal_pe64(0x200);
        put_u32(&mut original, 0x148 + 8, 0); // .text VirtualSize

        let mut image = PeImage::from_bytes(original).expect("image is valid");
        image
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            })
            .expect("SizeOfRawData supplies the effective virtual size");

        let section = image.pe().sections.last().expect("new section exists");
        assert_eq!(section.virtual_address, Rva(0x2000));
    }

    #[test]
    fn rejects_low_alignment_image() {
        let mut original = minimal_pe64(0x200);
        put_u32(&mut original, 0x58 + 32, 0x200); // SectionAlignment
        put_u32(&mut original, 0x58 + 36, 0x200); // FileAlignment
        put_u32(&mut original, 0x58 + 56, 0x600); // SizeOfImage
        put_u32(&mut original, 0x148 + 8, 0x300); // .text VirtualSize
        put_u32(&mut original, 0x148 + 12, 0x200); // .text VirtualAddress == raw offset

        let mut image = PeImage::from_bytes(original).expect("low-alignment input is parseable");
        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "low-alignment images are mapped 1:1 and are not supported"
            })
        ));
    }

    #[test]
    fn rejects_section_count_above_loader_limit() {
        let original = minimal_pe64_with_bss_sections(96);
        let mut image = PeImage::from_bytes(original).expect("96-section image is valid");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::TooManySections)
        ));
    }

    #[test]
    fn zero_raw_section_ignores_stale_pointer_when_finding_file_end() {
        let mut original = minimal_pe64(0x200);
        add_second_section(&mut original, 0x2000, 0x1000, 0x1000, 0);
        original.truncate(0x400);
        put_u32(&mut original, 0x58 + 56, 0x3000); // SizeOfImage
        put_u32(&mut original, 0x148 + 40 + 36, 0xc000_0080); // BSS

        let mut image = PeImage::from_bytes(original).expect("BSS image is valid");
        image
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            })
            .expect("zero-sized raw range must not extend the physical file");

        let reparsed = PeFile::parse(image.bytes()).expect("writer output must reparse");
        assert_eq!(reparsed.sections[2].pointer_to_raw_data, FileOffset(0x400));
        assert_eq!(reparsed.sections[2].virtual_address, Rva(0x3000));
    }

    #[test]
    fn section_insertion_is_atomic_on_failure() {
        let mut original = minimal_pe64(0x200);
        original.push(0xaa); // overlay
        let mut image = PeImage::from_bytes(original.clone()).expect("image is valid");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::OverlayPresent { .. })
        ));
        assert_eq!(image.bytes(), original);
    }

    #[test]
    fn rejects_missing_or_nonzero_section_header_slot() {
        let mut no_space = minimal_pe64(0x170);
        let mut image = PeImage::from_bytes(no_space.clone()).expect("image is valid");
        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::NoSectionHeaderSpace { .. })
        ));

        no_space = minimal_pe64(0x200);
        no_space[0x170] = 1;
        let mut image = PeImage::from_bytes(no_space).expect("image is valid");
        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::SectionHeaderSlotNotEmpty { .. })
        ));
    }

    #[test]
    fn rejects_slot_overlapping_bound_import_directory() {
        let mut data = minimal_pe64(0x200);
        let directories = 0x58 + 112;
        put_u32(&mut data, directories + directory::BOUND_IMPORT * 8, 0x170);
        put_u32(&mut data, directories + directory::BOUND_IMPORT * 8 + 4, 40);
        let mut image = PeImage::from_bytes(data).expect("directory is structurally mapped");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::HeaderDirectoryOverlapsSlot {
                directory: directory::BOUND_IMPORT,
                offset: 0x170,
            })
        ));
    }

    #[test]
    fn rejects_slot_overlapping_in_header_debug_directory() {
        let mut data = minimal_pe64(0x200);
        let directories = 0x58 + 112;
        put_u32(&mut data, directories + directory::DEBUG * 8, 0x170);
        put_u32(&mut data, directories + directory::DEBUG * 8 + 4, 40);
        let mut image = PeImage::from_bytes(data).expect("directory is structurally mapped");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::HeaderDirectoryOverlapsSlot {
                directory: directory::DEBUG,
                offset: 0x170,
            })
        ));
    }

    #[test]
    fn rejects_certificate_table_before_overlay_policy() {
        let mut data = minimal_pe64(0x200);
        data.resize(0x408, 0);
        let dirs = 0x58 + 112;
        put_u32(&mut data, dirs + directory::SECURITY * 8, 0x400);
        put_u32(&mut data, dirs + directory::SECURITY * 8 + 4, 8);
        let mut image = PeImage::from_bytes(data).expect("image is structurally valid");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            }),
            Err(PeError::CertificateTablePresent)
        ));
    }

    #[test]
    fn cfg_blocks_executable_but_not_data_section() {
        let mut data = minimal_pe64(0x200);
        put_u16(&mut data, 0x58 + 70, dll_characteristics::GUARD_CF);

        let mut executable = PeImage::from_bytes(data.clone()).expect("image is valid");
        assert!(matches!(
            executable.add_section(NewSection {
                name: ".vmpx",
                data: &[0xc3],
                characteristics: 0x6000_0020,
            }),
            Err(PeError::ControlFlowGuardUnsupported)
        ));

        let mut data_only = PeImage::from_bytes(data).expect("image is valid");
        data_only
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: READ_ONLY_DATA,
            })
            .expect("CFG does not constrain non-executable data");
    }

    #[test]
    fn rejects_mixed_section_content_type_flags() {
        let data = minimal_pe64(0x200);
        let mut image = PeImage::from_bytes(data).expect("image is valid");

        assert!(matches!(
            image.add_section(NewSection {
                name: ".mixed",
                data: &[1],
                characteristics: 0x6000_0060, // CODE | INITIALIZED_DATA | EXECUTE | READ
            }),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
    }
}
