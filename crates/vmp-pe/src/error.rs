//! Typed PE parsing errors.
//!
//! Any malformed input must return one of these errors rather than panicking,
//! reading out of bounds, or looping forever.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeError {
    /// A read would cross the end of the buffer.
    #[error("input truncated: need {needed} byte(s) at offset {offset:#x}, but only {available} available")]
    Truncated {
        offset: u64,
        needed: u64,
        available: u64,
    },

    /// The `MZ` signature is missing.
    #[error("bad DOS signature: expected 'MZ' (0x5a4d), found {found:#06x}")]
    BadDosSignature { found: u16 },

    /// `e_lfanew` points past the end of the file or at unaligned garbage.
    #[error("bad PE signature at offset {offset:#x}: found {found:#010x}, expected 'PE\\0\\0'")]
    BadPeSignature { offset: u64, found: u32 },

    /// The optional header magic is neither PE32 nor PE32+.
    #[error("unsupported optional header magic {magic:#06x} (expected 0x10b PE32 or 0x20b PE32+)")]
    UnsupportedOptionalMagic { magic: u16 },

    /// The COFF `Machine` is not in the supported set.
    #[error("unsupported machine {machine:#06x} (only x86 0x14c and x64 0x8664 are supported)")]
    UnsupportedMachine { machine: u16 },

    /// The COFF machine type and optional-header format declare different
    /// image bitnesses.
    #[error("machine {machine:#06x} is inconsistent with optional header magic {magic:#06x}")]
    MachineOptionalHeaderMismatch { machine: u16, magic: u16 },

    /// `SizeOfOptionalHeader` is too small for the declared magic.
    #[error("optional header too small: {size} byte(s) cannot hold a {magic:#06x} header")]
    OptionalHeaderTooSmall { size: u16, magic: u16 },

    /// `SizeOfHeaders` claims more bytes than the file contains, so header
    /// The declared header region is larger than the physical file.
    #[error("SizeOfHeaders {size_of_headers:#x} exceeds file size {file_size:#x}")]
    HeadersExceedFile {
        size_of_headers: u32,
        file_size: u64,
    },

    /// The current section table is not contained in the declared headers.
    #[error("section table ends at {table_end:#x}, beyond SizeOfHeaders {size_of_headers:#x}")]
    SectionTableExceedsHeaders {
        table_end: u64,
        size_of_headers: u32,
    },

    /// A section's physical bytes claim part of the PE header region.
    #[error(
        "section {index} raw range [{start:#x}, {end:#x}) overlaps headers ending at {headers_end:#x}"
    )]
    SectionRawDataOverlapsHeaders {
        index: usize,
        start: u64,
        end: u64,
        headers_end: u64,
    },

    /// The declared data directories would extend past `SizeOfOptionalHeader`
    /// into the section table
    #[error("{count} data directories do not fit in the {size}-byte optional header")]
    DirectoriesExceedOptionalHeader { count: u32, size: u16 },

    /// A section's declared raw bytes extend beyond the physical file.
    #[error("section {index} raw range [{start:#x}, {end:#x}) exceeds file size {file_size:#x}")]
    SectionRawDataOutOfBounds {
        index: usize,
        start: u64,
        end: u64,
        file_size: u64,
    },

    /// Two sections overlap in file-offset or RVA space, making mapping
    /// dependent on section-table order.
    #[error("sections {first} and {second} overlap in {space} space")]
    OverlappingSections {
        space: &'static str,
        first: usize,
        second: usize,
    },

    /// A section claims RVA space reserved for the image headers.
    #[error(
        "section {index} virtual range [{start:#x}, {end:#x}) overlaps headers ending at {headers_end:#x}"
    )]
    SectionOverlapsHeaders {
        index: usize,
        start: u64,
        end: u64,
        headers_end: u64,
    },

    /// A section claims RVA space beyond the declared image size.
    #[error(
        "section {index} virtual range [{start:#x}, {end:#x}) exceeds SizeOfImage {size_of_image:#x}"
    )]
    SectionExceedsImage {
        index: usize,
        start: u64,
        end: u64,
        size_of_image: u64,
    },

    /// A present load-config directory is structurally unreadable.
    #[error("malformed load-config directory: {reason}")]
    MalformedLoadConfig { reason: &'static str },

    /// The optional embedded COFF symbol table is structurally unreadable.
    #[error("malformed COFF symbol table: {reason}")]
    MalformedCoffSymbolTable { reason: &'static str },

    /// The certificate table uses inconsistent or out-of-file metadata.
    #[error("malformed security directory: {reason}")]
    MalformedSecurityDirectory { reason: &'static str },

    /// A requested section name cannot be represented by an image section
    /// header (non-empty, at most eight bytes, without embedded NULs).
    #[error("invalid PE section name: {reason}")]
    InvalidSectionName { reason: &'static str },

    /// The writer only emits initialized sections with at least one byte.
    #[error("a new section must contain at least one byte")]
    EmptySection,

    /// An alignment field is zero or not a power of two, so no layout
    /// arithmetic derived from it is meaningful.
    #[error("unsupported {field} value {value:#x}")]
    InvalidAlignment { field: &'static str, value: u32 },

    /// The two alignments are individually well-formed but their combination is
    /// not a profile the Windows loader maps predictably.
    #[error(
        "incompatible alignments: SectionAlignment {section_alignment:#x} with FileAlignment {file_alignment:#x} ({reason})"
    )]
    IncompatibleAlignments {
        section_alignment: u32,
        file_alignment: u32,
        reason: &'static str,
    },

    /// An optional-header layout field is not a multiple of the alignment that
    /// governs it.
    #[error("{field} {value:#x} is not a multiple of {alignment:#x}")]
    Misaligned {
        field: &'static str,
        value: u64,
        alignment: u32,
    },

    /// A section header field is not a multiple of the alignment that governs
    /// it, so the loader's mapping would not match the declared layout.
    #[error("section {index} {field} {value:#x} is not a multiple of {alignment:#x}")]
    MisalignedSection {
        index: usize,
        field: &'static str,
        value: u64,
        alignment: u32,
    },

    /// No complete 40-byte section-table entry is available in the headers.
    #[error(
        "no room for another section header: entry ends at {required_end:#x}, limit is {limit:#x}"
    )]
    NoSectionHeaderSpace { required_end: u64, limit: u64 },

    /// The nominally free section-table slot contains unknown bytes.
    #[error("candidate section-header slot at {offset:#x} is not empty")]
    SectionHeaderSlotNotEmpty { offset: u64 },

    /// A present loader data directory owns bytes in the candidate section
    /// header slot.
    #[error("data directory {directory} overlaps candidate section-header slot at {offset:#x}")]
    HeaderDirectoryOverlapsSlot { directory: usize, offset: u64 },

    /// Trailing data has no explicit preservation policy in the append-only
    /// writer yet.
    #[error("overlay starts at {offset:#x} and contains {size} byte(s)")]
    OverlayPresent { offset: u64, size: u64 },

    /// Rewriting an Authenticode-signed image invalidates its certificate.
    #[error("certificate table is present; strip/re-sign policy is not implemented")]
    CertificateTablePresent,

    /// New executable targets require updating CFG metadata.
    #[error("cannot add executable code to a Control Flow Guard image")]
    ControlFlowGuardUnsupported,

    /// The result would exceed the Windows loader's 96-section limit.
    #[error("the Windows loader supports at most 96 image sections")]
    TooManySections,

    /// The parsed image is valid enough to inspect, but not in the narrower
    /// profile accepted by the writer.
    #[error("unsupported image layout for rewriting: {reason}")]
    UnsupportedRewriteLayout { reason: &'static str },

    /// The serialized candidate parsed successfully but disagrees with the
    /// layout that the writer planned.
    #[error("candidate verification failed: {reason}")]
    CandidateVerificationFailed { reason: &'static str },

    /// The RVA is covered neither by the headers nor by any section.
    #[error("unmapped RVA {rva:#x}: not contained in headers or any section")]
    UnmappedRva { rva: u64 },

    /// A present data directory cannot be read as the structure its index
    /// declares.
    #[error("malformed data directory {directory}: {reason}")]
    MalformedDirectory {
        directory: usize,
        reason: &'static str,
    },

    /// A NUL-terminated string runs past the end of the raw data holding it.
    #[error("unterminated string at RVA {rva:#x}")]
    UnterminatedString { rva: u64 },

    /// A base relocation uses a type the crate cannot re-emit.
    #[error("unsupported base relocation type {kind} in the page at {page:#x}")]
    UnsupportedFixupKind { kind: u16, page: u64 },

    /// Two base relocations claim the same address, so the loader would apply
    /// the relocation delta twice or apply contradictory widths.
    #[error("conflicting base relocation at RVA {rva:#x}")]
    ConflictingFixup { rva: u64 },

    /// A new runtime function would overlap one already in the table, which
    /// would make the unwinder's binary search ambiguous.
    #[error("runtime function starting at {begin:#x} overlaps an existing entry")]
    OverlappingRuntimeFunction { begin: u64 },

    /// Arithmetic overflow while computing the file layout.
    #[error("layout overflow while computing {field}")]
    Overflow { field: &'static str },
}

impl PeError {
    /// The directory-scoped malformed error every directory parser reports.
    ///
    /// Each parser wraps this in a module-level `malformed` that binds its own
    /// directory index, so a call site names only the reason.
    pub(crate) const fn malformed(directory: usize, reason: &'static str) -> PeError {
        PeError::MalformedDirectory { directory, reason }
    }

    /// Narrows a container length to the `u32` a PE header field holds.
    ///
    /// Every serializer needs this on the way back out to a header, and the
    /// only way it can fail is a payload larger than 4 GiB.
    pub(crate) fn u32_len(len: usize, field: &'static str) -> Result<u32, PeError> {
        u32::try_from(len).map_err(|_| PeError::Overflow { field })
    }
}
