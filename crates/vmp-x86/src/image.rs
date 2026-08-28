//! A read-only view of a parsed image, in the terms the decoder needs.
//!
//! Everything the traversal asks about an address — is it code, what bytes are
//! there, does a relocation cover it, is it an import thunk — is answered here,
//! so the decoder never touches raw PE layout itself.

use vmp_ir::{TargetKind, UnwindRange};
use vmp_pe::{Fixup, PeFile};
use vmp_types::{Architecture, ImageBase, Rva};

/// A parsed PE plus the bytes it was parsed from.
#[derive(Debug, Clone, Copy)]
pub struct Image<'a> {
    pe: &'a PeFile,
    data: &'a [u8],
}

impl<'a> Image<'a> {
    pub fn new(pe: &'a PeFile, data: &'a [u8]) -> Image<'a> {
        Image { pe, data }
    }

    pub fn pe(&self) -> &'a PeFile {
        self.pe
    }

    pub fn architecture(&self) -> Architecture {
        self.pe.architecture
    }

    /// Decoder bitness for this image.
    pub fn bitness(&self) -> u32 {
        match self.pe.architecture {
            Architecture::X86 => 32,
            Architecture::X64 => 64,
        }
    }

    pub fn image_base(&self) -> ImageBase {
        self.pe.optional.image_base
    }

    /// Whether `rva` falls in a section the loader maps as executable.
    pub fn is_executable(&self, rva: Rva) -> bool {
        self.pe
            .section_at(rva)
            .is_some_and(|section| section.permissions.execute)
    }

    pub fn is_mapped(&self, rva: Rva) -> bool {
        self.pe.section_at(rva).is_some() || self.in_headers(rva)
    }

    /// Whether `rva` lands in the header region, which the loader maps
    /// read-only ahead of the first section.
    ///
    /// Real code reads it: the MSVC startup path compares the `MZ` and `PE`
    /// signatures of its own image through a RIP-relative operand.
    fn in_headers(&self, rva: Rva) -> bool {
        rva.get() < self.pe.optional.size_of_headers
    }

    /// Every byte mapped contiguously from `rva` onwards, or `None` when the
    /// address has no file backing.
    pub fn bytes_from(&self, rva: Rva) -> Option<&'a [u8]> {
        self.pe.mapped_from(self.data, rva).ok()
    }

    /// A NUL-terminated byte string whose payload is bounded by `max_len`.
    ///
    /// The returned slice excludes the NUL and borrows the mapped image, so
    /// marker-name recovery cannot allocate in proportion to attacker-controlled
    /// input.
    pub fn c_string_bytes(&self, rva: Rva, max_len: usize) -> Option<&'a [u8]> {
        let bytes = self.bytes_from(rva)?;
        let search_len = max_len.checked_add(1)?;
        let end = bytes.iter().take(search_len).position(|byte| *byte == 0)?;
        (end <= max_len).then_some(&bytes[..end])
    }

    /// A NUL-terminated UTF-8 string whose payload is bounded by `max_len`.
    ///
    /// The returned slice borrows the mapped image, so marker-name recovery
    /// cannot allocate in proportion to attacker-controlled input.
    pub fn utf8_c_string(&self, rva: Rva, max_len: usize) -> Option<&'a str> {
        std::str::from_utf8(self.c_string_bytes(rva, max_len)?).ok()
    }

    /// Classifies what lives at `rva`.
    pub fn classify(&self, rva: Rva) -> TargetKind {
        if self.import_thunk(rva).is_some() {
            return TargetKind::ImportThunk;
        }
        match self.pe.section_at(rva) {
            Some(section) if section.permissions.execute => TargetKind::Code,
            Some(_) => TargetKind::Data,
            // The header region is mapped read-only, so it is data like any
            // other non-executable mapping
            None if self.in_headers(rva) => TargetKind::Data,
            None => TargetKind::Unmapped,
        }
    }

    /// The `.pdata` entry covering `rva`, if the image has an exception
    /// directory that describes it.
    pub fn runtime_function(&self, rva: Rva) -> Option<UnwindRange> {
        self.pe
            .exception_table
            .as_ref()?
            .functions()
            .find(|function| rva >= function.begin && rva < function.end)
            .map(|function| UnwindRange {
                begin: function.begin,
                end: function.end,
                unwind_info: function.unwind_info,
            })
    }

    /// Base relocations that start inside `[rva, rva + len)`.
    ///
    /// Padding entries never reach here: `vmp-pe` drops `IMAGE_REL_BASED_ABSOLUTE`
    /// while parsing, so every fixup in the table patches real bytes.
    pub fn fixups_in(&self, rva: Rva, len: u8) -> Vec<Fixup> {
        let Some(relocations) = self.pe.base_relocations.as_ref() else {
            return Vec::new();
        };
        let Some(end) = rva.checked_add(u32::from(len)) else {
            return Vec::new();
        };
        relocations
            .fixups()
            .iter()
            .copied()
            .filter(|fixup| fixup.rva >= rva && fixup.rva < end)
            .collect()
    }

    /// The imported function whose IAT slot lives at `rva`.
    pub fn import_thunk(&self, rva: Rva) -> Option<(&'a str, ImportName<'a>)> {
        let imports = self.pe.imports.as_ref()?;
        for library in &imports.descriptors {
            for function in &library.functions {
                if function.thunk_rva == rva {
                    return Some((library.name.as_str(), ImportName::from(&function.target)));
                }
            }
        }
        None
    }
}

/// How an imported function is identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportName<'a> {
    Name(&'a str),
    Ordinal(u16),
}

impl<'a> From<&'a vmp_pe::ImportTarget> for ImportName<'a> {
    fn from(target: &'a vmp_pe::ImportTarget) -> ImportName<'a> {
        match target {
            vmp_pe::ImportTarget::Name { name, .. } => ImportName::Name(name.as_str()),
            vmp_pe::ImportTarget::Ordinal(ordinal) => ImportName::Ordinal(*ordinal),
        }
    }
}

impl std::fmt::Display for ImportName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportName::Name(name) => f.write_str(name),
            ImportName::Ordinal(ordinal) => write!(f, "#{ordinal}"),
        }
    }
}
