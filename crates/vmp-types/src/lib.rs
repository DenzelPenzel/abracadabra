//! Shared domain types that are independent of any file format.
//!
//! Addresses and offsets are deliberately distinct types so the compiler
//! refuses to mix `Rva`, `FileOffset` and `VirtualAddress` as plain numbers.

use std::fmt;

/// Relative Virtual Address — an offset from `ImageBase` once loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rva(pub u32);

/// A physical offset inside the on-disk file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileOffset(pub u64);

/// An absolute virtual address in the loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualAddress(pub u64);

/// The image base (`OptionalHeader.ImageBase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageBase(pub u64);

impl Rva {
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Adds an offset to the RVA with overflow checking.
    pub fn checked_add(self, delta: u32) -> Option<Rva> {
        self.0.checked_add(delta).map(Rva)
    }

    /// Converts the RVA to an absolute virtual address relative to the base.
    pub fn to_va(self, base: ImageBase) -> Option<VirtualAddress> {
        base.0.checked_add(u64::from(self.0)).map(VirtualAddress)
    }
}

impl FileOffset {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, delta: u64) -> Option<FileOffset> {
        self.0.checked_add(delta).map(FileOffset)
    }
}

impl VirtualAddress {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl ImageBase {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Rva {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl fmt::Display for FileOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl fmt::Display for ImageBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// The architecture of the image being processed.
///
/// Determined explicitly from the COFF `Machine`, never from the host's
/// `cfg(target_arch)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    X86,
    X64,
}

impl Architecture {
    /// COFF machine for x86 (`IMAGE_FILE_MACHINE_I386`).
    pub const MACHINE_I386: u16 = 0x014c;
    /// COFF machine for x64 (`IMAGE_FILE_MACHINE_AMD64`).
    pub const MACHINE_AMD64: u16 = 0x8664;

    /// Recognises a supported architecture from the COFF `Machine`.
    ///
    /// Unknown values return `None`: the caller must treat that as fail-closed
    /// rather than substituting the host architecture.
    pub fn from_machine(machine: u16) -> Option<Architecture> {
        match machine {
            Self::MACHINE_I386 => Some(Architecture::X86),
            Self::MACHINE_AMD64 => Some(Architecture::X64),
            _ => None,
        }
    }

    /// Pointer width in bytes.
    pub const fn pointer_width(self) -> u8 {
        match self {
            Architecture::X86 => 4,
            Architecture::X64 => 8,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Section access rights derived from `SectionHeader.Characteristics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SectionPermissions {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    pub const fn from_characteristics(characteristics: u32) -> SectionPermissions {
        SectionPermissions {
            read: characteristics & Self::IMAGE_SCN_MEM_READ != 0,
            write: characteristics & Self::IMAGE_SCN_MEM_WRITE != 0,
            execute: characteristics & Self::IMAGE_SCN_MEM_EXECUTE != 0,
        }
    }

    /// Compact `r-x` / `rw-` style string.
    pub fn as_rwx(self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { 'w' } else { '-' });
        s.push(if self.execute { 'x' } else { '-' });
        s
    }
}

/// Function protection mode. In Stage 1 it is used only as an enum; the
/// compiler arrives later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionMode {
    Mutation,
    Virtualization,
}

impl ProtectionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProtectionMode::Mutation => "mutation",
            ProtectionMode::Virtualization => "virtualization",
        }
    }
}

impl fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rva_to_va_uses_base() {
        let rva = Rva(0x1000);
        let va = rva.to_va(ImageBase(0x1_4000_0000)).expect("no overflow");
        assert_eq!(va, VirtualAddress(0x1_4000_1000));
    }

    #[test]
    fn rva_to_va_detects_overflow() {
        let rva = Rva(0x10);
        assert_eq!(rva.to_va(ImageBase(u64::MAX)), None);
    }

    #[test]
    fn architecture_from_machine() {
        assert_eq!(Architecture::from_machine(0x8664), Some(Architecture::X64));
        assert_eq!(Architecture::from_machine(0x014c), Some(Architecture::X86));
        assert_eq!(Architecture::from_machine(0x01c0), None);
        assert_eq!(Architecture::X64.pointer_width(), 8);
    }

    #[test]
    fn permissions_decode_rwx() {
        // MEM_READ | MEM_EXECUTE
        let perms = SectionPermissions::from_characteristics(0x4000_0000 | 0x2000_0000);
        assert_eq!(perms.as_rwx(), "r-x");
        assert!(perms.read && perms.execute && !perms.write);
    }
}
