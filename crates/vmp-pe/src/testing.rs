//! Synthetic PE builders shared by the unit tests of every module.
//!
//! The images are the smallest well-formed inputs the parser accepts, so a test
//! can corrupt exactly one field and attribute the resulting error to it.

use vmp_types::Architecture;

use crate::{DOS_MAGIC, OPT_MAGIC_PE32, OPT_MAGIC_PE32PLUS, PE_SIGNATURE};

/// Offset of the section table in both synthetic PE32+ images below.
pub(crate) const PE64_SECTION_TABLE: usize = 0x148;
/// Offset of the section table in the synthetic PE32 image.
pub(crate) const PE32_SECTION_TABLE: usize = 0x138;
/// Offset of the optional header in both synthetic images.
pub(crate) const OPTIONAL_HEADER: usize = 0x58;

pub(crate) fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Offset of the data directory array, chosen by the optional header magic.
pub(crate) fn directories_offset(data: &[u8]) -> usize {
    let magic = u16::from_le_bytes([data[OPTIONAL_HEADER], data[OPTIONAL_HEADER + 1]]);
    OPTIONAL_HEADER + crate::optional_header_fixed_size(magic) as usize
}

/// Points one data directory entry at `rva` with `size` bytes.
pub(crate) fn set_directory(data: &mut [u8], index: usize, rva: u32, size: u32) {
    let base = directories_offset(data) + index * 8;
    put_u32(data, base, rva);
    put_u32(data, base + 4, size);
}

/// Builds a minimal well-formed PE32+ image with a single `.text` section whose
/// raw data starts at 0x200; only `size_of_headers` is a parameter so tests can
/// corrupt it.
pub(crate) fn minimal_pe64(size_of_headers: u32) -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    put_u16(&mut d, 0, DOS_MAGIC);
    put_u32(&mut d, 0x3c, 0x40); // e_lfanew
    put_u32(&mut d, 0x40, PE_SIGNATURE);
    // COFF file header at 0x44
    put_u16(&mut d, 0x44, Architecture::MACHINE_AMD64);
    put_u16(&mut d, 0x46, 1); // NumberOfSections
    put_u16(&mut d, 0x54, 240); // SizeOfOptionalHeader = 112 + 16 * 8

    // Optional header at 0x58
    put_u16(&mut d, 0x58, OPT_MAGIC_PE32PLUS);
    put_u32(&mut d, 0x58 + 16, 0x1000); // AddressOfEntryPoint
    put_u64(&mut d, 0x58 + 24, 0x1_4000_0000); // ImageBase
    put_u32(&mut d, 0x58 + 32, 0x1000); // SectionAlignment
    put_u32(&mut d, 0x58 + 36, 0x200); // FileAlignment
    put_u32(&mut d, 0x58 + 56, 0x2000); // SizeOfImage
    put_u32(&mut d, 0x58 + 60, size_of_headers);
    put_u16(&mut d, 0x58 + 68, 3); // Subsystem: console
    put_u32(&mut d, 0x58 + 108, 16); // NumberOfRvaAndSizes

    // Section table entry at 0x58 + 240
    let s = PE64_SECTION_TABLE;
    d[s..s + 5].copy_from_slice(b".text");
    put_u32(&mut d, s + 8, 0x200); // VirtualSize
    put_u32(&mut d, s + 12, 0x1000); // VirtualAddress
    put_u32(&mut d, s + 16, 0x200); // SizeOfRawData
    put_u32(&mut d, s + 20, 0x200); // PointerToRawData
    put_u32(&mut d, s + 36, 0x6000_0020); // CODE | EXECUTE | READ
    d
}

/// Builds the PE32 counterpart of [`minimal_pe64`].
pub(crate) fn minimal_pe32(size_of_headers: u32) -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    put_u16(&mut d, 0, DOS_MAGIC);
    put_u32(&mut d, 0x3c, 0x40); // e_lfanew
    put_u32(&mut d, 0x40, PE_SIGNATURE);
    // COFF file header at 0x44
    put_u16(&mut d, 0x44, Architecture::MACHINE_I386);
    put_u16(&mut d, 0x46, 1); // NumberOfSections
    put_u16(&mut d, 0x54, 224); // SizeOfOptionalHeader = 96 + 16 * 8

    // Optional header at 0x58
    put_u16(&mut d, 0x58, OPT_MAGIC_PE32);
    put_u32(&mut d, 0x58 + 16, 0x1000); // AddressOfEntryPoint
    put_u32(&mut d, 0x58 + 28, 0x0040_0000); // ImageBase
    put_u32(&mut d, 0x58 + 32, 0x1000); // SectionAlignment
    put_u32(&mut d, 0x58 + 36, 0x200); // FileAlignment
    put_u32(&mut d, 0x58 + 56, 0x2000); // SizeOfImage
    put_u32(&mut d, 0x58 + 60, size_of_headers);
    put_u16(&mut d, 0x58 + 68, 3); // Subsystem: console
    put_u32(&mut d, 0x58 + 92, 16); // NumberOfRvaAndSizes

    // Section table entry at 0x58 + 224
    let s = PE32_SECTION_TABLE;
    d[s..s + 5].copy_from_slice(b".text");
    put_u32(&mut d, s + 8, 0x200); // VirtualSize
    put_u32(&mut d, s + 12, 0x1000); // VirtualAddress
    put_u32(&mut d, s + 16, 0x200); // SizeOfRawData
    put_u32(&mut d, s + 20, 0x200); // PointerToRawData
    put_u32(&mut d, s + 36, 0x6000_0020); // CODE | EXECUTE | READ
    d
}

/// Appends a second `.data` section header to a [`minimal_pe64`] image.
pub(crate) fn add_second_section(
    data: &mut Vec<u8>,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
) {
    data.resize(data.len().max((raw_offset + raw_size) as usize), 0);
    put_u16(data, 0x46, 2);
    let s = PE64_SECTION_TABLE + 40;
    data[s..s + 5].copy_from_slice(b".data");
    put_u32(data, s + 8, virtual_size);
    put_u32(data, s + 12, virtual_address);
    put_u32(data, s + 16, raw_size);
    put_u32(data, s + 20, raw_offset);
    put_u32(data, s + 36, 0xc000_0040); // INITIALIZED_DATA | READ | WRITE
}

/// Builds a PE32+ image whose section table is filled with `count` BSS sections.
pub(crate) fn minimal_pe64_with_bss_sections(count: u16) -> Vec<u8> {
    let mut data = minimal_pe64(0x2000);
    data.resize(0x2000, 0);
    put_u16(&mut data, 0x46, count);
    put_u32(&mut data, 0x58 + 56, 0x2000 + u32::from(count) * 0x1000);

    for index in 0..usize::from(count) {
        let section = PE64_SECTION_TABLE + index * 40;
        data[section..section + 40].fill(0);
        data[section..section + 4].copy_from_slice(b".bss");
        put_u32(&mut data, section + 8, 0x1000); // VirtualSize
        put_u32(&mut data, section + 12, 0x2000 + (index as u32) * 0x1000);
        put_u32(&mut data, section + 36, 0xc000_0080); // BSS | READ | WRITE
    }
    data
}

/// RVA the payload section of every synthetic image is mapped at.
pub(crate) const PAYLOAD_RVA: u32 = 0x2000;
/// File offset the payload section's raw data starts at.
pub(crate) const PAYLOAD_RAW: usize = 0x400;

/// Grows a [`minimal_pe64`] image with a second, file-backed `.rdata` section
/// that directory payloads can live in.
///
/// Returns the RVA of the new section, whose raw data starts at
/// [`PAYLOAD_RAW`] and is `size` bytes long, rounded up to the file alignment.
pub(crate) fn add_payload_section(data: &mut Vec<u8>, size: u32) -> u32 {
    let raw_size = size.next_multiple_of(0x200).max(0x200);
    add_second_section(data, PAYLOAD_RVA, size.max(1), PAYLOAD_RAW as u32, raw_size);
    let s = PE64_SECTION_TABLE + 40;
    data[s..s + 6].copy_from_slice(b".rdata");
    put_u32(data, s + 36, 0x4000_0040); // INITIALIZED_DATA | READ
    put_u32(data, 0x58 + 56, 0x3000); // SizeOfImage
    PAYLOAD_RVA
}

/// PE32 counterpart of [`add_payload_section`], which targets PE32+ only.
pub(crate) fn add_payload_section_pe32(data: &mut Vec<u8>) -> u32 {
    let raw_size = 0x200u32;
    data.resize(PAYLOAD_RAW + raw_size as usize, 0);
    put_u16(data, 0x46, 2); // NumberOfSections
    let s = PE32_SECTION_TABLE + 40;
    data[s..s + 6].copy_from_slice(b".rdata");
    put_u32(data, s + 8, raw_size); // VirtualSize
    put_u32(data, s + 12, PAYLOAD_RVA); // VirtualAddress
    put_u32(data, s + 16, raw_size); // SizeOfRawData
    put_u32(data, s + 20, PAYLOAD_RAW as u32); // PointerToRawData
    put_u32(data, s + 36, 0x4000_0040); // INITIALIZED_DATA | READ
    put_u32(data, 0x58 + 56, 0x3000); // SizeOfImage
    PAYLOAD_RVA
}

/// File offset backing a payload RVA in an image built by either
/// `add_payload_section` helper.
pub(crate) fn raw_of(rva: u32) -> usize {
    PAYLOAD_RAW + (rva - PAYLOAD_RVA) as usize
}

/// Writes a little-endian `u32` at a payload RVA.
pub(crate) fn put32(data: &mut [u8], rva: u32, value: u32) {
    put_u32(data, raw_of(rva), value);
}

/// Writes a little-endian `u16` at a payload RVA.
pub(crate) fn put16(data: &mut [u8], rva: u32, value: u16) {
    put_u16(data, raw_of(rva), value);
}

/// Writes raw bytes at a payload RVA.
pub(crate) fn put_bytes(data: &mut [u8], rva: u32, bytes: &[u8]) {
    let offset = raw_of(rva);
    data[offset..offset + bytes.len()].copy_from_slice(bytes);
}
