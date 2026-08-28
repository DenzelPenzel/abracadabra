//! Export directory (`IMAGE_EXPORT_DIRECTORY`).
//!
//! The directory is three parallel arrays: `AddressOfFunctions` maps each
//! ordinal slot to a target RVA, while `AddressOfNames` and
//! `AddressOfNameOrdinals` together attach names to a subset of those slots. The
//! model flattens them into one entry per exported ordinal, carrying the
//! optional name and the resolved target.
//!
//! An ordinal is `Base + slot_index`. A zero function slot is a hole in the
//! ordinal space and is skipped, exactly as the loader ignores it. A target RVA
//! that lands inside the export directory's own range is not code but a
//! forwarder string (`"OTHERDLL.Symbol"`), matching the original C++
//! `PEExportList::ReadFromFile`.
//!
//! All three arrays are bounded against mapped data before they are walked, so a
//! hostile `NumberOfFunctions` or `NumberOfNames` yields a typed error rather
//! than an out-of-bounds read or an unbounded loop.

use std::collections::HashMap;

use crate::reader::{le_u16, le_u32};
use crate::{directory, PeError, PeFile};
use vmp_types::Rva;

/// Bytes in the fixed `IMAGE_EXPORT_DIRECTORY` header.
const DIRECTORY_SIZE: u32 = 40;

/// What an exported ordinal resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// A target RVA inside the image.
    Code(Rva),
    /// A `"Module.Symbol"` string re-exporting from another library.
    Forwarder(String),
}

/// One exported ordinal, with its name when one is bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target: ExportTarget,
}

/// The parsed export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exports {
    /// The exporting module's own name, or empty when the directory omits it.
    pub name: String,
    /// The ordinal `Base`; the first function slot is this ordinal.
    pub ordinal_base: u32,
    pub entries: Vec<ExportEntry>,
}

impl Exports {
    /// Parses the export directory, or returns `None` when the image declares
    /// none.
    pub fn parse(pe: &PeFile, data: &[u8]) -> Result<Option<Exports>, PeError> {
        let Some(entry) = pe.data_directory(directory::EXPORT) else {
            return Ok(None);
        };
        if !entry.is_present() {
            return Ok(None);
        }
        let directory_rva = entry.address.rva().ok_or(malformed(
            "export directory entry is a file offset, not an RVA",
        ))?;
        Self::parse_at(pe, data, directory_rva, entry.size).map(Some)
    }

    fn parse_at(
        pe: &PeFile,
        data: &[u8],
        directory_rva: Rva,
        directory_size: u32,
    ) -> Result<Exports, PeError> {
        let header = pe
            .mapped_range(data, directory_rva, DIRECTORY_SIZE)
            .map_err(|_| malformed("export directory header is not backed by mapped data"))?;

        let name_rva = le_u32(header, 12);
        let ordinal_base = le_u32(header, 16);
        let number_of_functions = le_u32(header, 20);
        let number_of_names = le_u32(header, 24);
        let address_of_functions = le_u32(header, 28);
        let address_of_names = le_u32(header, 32);
        let address_of_name_ordinals = le_u32(header, 36);

        let name = if name_rva != 0 {
            pe.mapped_string(data, Rva(name_rva))?
        } else {
            String::new()
        };

        let names = read_name_map(
            pe,
            data,
            ordinal_base,
            number_of_names,
            address_of_names,
            address_of_name_ordinals,
        )?;

        // The forwarder range is the directory's own [rva, rva + size) window.
        let directory_end = directory_rva
            .get()
            .checked_add(directory_size)
            .ok_or(malformed("export directory range overflows"))?;

        let entries = read_entries(
            pe,
            data,
            ordinal_base,
            number_of_functions,
            address_of_functions,
            directory_rva.get(),
            directory_end,
            &names,
        )?;

        Ok(Exports {
            name,
            ordinal_base,
            entries,
        })
    }
}

/// Correlates `AddressOfNames` with `AddressOfNameOrdinals` into an
/// ordinal-to-name-RVA map. When two names claim one ordinal the first wins
fn read_name_map(
    pe: &PeFile,
    data: &[u8],
    ordinal_base: u32,
    number_of_names: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
) -> Result<HashMap<u32, u32>, PeError> {
    let mut names = HashMap::new();
    if number_of_names == 0 {
        return Ok(names);
    }
    if address_of_names == 0 || address_of_name_ordinals == 0 {
        return Err(malformed(
            "export name table pointer is null but NumberOfNames is non-zero",
        ));
    }

    let name_table = bounded_array(pe, data, address_of_names, number_of_names, 4)
        .map_err(|_| malformed("export name table is not backed by mapped data"))?;

    let ordinal_table = bounded_array(pe, data, address_of_name_ordinals, number_of_names, 2)
        .map_err(|_| malformed("export name-ordinal table is not backed by mapped data"))?;

    for index in 0..number_of_names as usize {
        let name_rva = le_u32(name_table, index * 4);
        let ordinal_index = le_u16(ordinal_table, index * 2);
        let ordinal = ordinal_base
            .checked_add(u32::from(ordinal_index))
            .ok_or(malformed("export ordinal overflows"))?;
        names.entry(ordinal).or_insert(name_rva);
    }

    Ok(names)
}

/// Walks `AddressOfFunctions`, emitting one entry per non-zero slot.
#[allow(clippy::too_many_arguments)]
fn read_entries(
    pe: &PeFile,
    data: &[u8],
    ordinal_base: u32,
    number_of_functions: u32,
    address_of_functions: u32,
    directory_start: u32,
    directory_end: u32,
    names: &HashMap<u32, u32>,
) -> Result<Vec<ExportEntry>, PeError> {
    let mut entries = Vec::new();
    if number_of_functions == 0 {
        return Ok(entries);
    }
    if address_of_functions == 0 {
        return Err(malformed(
            "export address table pointer is null but NumberOfFunctions is non-zero",
        ));
    }

    let table = bounded_array(pe, data, address_of_functions, number_of_functions, 4)
        .map_err(|_| malformed("export address table is not backed by mapped data"))?;

    for index in 0..number_of_functions as usize {
        let target_rva = le_u32(table, index * 4);
        // A zero slot is a hole in the ordinal space, not an export.
        if target_rva == 0 {
            continue;
        }
        let ordinal = ordinal_base
            .checked_add(u32::try_from(index).map_err(|_| malformed("export ordinal overflows"))?)
            .ok_or(malformed("export ordinal overflows"))?;

        let target = if target_rva >= directory_start && target_rva < directory_end {
            ExportTarget::Forwarder(pe.mapped_string(data, Rva(target_rva))?)
        } else {
            ExportTarget::Code(Rva(target_rva))
        };

        let name = match names.get(&ordinal) {
            Some(&name_rva) if name_rva != 0 => Some(pe.mapped_string(data, Rva(name_rva))?),
            _ => None,
        };

        entries.push(ExportEntry {
            ordinal,
            name,
            target,
        });
    }
    Ok(entries)
}

/// Returns exactly `count * element` mapped bytes, rejecting a count whose byte
/// span does not fit the 32-bit address space.
fn bounded_array<'data>(
    pe: &PeFile,
    data: &'data [u8],
    rva: u32,
    count: u32,
    element: u32,
) -> Result<&'data [u8], PeError> {
    let bytes = count
        .checked_mul(element)
        .ok_or(malformed("export array size overflows"))?;
    pe.mapped_range(data, Rva(rva), bytes)
}

/// The export-directory-scoped malformed error.
fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::EXPORT, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        add_payload_section, add_payload_section_pe32, minimal_pe32, minimal_pe64, put16, put32,
        put_bytes, set_directory,
    };

    /// Writes a directory header at 0x2000 pointing at arrays laid out below.
    fn write_export_header(
        data: &mut [u8],
        base: u32,
        number_of_functions: u32,
        number_of_names: u32,
    ) {
        put32(data, 0x2000 + 12, 0x2100); // Name
        put32(data, 0x2000 + 16, base); // Base
        put32(data, 0x2000 + 20, number_of_functions); // NumberOfFunctions
        put32(data, 0x2000 + 24, number_of_names); // NumberOfNames
        put32(data, 0x2000 + 28, 0x2040); // AddressOfFunctions
        put32(data, 0x2000 + 32, 0x2060); // AddressOfNames
        put32(data, 0x2000 + 36, 0x2070); // AddressOfNameOrdinals
        put_bytes(data, 0x2100, b"MYLIB.dll\0");
    }

    #[test]
    fn absent_directory_has_no_model() {
        let data = minimal_pe64(0x200);
        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        assert_eq!(
            Exports::parse(&pe, &data).expect("absent directory is not an error"),
            None
        );
    }

    #[test]
    fn parses_named_ordinal_only_and_hole_slots() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        write_export_header(&mut data, 1, 3, 1);

        // Function slots: code, hole, code.
        put32(&mut data, 0x2040, 0x1000); // ordinal 1 -> code 0x1000
        put32(&mut data, 0x2044, 0); // ordinal 2 -> hole
        put32(&mut data, 0x2048, 0x1100); // ordinal 3 -> code 0x1100

        // One name binding "OnlyExport" to ordinal 1 (Base + nameOrdinal 0).
        put32(&mut data, 0x2060, 0x2080); // AddressOfNames[0]
        put16(&mut data, 0x2070, 0); // AddressOfNameOrdinals[0]
        put_bytes(&mut data, 0x2080, b"OnlyExport\0");

        set_directory(&mut data, directory::EXPORT, rva, 0x40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let exports = Exports::parse(&pe, &data)
            .expect("well-formed exports parse")
            .expect("directory is present");

        assert_eq!(exports.name, "MYLIB.dll");
        assert_eq!(exports.ordinal_base, 1);
        assert_eq!(
            exports.entries,
            [
                ExportEntry {
                    ordinal: 1,
                    name: Some("OnlyExport".to_string()),
                    target: ExportTarget::Code(Rva(0x1000)),
                },
                ExportEntry {
                    // Ordinal 2 was a hole and is absent; ordinal 3 has no name.
                    ordinal: 3,
                    name: None,
                    target: ExportTarget::Code(Rva(0x1100)),
                },
            ]
        );
    }

    #[test]
    fn parses_exports_pe32() {
        let mut data = minimal_pe32(0x200);
        let rva = add_payload_section_pe32(&mut data);
        write_export_header(&mut data, 5, 1, 1);

        put32(&mut data, 0x2040, 0x1000); // ordinal 5 -> code 0x1000
        put32(&mut data, 0x2060, 0x2080); // AddressOfNames[0]
        put16(&mut data, 0x2070, 0); // AddressOfNameOrdinals[0] -> ordinal 5
        put_bytes(&mut data, 0x2080, b"Widget\0");

        set_directory(&mut data, directory::EXPORT, rva, 0x40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let exports = Exports::parse(&pe, &data)
            .expect("well-formed exports parse")
            .expect("directory is present");

        assert_eq!(exports.ordinal_base, 5);
        assert_eq!(
            exports.entries,
            [ExportEntry {
                ordinal: 5,
                name: Some("Widget".to_string()),
                target: ExportTarget::Code(Rva(0x1000)),
            }]
        );
    }

    #[test]
    fn detects_forwarders_inside_the_directory_range() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        write_export_header(&mut data, 1, 1, 1);

        // The directory spans [0x2000, 0x2100); a target inside it is a
        // forwarder string, not code.
        put32(&mut data, 0x2040, 0x2090); // ordinal 1 -> forwarder at 0x2090
        put32(&mut data, 0x2060, 0x2080); // AddressOfNames[0]
        put16(&mut data, 0x2070, 0); // -> ordinal 1
        put_bytes(&mut data, 0x2080, b"SE_Export\0");
        put_bytes(&mut data, 0x2090, b"APPHELP.SE_Export\0");

        set_directory(&mut data, directory::EXPORT, rva, 0x100);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let exports = Exports::parse(&pe, &data)
            .expect("well-formed exports parse")
            .expect("directory is present");

        assert_eq!(
            exports.entries,
            [ExportEntry {
                ordinal: 1,
                name: Some("SE_Export".to_string()),
                target: ExportTarget::Forwarder("APPHELP.SE_Export".to_string()),
            }]
        );
    }

    #[test]
    fn rejects_a_directory_pointing_at_unmapped_memory() {
        let mut data = minimal_pe64(0x200);
        add_payload_section(&mut data, 0x200);
        set_directory(&mut data, directory::EXPORT, 0xf000, 0x40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                directory: directory::EXPORT,
                reason: "export directory header is not backed by mapped data",
            })
        ));
    }

    #[test]
    fn rejects_a_function_table_that_exceeds_mapped_data() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        // 0x100 functions * 4 bytes = 1 KiB, but only ~0x1c0 bytes remain from
        // AddressOfFunctions to the section end.
        write_export_header(&mut data, 1, 0x100, 0);
        set_directory(&mut data, directory::EXPORT, rva, 0x40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                reason: "export address table is not backed by mapped data",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unterminated_forwarder_string() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        write_export_header(&mut data, 1, 1, 0);
        // Forwarder target at the section's final four non-NUL bytes.
        let tail = 0x2000 + 0x200 - 4;
        put32(&mut data, 0x2040, tail);
        put_bytes(&mut data, tail, &[0xff, 0xff, 0xff, 0xff]);
        set_directory(&mut data, directory::EXPORT, rva, 0x200);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::UnterminatedString { .. })
        ));
    }

    #[test]
    fn treats_a_slotless_directory_as_empty() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        write_export_header(&mut data, 1, 0, 0);
        set_directory(&mut data, directory::EXPORT, rva, 0x40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let exports = Exports::parse(&pe, &data)
            .expect("well-formed exports parse")
            .expect("directory is present");
        assert!(exports.entries.is_empty());
        assert_eq!(exports.name, "MYLIB.dll");
    }
}
