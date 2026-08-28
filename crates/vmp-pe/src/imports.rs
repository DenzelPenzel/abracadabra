//! Import directory (`IMAGE_IMPORT_DESCRIPTOR`).
//!
//! The on-disk table is an array of per-library descriptors, each pointing at
//! two parallel thunk arrays: the import name table (`OriginalFirstThunk`) that
//! names what is imported, and the import address table (`FirstThunk`) that the
//! loader overwrites with resolved addresses. The model keeps both — the names
//! read from whichever name table is present, and the address-table slot RVA of
//! every function so a protector knows exactly which pointer the loader binds.
//!
//! Names are preferred from `OriginalFirstThunk`; when it is absent the loader
//! (and this parser) fall back to walking `FirstThunk` for both purposes, which
//! is what the original C++ `PEImport::ReadFromFile` does. The descriptor array
//! terminates at the first record with a zero `FirstThunk` — the canonical
//! all-zero terminator has one, so this subsumes it while matching the loader.
//!
//! Every walk is bounded by mapped data: a descriptor array or thunk array that
//! runs off the end of the image without a terminator is a typed error, never an
//! unbounded scan. Delay imports are deliberately not parsed here; see
//! [`Imports::parse`].

use crate::reader::{le_u32, le_u64};
use crate::{directory, PeError, PeFile};
use vmp_types::Rva;

/// Bytes in one `IMAGE_IMPORT_DESCRIPTOR`.
const DESCRIPTOR_SIZE: usize = 20;
/// `IMAGE_ORDINAL_FLAG32`: high bit of a PE32 thunk marks an import by ordinal.
const ORDINAL_FLAG_PE32: u64 = 0x8000_0000;
/// `IMAGE_ORDINAL_FLAG64`: high bit of a PE32+ thunk marks an import by ordinal.
const ORDINAL_FLAG_PE32PLUS: u64 = 0x8000_0000_0000_0000;

/// What a single imported thunk resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportTarget {
    /// Imported by ordinal; carries the ordinal number.
    Ordinal(u16),
    /// Imported by name via `IMAGE_IMPORT_BY_NAME`, with its hint.
    Name { hint: u16, name: String },
}

/// One imported function: where the loader binds it and what it resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFunction {
    /// RVA of this function's slot in the import address table (`FirstThunk`).
    pub thunk_rva: Rva,
    pub target: ImportTarget,
}

/// One imported library (`IMAGE_IMPORT_DESCRIPTOR`) and its functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedLibrary {
    pub name: String,
    /// The import name table RVA, or `None` when the descriptor omits it and the
    /// address table doubles as the name source.
    pub original_first_thunk: Option<Rva>,
    /// The import address table RVA the loader overwrites with resolved pointers.
    pub first_thunk: Rva,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub functions: Vec<ImportedFunction>,
}

/// The parsed import directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imports {
    pub descriptors: Vec<ImportedLibrary>,
}

impl Imports {
    /// Parses the import directory, or returns `None` when the image declares
    /// none.
    ///
    /// The delay-import directory is intentionally not parsed: a pre-VS2015
    /// delay descriptor whose `Attributes` RVA bit is clear stores absolute
    /// virtual addresses rather than RVAs, and disambiguating that safely is out
    /// of scope for this RVA-based reader. Leaving it out is fail-closed — no
    /// address is guessed.
    pub fn parse(pe: &PeFile, data: &[u8]) -> Result<Option<Imports>, PeError> {
        let Some(entry) = pe.data_directory(directory::IMPORT) else {
            return Ok(None);
        };
        if !entry.is_present() {
            return Ok(None);
        }
        let rva = entry.address.rva().ok_or(malformed(
            "import directory entry is a file offset, not an RVA",
        ))?;
        Self::parse_at(pe, data, rva).map(Some)
    }

    fn parse_at(pe: &PeFile, data: &[u8], directory_rva: Rva) -> Result<Imports, PeError> {
        let is_pe32_plus = pe.optional.is_pe32_plus();
        let descriptors_bytes = pe
            .mapped_from(data, directory_rva)
            .map_err(|_| malformed("import directory is not backed by mapped data"))?;

        let mut descriptors = Vec::new();
        let mut cursor = 0usize;
        loop {
            let end = cursor
                .checked_add(DESCRIPTOR_SIZE)
                .ok_or(malformed("import descriptor offset overflows"))?;
            let Some(record) = descriptors_bytes.get(cursor..end) else {
                return Err(malformed("import descriptor array runs past mapped data"));
            };

            let original_first_thunk = le_u32(record, 0);
            let time_date_stamp = le_u32(record, 4);
            let forwarder_chain = le_u32(record, 8);
            let name_rva = le_u32(record, 12);
            let first_thunk = le_u32(record, 16);

            // A zero FirstThunk is the terminator every loader stops at; the
            // canonical all-zero descriptor is one such record.
            if first_thunk == 0 {
                break;
            }
            if name_rva == 0 {
                return Err(malformed("import descriptor has no name"));
            }

            let name = pe.mapped_string(data, Rva(name_rva))?;
            // The name table wins when present, else the address table names the
            // imports too.
            let name_source = if original_first_thunk != 0 {
                Rva(original_first_thunk)
            } else {
                Rva(first_thunk)
            };
            let functions = read_functions(pe, data, name_source, Rva(first_thunk), is_pe32_plus)?;

            descriptors.push(ImportedLibrary {
                name,
                original_first_thunk: (original_first_thunk != 0)
                    .then_some(Rva(original_first_thunk)),
                first_thunk: Rva(first_thunk),
                time_date_stamp,
                forwarder_chain,
                functions,
            });
            cursor = end;
        }

        Ok(Imports { descriptors })
    }
}

/// Walks the name table for one library, pairing each entry with its address
/// table slot RVA.
fn read_functions(
    pe: &PeFile,
    data: &[u8],
    name_source: Rva,
    first_thunk: Rva,
    is_pe32_plus: bool,
) -> Result<Vec<ImportedFunction>, PeError> {
    let width = usize::from(pe.architecture.pointer_width());
    let thunks = pe
        .mapped_from(data, name_source)
        .map_err(|_| malformed("import thunk array is not backed by mapped data"))?;

    let mut functions = Vec::new();
    let mut index = 0usize;
    loop {
        let offset = index
            .checked_mul(width)
            .ok_or(malformed("import thunk offset overflows"))?;
        let end = offset
            .checked_add(width)
            .ok_or(malformed("import thunk offset overflows"))?;
        let Some(chunk) = thunks.get(offset..end) else {
            return Err(malformed("import thunk array runs past mapped data"));
        };

        let raw = if is_pe32_plus {
            le_u64(chunk, 0)
        } else {
            u64::from(le_u32(chunk, 0))
        };
        // A zero thunk terminates this library's function list.
        if raw == 0 {
            break;
        }

        let target = decode_target(pe, data, raw, is_pe32_plus)?;
        let slot_offset = u32::try_from(offset)
            .map_err(|_| malformed("import address table offset overflows"))?;
        let thunk_rva = first_thunk
            .checked_add(slot_offset)
            .ok_or(malformed("import address table slot RVA overflows"))?;
        functions.push(ImportedFunction { thunk_rva, target });
        index += 1;
    }

    // `thunk_rva` is the pointer the loader binds and a protector rebinds, so the
    // whole address table has to be inside the image — the name table this walk
    // followed may well be the longer of the two
    let span = u32::try_from(functions.len().saturating_mul(width))
        .map_err(|_| malformed("import address table span overflows"))?;
    if span != 0 && !pe.covers_virtual_range(first_thunk, span) {
        return Err(malformed("import address table is not mapped by the image"));
    }

    Ok(functions)
}

/// Decodes one thunk value into an ordinal or a hinted name.
fn decode_target(
    pe: &PeFile,
    data: &[u8],
    raw: u64,
    is_pe32_plus: bool,
) -> Result<ImportTarget, PeError> {
    let ordinal_flag = if is_pe32_plus {
        ORDINAL_FLAG_PE32PLUS
    } else {
        ORDINAL_FLAG_PE32
    };
    if raw & ordinal_flag != 0 {
        // The low 16 bits are the ordinal; the rest of the value is reserved.
        return Ok(ImportTarget::Ordinal((raw & 0xffff) as u16));
    }

    // A name thunk holds the RVA of an IMAGE_IMPORT_BY_NAME { WORD Hint; char Name[] }.
    let name_rva = u32::try_from(raw & !ordinal_flag)
        .map_err(|_| malformed("import name RVA exceeds the 32-bit address space"))?;
    let by_name = Rva(name_rva);
    let hint_bytes = pe
        .mapped_range(data, by_name, 2)
        .map_err(|_| malformed("import name hint is not backed by mapped data"))?;
    let hint = u16::from_le_bytes([hint_bytes[0], hint_bytes[1]]);
    let name_rva = by_name
        .checked_add(2)
        .ok_or(malformed("import name RVA overflows"))?;
    let name = pe.mapped_string(data, name_rva)?;
    Ok(ImportTarget::Name { hint, name })
}

/// The import-directory-scoped malformed error.
fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::IMPORT, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        add_payload_section, add_payload_section_pe32, minimal_pe32, minimal_pe64, put16, put32,
        put_bytes, set_directory,
    };

    /// Lays out one USER32.dll descriptor with a named and an ordinal import.
    ///
    /// `ordinal_flag` selects the bitness-specific ordinal marker and `width`
    /// the thunk size, so the same layout drives both PE32 and PE32+.
    fn write_two_import_library(data: &mut [u8], ordinal_flag: u64, width: u32) {
        // Descriptor at 0x2000: OFT=0x2050, Name=0x2040, FirstThunk=0x2100.
        put32(data, 0x2000, 0x2050); // OriginalFirstThunk
        put32(data, 0x2000 + 12, 0x2040); // Name
        put32(data, 0x2000 + 16, 0x2100); // FirstThunk
                                          // Terminator descriptor at 0x2014 stays zero (FirstThunk == 0).

        put_bytes(data, 0x2040, b"USER32.dll\0");

        // Name table at 0x2050: [name -> 0x2080], [ordinal 5], [terminator].
        put32(data, 0x2050, 0x2080);
        let ordinal_entry = ordinal_flag | 5;
        put32(data, 0x2050 + width, ordinal_entry as u32);
        if width == 8 {
            put32(data, 0x2050 + width + 4, (ordinal_entry >> 32) as u32);
        }

        // IMAGE_IMPORT_BY_NAME at 0x2080: hint 7, "MessageBoxW".
        put16(data, 0x2080, 7);
        put_bytes(data, 0x2082, b"MessageBoxW\0");
    }

    #[test]
    fn absent_directory_has_no_model() {
        let data = minimal_pe64(0x200);
        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        assert_eq!(
            Imports::parse(&pe, &data).expect("absent directory is not an error"),
            None
        );
    }

    #[test]
    fn parses_named_and_ordinal_imports_pe32_plus() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        write_two_import_library(&mut data, ORDINAL_FLAG_PE32PLUS, 8);
        set_directory(&mut data, directory::IMPORT, rva, 40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let imports = Imports::parse(&pe, &data)
            .expect("well-formed imports parse")
            .expect("directory is present");

        assert_eq!(imports.descriptors.len(), 1);
        let library = &imports.descriptors[0];
        assert_eq!(library.name, "USER32.dll");
        assert_eq!(library.original_first_thunk, Some(Rva(0x2050)));
        assert_eq!(library.first_thunk, Rva(0x2100));
        assert_eq!(
            library.functions,
            [
                ImportedFunction {
                    thunk_rva: Rva(0x2100),
                    target: ImportTarget::Name {
                        hint: 7,
                        name: "MessageBoxW".to_string(),
                    },
                },
                ImportedFunction {
                    // Second 8-byte IAT slot.
                    thunk_rva: Rva(0x2108),
                    target: ImportTarget::Ordinal(5),
                },
            ]
        );
    }

    #[test]
    fn parses_named_and_ordinal_imports_pe32() {
        let mut data = minimal_pe32(0x200);
        let rva = add_payload_section_pe32(&mut data);
        write_two_import_library(&mut data, ORDINAL_FLAG_PE32, 4);
        set_directory(&mut data, directory::IMPORT, rva, 40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let imports = Imports::parse(&pe, &data)
            .expect("well-formed imports parse")
            .expect("directory is present");

        assert_eq!(imports.descriptors.len(), 1);
        let library = &imports.descriptors[0];
        assert_eq!(library.name, "USER32.dll");
        assert_eq!(
            library.functions,
            [
                ImportedFunction {
                    thunk_rva: Rva(0x2100),
                    target: ImportTarget::Name {
                        hint: 7,
                        name: "MessageBoxW".to_string(),
                    },
                },
                ImportedFunction {
                    // Second 4-byte IAT slot.
                    thunk_rva: Rva(0x2104),
                    target: ImportTarget::Ordinal(5),
                },
            ]
        );
    }

    #[test]
    fn falls_back_to_first_thunk_when_name_table_absent() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        // No OriginalFirstThunk: names must come from FirstThunk itself.
        put32(&mut data, 0x2000 + 12, 0x2040); // Name
        put32(&mut data, 0x2000 + 16, 0x2050); // FirstThunk doubles as name table
        put_bytes(&mut data, 0x2040, b"KERNEL32.dll\0");
        put32(&mut data, 0x2050, 0x2080); // one named import
        put16(&mut data, 0x2080, 1);
        put_bytes(&mut data, 0x2082, b"ExitProcess\0");
        set_directory(&mut data, directory::IMPORT, rva, 40);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let imports = Imports::parse(&pe, &data)
            .expect("well-formed imports parse")
            .expect("directory is present");

        let library = &imports.descriptors[0];
        assert_eq!(library.original_first_thunk, None);
        assert_eq!(library.first_thunk, Rva(0x2050));
        assert_eq!(
            library.functions,
            [ImportedFunction {
                thunk_rva: Rva(0x2050),
                target: ImportTarget::Name {
                    hint: 1,
                    name: "ExitProcess".to_string(),
                },
            }]
        );
    }

    #[test]
    fn rejects_a_directory_pointing_at_unmapped_memory() {
        let mut data = minimal_pe64(0x200);
        add_payload_section(&mut data, 0x200);
        // An RVA covered by no section: the directory is not backed by data.
        set_directory(&mut data, directory::IMPORT, 0xf000, 40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                directory: directory::IMPORT,
                reason: "import directory is not backed by mapped data",
            })
        ));
    }

    #[test]
    fn rejects_a_descriptor_array_that_runs_past_mapped_data() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        // Point the directory eight bytes short of the section end so the first
        // 20-byte descriptor cannot be read in full.
        set_directory(&mut data, directory::IMPORT, rva + 0x200 - 8, 40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                reason: "import descriptor array runs past mapped data",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unterminated_dll_name() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        // Name points at the final four bytes, filled with non-NUL bytes.
        put32(&mut data, 0x2000 + 12, 0x2000 + 0x200 - 4); // Name
        put32(&mut data, 0x2000 + 16, 0x2100); // FirstThunk
        put_bytes(&mut data, 0x2000 + 0x200 - 4, &[0xff, 0xff, 0xff, 0xff]);
        set_directory(&mut data, directory::IMPORT, rva, 40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::UnterminatedString { .. })
        ));
    }

    #[test]
    fn rejects_a_thunk_array_that_runs_past_mapped_data() {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        put32(&mut data, 0x2000 + 12, 0x2040); // Name
        put32(&mut data, 0x2000 + 16, 0x2100); // FirstThunk
        put_bytes(&mut data, 0x2040, b"USER32.dll\0");
        // Name table sits four bytes from the end with a non-zero (non-terminator)
        // entry that cannot be followed by a full 8-byte thunk.
        let tail = 0x2000 + 0x200 - 4;
        put32(&mut data, 0x2000, tail); // OriginalFirstThunk
        put_bytes(&mut data, tail, &[0x11, 0x22, 0x33, 0x44]);
        set_directory(&mut data, directory::IMPORT, rva, 40);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                reason: "import thunk array runs past mapped data",
                ..
            })
        ));
    }

    #[test]
    fn preserves_duplicate_library_descriptors() {
        // A file may legally list the same DLL twice; the model must not merge.
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x200);
        for (index, slot) in [0x2000u32, 0x2000 + DESCRIPTOR_SIZE as u32]
            .into_iter()
            .enumerate()
        {
            put32(&mut data, slot, 0x2050); // OriginalFirstThunk
            put32(&mut data, slot + 12, 0x2040); // Name
            put32(&mut data, slot + 16, 0x2100 + index as u32 * 8); // FirstThunk
        }
        put_bytes(&mut data, 0x2040, b"KERNEL32.dll\0");
        put32(&mut data, 0x2050, 0x2080); // one named import
        put16(&mut data, 0x2080, 0);
        put_bytes(&mut data, 0x2082, b"Sleep\0");
        set_directory(&mut data, directory::IMPORT, rva, 60);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        let imports = Imports::parse(&pe, &data)
            .expect("well-formed imports parse")
            .expect("directory is present");

        assert_eq!(imports.descriptors.len(), 2);
        assert_eq!(imports.descriptors[0].name, "KERNEL32.dll");
        assert_eq!(imports.descriptors[1].name, "KERNEL32.dll");
        assert_eq!(imports.descriptors[0].first_thunk, Rva(0x2100));
        assert_eq!(imports.descriptors[1].first_thunk, Rva(0x2108));
    }
}
