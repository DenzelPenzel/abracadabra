//! Base relocation directory (`IMAGE_BASE_RELOCATION`).
//!
//! The on-disk table is a chain of per-page blocks, but every consumer cares
//! about individual fixups, so the model is a flat, sorted, duplicate-free list
//! of addresses — the block layout is re-derived when the table is serialized.
//! Padding entries (`IMAGE_REL_BASED_ABSOLUTE`) carry no information and are
//! dropped on parse and regenerated on write.
//!
//! Applying one fixup twice adds the relocation delta twice, so
//! [`BaseRelocations::insert`] refuses to store a duplicate silently and rejects
//! two different kinds claiming the same address.

use crate::reader::{le_u16, le_u32};
use crate::{directory, PeError, PeFile};
use vmp_types::{Architecture, Rva};

/// Bytes in one `IMAGE_BASE_RELOCATION` block header.
const BLOCK_HEADER_SIZE: usize = 8;
/// The page a block covers; the low 12 bits of an entry are the offset in it.
const PAGE_MASK: u32 = 0xffff_f000;
/// Blocks are kept 4-byte aligned, as every linker emits them.
const BLOCK_ALIGNMENT: usize = 4;

/// `IMAGE_REL_BASED_*` kinds the crate can preserve and re-emit.
///
/// Anything else is rejected rather than copied blindly: a protector that moves
/// code has to understand every fixup it is responsible for. `HIGHADJ` occupies
/// two entry slots, so copying it with a fixed one-word stride would
/// desynchronize the walk; `HIGH` and `LOW` patch half of a 32-bit pointer and do
/// not occur in x86 or x64 relocation tables; the MIPS, ARM and RISC-V kinds do
/// not apply to the supported architectures at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FixupKind {
    /// 32-bit absolute pointer patched in place.
    HighLow,
    /// 64-bit absolute pointer patched in place.
    Dir64,
}

impl FixupKind {
    /// `IMAGE_REL_BASED_ABSOLUTE`: a padding entry that applies nothing.
    const RAW_ABSOLUTE: u16 = 0;
    const RAW_HIGHLOW: u16 = 3;
    const RAW_DIR64: u16 = 10;

    fn from_raw(raw: u16) -> Option<FixupKind> {
        match raw {
            Self::RAW_HIGHLOW => Some(FixupKind::HighLow),
            Self::RAW_DIR64 => Some(FixupKind::Dir64),
            _ => None,
        }
    }

    const fn raw(self) -> u16 {
        match self {
            FixupKind::HighLow => Self::RAW_HIGHLOW,
            FixupKind::Dir64 => Self::RAW_DIR64,
        }
    }

    /// The kind that relocates a pointer-sized value on `architecture`.
    pub const fn for_architecture(architecture: Architecture) -> FixupKind {
        match architecture {
            Architecture::X86 => FixupKind::HighLow,
            Architecture::X64 => FixupKind::Dir64,
        }
    }

    /// Bytes the loader rewrites when applying the fixup.
    pub const fn width(self) -> u32 {
        match self {
            FixupKind::HighLow => 4,
            FixupKind::Dir64 => 8,
        }
    }
}

/// One address the loader patches when the image is not at its preferred base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fixup {
    pub rva: Rva,
    pub kind: FixupKind,
}

/// The flattened base relocation table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaseRelocations {
    /// Sorted by RVA and free of duplicates.
    fixups: Vec<Fixup>,
}

impl BaseRelocations {
    /// Parses the base relocation directory, or returns `None` when the image
    /// declares none.
    pub fn parse(pe: &PeFile, data: &[u8]) -> Result<Option<BaseRelocations>, PeError> {
        let Some(bytes) = pe.directory_bytes(data, directory::BASERELOC)? else {
            return Ok(None);
        };
        Self::parse_bytes(bytes, pe).map(Some)
    }

    fn parse_bytes(bytes: &[u8], pe: &PeFile) -> Result<BaseRelocations, PeError> {
        let mut fixups = Vec::new();
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            let remaining = bytes.len() - cursor;
            if remaining < BLOCK_HEADER_SIZE {
                return Err(malformed("trailing bytes cannot hold a block header"));
            }
            let page = le_u32(bytes, cursor);
            let block_size = le_u32(bytes, cursor + 4) as usize;
            // A zero header is the optional terminator every loader stops at
            if page == 0 && block_size == 0 {
                break;
            }
            if block_size < BLOCK_HEADER_SIZE {
                return Err(malformed("block size is smaller than its own header"));
            }
            if block_size > remaining {
                return Err(malformed("block extends past the directory"));
            }
            let entry_bytes = block_size - BLOCK_HEADER_SIZE;
            if !entry_bytes.is_multiple_of(2) {
                return Err(malformed("block size leaves half a relocation entry"));
            }

            for index in 0..entry_bytes / 2 {
                let raw = le_u16(bytes, cursor + BLOCK_HEADER_SIZE + index * 2);
                let raw_kind = raw >> 12;
                if raw_kind == FixupKind::RAW_ABSOLUTE {
                    continue;
                }
                let kind = FixupKind::from_raw(raw_kind).ok_or(PeError::UnsupportedFixupKind {
                    kind: raw_kind,
                    page: u64::from(page),
                })?;
                let offset = u32::from(raw & 0x0fff);
                let rva = page
                    .checked_add(offset)
                    .ok_or(malformed("fixup RVA overflows"))?;
                fixups.push(Fixup {
                    rva: Rva(rva),
                    kind,
                });
            }
            cursor += block_size;
        }

        let mut table = BaseRelocations { fixups };
        table.normalize()?;
        for fixup in &table.fixups {
            if !is_relocatable_target(pe, *fixup) {
                return Err(malformed("a fixup targets memory the image does not map"));
            }
        }
        Ok(table)
    }

    /// The fixups, sorted by address.
    pub fn fixups(&self) -> &[Fixup] {
        &self.fixups
    }

    pub fn len(&self) -> usize {
        self.fixups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fixups.is_empty()
    }

    /// Adds one fixup.
    ///
    /// Re-adding an identical fixup is rejected because the loader would apply
    /// the relocation delta twice; two kinds at one address are contradictory.
    pub fn insert(&mut self, fixup: Fixup) -> Result<(), PeError> {
        match self.fixups.binary_search(&fixup) {
            Ok(_) => Err(PeError::ConflictingFixup {
                rva: u64::from(fixup.rva.get()),
            }),
            Err(position) => {
                if self
                    .fixups
                    .iter()
                    .any(|existing| existing.rva == fixup.rva && existing.kind != fixup.kind)
                {
                    return Err(PeError::ConflictingFixup {
                        rva: u64::from(fixup.rva.get()),
                    });
                }
                self.fixups.insert(position, fixup);
                Ok(())
            }
        }
    }

    /// Sorts the table and rejects contradictory or duplicated entries.
    fn normalize(&mut self) -> Result<(), PeError> {
        self.fixups.sort_unstable();
        if let Some(duplicate) = self
            .fixups
            .windows(2)
            .find(|pair| pair[0].rva == pair[1].rva)
        {
            return Err(PeError::ConflictingFixup {
                rva: u64::from(duplicate[0].rva.get()),
            });
        }
        Ok(())
    }

    /// Serializes the table back into `IMAGE_BASE_RELOCATION` blocks.
    ///
    /// Blocks are emitted in ascending page order and padded with one
    /// `IMAGE_REL_BASED_ABSOLUTE` entry when an odd entry count would otherwise
    /// leave the next block header unaligned.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PeError> {
        let mut output = Vec::new();
        let mut index = 0usize;
        while index < self.fixups.len() {
            let page = self.fixups[index].rva.get() & PAGE_MASK;
            let start = index;
            while index < self.fixups.len() && self.fixups[index].rva.get() & PAGE_MASK == page {
                index += 1;
            }
            let entries = &self.fixups[start..index];
            let padded = entries.len() + usize::from(!entries.len().is_multiple_of(2));
            let block_size =
                BLOCK_HEADER_SIZE
                    .checked_add(padded * 2)
                    .ok_or(PeError::Overflow {
                        field: "relocation block size",
                    })?;
            debug_assert!(block_size.is_multiple_of(BLOCK_ALIGNMENT));

            output.extend_from_slice(&page.to_le_bytes());
            output.extend_from_slice(
                &u32::try_from(block_size)
                    .map_err(|_| PeError::Overflow {
                        field: "relocation block size",
                    })?
                    .to_le_bytes(),
            );
            for fixup in entries {
                let offset = fixup.rva.get() - page;
                let raw = (fixup.kind.raw() << 12) | (offset as u16 & 0x0fff);
                output.extend_from_slice(&raw.to_le_bytes());
            }
            if padded != entries.len() {
                output.extend_from_slice(&FixupKind::RAW_ABSOLUTE.to_le_bytes());
            }
        }
        Ok(output)
    }

    /// Byte length [`BaseRelocations::to_bytes`] would produce.
    pub fn byte_len(&self) -> Result<u32, PeError> {
        PeError::u32_len(self.to_bytes()?.len(), "relocation table size")
    }
}

/// Whether the whole patched value lies in memory the image maps.
///
/// The loader writes through the mapped image, so a fixup only needs virtual
/// coverage — a target in a section's zero-filled tail is legal even though no
/// file bytes back it.
fn is_relocatable_target(pe: &PeFile, fixup: Fixup) -> bool {
    pe.covers_virtual_range(fixup.rva, fixup.kind.width())
}

/// The base-relocation-directory-scoped malformed error.
fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::BASERELOC, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_payload_section, minimal_pe64, set_directory};

    /// Serializes one `IMAGE_BASE_RELOCATION` block from `(type, offset)` pairs.
    fn block(page: u32, entries: &[(u16, u16)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let size = BLOCK_HEADER_SIZE + entries.len() * 2;
        bytes.extend_from_slice(&page.to_le_bytes());
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        for (kind, offset) in entries {
            bytes.extend_from_slice(&((kind << 12) | (offset & 0x0fff)).to_le_bytes());
        }
        bytes
    }

    /// Places `table` in a mapped section and points the directory at it.
    ///
    /// The section spans a whole page so a fixup may target any address in it.
    fn image_with(table: &[u8]) -> Vec<u8> {
        let mut data = minimal_pe64(0x200);
        let rva = add_payload_section(&mut data, 0x1000);
        data[0x400..0x400 + table.len()].copy_from_slice(table);
        set_directory(&mut data, directory::BASERELOC, rva, table.len() as u32);
        data
    }

    /// Parses through `PeFile::parse`, which is where the model is built.
    fn parse(table: &[u8]) -> Result<BaseRelocations, PeError> {
        let data = image_with(table);
        PeFile::parse(&data).map(|pe| {
            pe.base_relocations
                .expect("the directory is present in the image")
        })
    }

    #[test]
    fn absent_directory_has_no_model() {
        let data = minimal_pe64(0x200);
        let pe = PeFile::parse(&data).expect("an image without relocations is valid");
        assert_eq!(pe.base_relocations, None);
    }

    #[test]
    fn flattens_blocks_and_drops_padding() {
        let table = block(
            0x1000,
            &[
                (FixupKind::RAW_DIR64, 0x008),
                (FixupKind::RAW_ABSOLUTE, 0),
                (FixupKind::RAW_DIR64, 0x000),
            ],
        );
        let parsed = parse(&table).expect("well-formed table must parse");

        assert_eq!(
            parsed.fixups(),
            [
                Fixup {
                    rva: Rva(0x1000),
                    kind: FixupKind::Dir64
                },
                Fixup {
                    rva: Rva(0x1008),
                    kind: FixupKind::Dir64
                },
            ],
            "entries are flattened and sorted, padding is dropped"
        );
    }

    #[test]
    fn stops_at_a_zero_terminator_block() {
        let mut table = block(0x1000, &[(FixupKind::RAW_DIR64, 0)]);
        table.extend_from_slice(&[0u8; BLOCK_HEADER_SIZE]);

        assert_eq!(parse(&table).expect("terminator is legal").len(), 1);
    }

    #[test]
    fn rejects_block_size_below_its_header() {
        let mut table = block(0x1000, &[(FixupKind::RAW_DIR64, 0)]);
        table[4..8].copy_from_slice(&4u32.to_le_bytes());

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                directory: directory::BASERELOC,
                reason: "block size is smaller than its own header",
            })
        ));
    }

    #[test]
    fn rejects_block_extending_past_the_directory() {
        let mut table = block(0x1000, &[(FixupKind::RAW_DIR64, 0)]);
        table[4..8].copy_from_slice(&0x40u32.to_le_bytes());

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                reason: "block extends past the directory",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_block_that_leaves_half_an_entry() {
        let mut table = block(0x1000, &[(FixupKind::RAW_DIR64, 0), (0, 0)]);
        table[4..8].copy_from_slice(&11u32.to_le_bytes());
        table.truncate(11);

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                reason: "block size leaves half a relocation entry",
                ..
            })
        ));
    }

    #[test]
    fn rejects_trailing_bytes_too_short_for_a_header() {
        let mut table = block(0x1000, &[(FixupKind::RAW_DIR64, 0)]);
        table.extend_from_slice(&[0u8; 4]);

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                reason: "trailing bytes cannot hold a block header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_relocation_kinds_the_writer_cannot_re_emit() {
        // IMAGE_REL_BASED_HIGHADJ consumes a second entry as its operand, so
        // copying it blindly would desynchronize the walk
        let table = block(0x1000, &[(4, 0)]);

        assert!(matches!(
            parse(&table),
            Err(PeError::UnsupportedFixupKind {
                kind: 4,
                page: 0x1000,
            })
        ));
    }

    #[test]
    fn rejects_two_fixups_at_one_address() {
        let table = block(
            0x1000,
            &[(FixupKind::RAW_DIR64, 0x10), (FixupKind::RAW_DIR64, 0x10)],
        );

        assert!(matches!(
            parse(&table),
            Err(PeError::ConflictingFixup { rva: 0x1010 })
        ));
    }

    #[test]
    fn rejects_a_fixup_outside_mapped_memory() {
        let table = block(0xf000, &[(FixupKind::RAW_DIR64, 0)]);

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                reason: "a fixup targets memory the image does not map",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_fixup_whose_tail_leaves_the_section() {
        // The last four bytes of .text are mapped, the next four are not
        let table = block(0x1000, &[(FixupKind::RAW_DIR64, 0x1fc)]);

        assert!(matches!(
            parse(&table),
            Err(PeError::MalformedDirectory {
                reason: "a fixup targets memory the image does not map",
                ..
            })
        ));
    }

    #[test]
    fn insert_rejects_duplicates_and_contradictions() {
        let mut table = BaseRelocations::default();
        let fixup = Fixup {
            rva: Rva(0x2000),
            kind: FixupKind::Dir64,
        };
        table.insert(fixup).expect("first insertion succeeds");

        assert!(matches!(
            table.insert(fixup),
            Err(PeError::ConflictingFixup { rva: 0x2000 })
        ));
        assert!(matches!(
            table.insert(Fixup {
                rva: Rva(0x2000),
                kind: FixupKind::HighLow,
            }),
            Err(PeError::ConflictingFixup { rva: 0x2000 })
        ));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn insert_keeps_the_table_sorted() {
        let mut table = BaseRelocations::default();
        for rva in [0x3000u32, 0x1000, 0x2000] {
            table
                .insert(Fixup {
                    rva: Rva(rva),
                    kind: FixupKind::Dir64,
                })
                .expect("distinct addresses are accepted");
        }

        let addresses: Vec<u32> = table.fixups().iter().map(|fixup| fixup.rva.get()).collect();
        assert_eq!(addresses, [0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn serialization_groups_pages_and_round_trips() {
        let table = [
            block(0x2000, &[(FixupKind::RAW_DIR64, 0x10)]),
            block(
                0x1000,
                &[(FixupKind::RAW_DIR64, 0x20), (FixupKind::RAW_DIR64, 0)],
            ),
        ]
        .concat();
        let parsed = parse(&table).expect("out-of-order blocks are legal");
        let serialized = parsed.to_bytes().expect("table serializes");

        // Pages come out in ascending order regardless of the input order
        // Two entries fill the first block exactly, so the next header follows
        // at offset 12
        assert_eq!(&serialized[0..4], &0x1000u32.to_le_bytes());
        assert_eq!(&serialized[4..8], &12u32.to_le_bytes());
        assert_eq!(&serialized[12..16], &0x2000u32.to_le_bytes());

        let round_tripped = parse(&serialized).expect("serialized table parses");
        assert_eq!(
            round_tripped, parsed,
            "serialization is semantics-preserving"
        );
        assert_eq!(
            round_tripped.to_bytes().expect("serializes"),
            serialized,
            "serialization is idempotent"
        );
    }

    #[test]
    fn serialization_pads_odd_entry_counts() {
        let mut parsed = BaseRelocations::default();
        parsed
            .insert(Fixup {
                rva: Rva(0x1000),
                kind: FixupKind::Dir64,
            })
            .expect("insertion succeeds");
        let serialized = parsed.to_bytes().expect("table serializes");

        assert_eq!(serialized.len(), 12, "one entry is padded to a second slot");
        assert_eq!(&serialized[4..8], &12u32.to_le_bytes());
        assert_eq!(
            &serialized[10..12],
            &FixupKind::RAW_ABSOLUTE.to_le_bytes(),
            "the pad is an ABSOLUTE entry"
        );
        assert_eq!(parsed.byte_len().expect("length fits"), 12);
    }

    #[test]
    fn empty_table_serializes_to_nothing() {
        let table = BaseRelocations::default();
        assert!(table.is_empty());
        assert!(table.to_bytes().expect("serializes").is_empty());
        assert_eq!(table.byte_len().expect("length fits"), 0);
    }
}
