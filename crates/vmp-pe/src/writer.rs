//! Append-only PE image writer.
//!
//! The MVP deliberately never moves existing headers, sections, or data
//! directories. A candidate output is reparsed before it replaces the owned
//! image, so mutations are atomic on failure.

use crate::exception::{ExceptionTable, FunctionEntry, RuntimeFunction, UnwindInfo};
use crate::reader::{le_u32, slice, slice_mut};
use crate::relocations::{BaseRelocations, Fixup, FixupKind};
use crate::tls::{self, TlsDirectory};
use crate::{directory, PeError, PeFile, DIRECTORY_ENTRY_SIZE, SECTION_HEADER_SIZE};
use vmp_types::Rva;

const MAX_IMAGE_SECTIONS: u16 = 96;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// `IMAGE_FILE_RELOCS_STRIPPED`: the loader must ignore base relocations.
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// Characteristics of the read-only payload sections the directory operations
/// emit.
const PAYLOAD_CHARACTERISTICS: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

/// Description of a section to append to an image.
#[derive(Debug, Clone, Copy)]
pub struct NewSection<'data> {
    /// UTF-8 section name encoded directly into the eight-byte PE field.
    pub name: &'data str,
    /// Initialized bytes to place in the section's raw range.
    pub data: &'data [u8],
    /// Raw `IMAGE_SCN_*` characteristics.
    pub characteristics: u32,
}

/// A data directory to re-point at bytes inside the section being appended.
///
/// Only the directory's `VirtualAddress` and `Size` entry in the optional header
/// changes; the bytes it used to point at stay where they are, because the
/// append-only writer never moves existing content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryPlacement {
    /// Index into the data directory array (see [`crate::directory`]).
    pub directory: usize,
    /// Offset of the payload within [`NewSection::data`].
    pub offset: u32,
    /// Byte count to record in the directory entry.
    pub size: u32,
}

/// A runtime function to add to the exception directory, with the unwind info
/// that will be emitted alongside it.
#[derive(Debug, Clone)]
pub struct NewFunction {
    /// Start of the code the entry describes.
    pub begin: Rva,
    /// Exclusive end of that code.
    pub end: Rva,
    /// Unwind info for the function. It must be re-emittable, so it may not
    /// carry language-specific handler data.
    pub unwind: UnwindInfo,
}

/// An owned PE file together with its validated parsed model.
#[derive(Debug, Clone)]
pub struct PeImage {
    bytes: Vec<u8>,
    pe: PeFile,
}

#[derive(Debug)]
pub(crate) struct ExpectedLayout {
    section_table_offset: u64,
    old_section_count: usize,
    section_count: u16,
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
    size_of_image: u32,
    /// Every data directory entry as it must read after the rewrite.
    directories: Vec<(u64, u32)>,
    /// Directory models the rewrite is expected to produce. `None` means the
    /// directory is untouched and must still parse to the previous model.
    models: ExpectedModels,
}

/// Structured directories the candidate must contain after a rewrite.
#[derive(Debug, Default)]
pub(crate) struct ExpectedModels {
    relocations: Option<BaseRelocations>,
    tls: Option<TlsDirectory>,
    exception: Option<ExceptionTable>,
}

impl PeImage {
    /// Parses and takes ownership of a complete PE file image.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<PeImage, PeError> {
        let pe = PeFile::parse(&bytes)?;
        Ok(PeImage { bytes, pe })
    }

    /// Returns the current parsed model.
    pub fn pe(&self) -> &PeFile {
        &self.pe
    }

    /// Returns the current serialized bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the image and returns its serialized bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The RVA the next appended section will start at.
    ///
    /// Code placed in an appended section has to be encoded for the address it
    /// will occupy, and that address has to be known before the section exists.
    /// Every append lands at the current `SizeOfImage`, so the answer is
    /// available in advance — but only for an image this writer can extend at
    /// all, which is why the layout checks run here too.
    pub fn next_section_rva(&self) -> Result<Rva, PeError> {
        planned_section_rva(&self.pe).map(Rva)
    }

    /// Appends a section without moving any existing PE structure.
    ///
    /// The mutation is committed only after the candidate output parses again.
    pub fn add_section(&mut self, section: NewSection<'_>) -> Result<(), PeError> {
        self.commit(section, &[], ExpectedModels::default())
    }

    /// Appends a section and re-points data directories at bytes inside it.
    ///
    /// This is the primitive behind the directory operations below: the new
    /// content is appended, the affected `IMAGE_DATA_DIRECTORY` entries are
    /// rewritten in place, and every other entry has to come back unchanged.
    pub fn add_section_with_directories(
        &mut self,
        section: NewSection<'_>,
        placements: &[DirectoryPlacement],
    ) -> Result<(), PeError> {
        self.commit(section, placements, ExpectedModels::default())
    }

    /// Rewrites the base relocation table with `additional` fixups added.
    ///
    /// The whole table is re-serialized into a new section and directory 5 is
    /// re-pointed at it; the original `.reloc` bytes stay in the file, unused.
    /// An image that declares no relocations is refused rather than turned into
    /// a relocatable one, which would change how the loader maps it.
    pub fn extend_base_relocations(
        &mut self,
        name: &str,
        additional: &[Fixup],
    ) -> Result<(), PeError> {
        let mut table = self.relocatable_table()?;
        for fixup in additional {
            table.insert(*fixup)?;
        }
        let payload = table.to_bytes()?;
        let size = PeError::u32_len(payload.len(), "relocation payload size")?;
        self.commit(
            NewSection {
                name,
                data: &payload,
                characteristics: PAYLOAD_CHARACTERISTICS,
            },
            &[DirectoryPlacement {
                directory: directory::BASERELOC,
                offset: 0,
                size,
            }],
            ExpectedModels {
                relocations: Some(table),
                ..ExpectedModels::default()
            },
        )
    }

    /// Moves the TLS directory into a new section, optionally appending
    /// callbacks.
    ///
    /// The directory's four address fields are absolute virtual addresses, so a
    /// relocatable image also needs one base relocation per non-zero field and
    /// per callback slot. Those fixups are folded into the relocation table in
    /// the same atomic step, which is why the new section can carry both
    /// payloads.
    ///
    /// Apply this once per image. A second call moves the directory again but
    /// keeps the fixups belonging to the copy it abandons: those addresses are
    /// still mapped, so the output remains valid and loadable, but the relocation
    /// table grows by the size of the abandoned copy's fixup set on every
    /// repetition. The fixups are deliberately not withdrawn — on the first move
    /// they are the ones the original linker emitted, and dropping inherited
    /// metadata is a larger change than adding to it.
    pub fn relocate_tls(
        &mut self,
        name: &str,
        additional_callbacks: &[Rva],
    ) -> Result<(), PeError> {
        let tls = self
            .pe
            .tls
            .clone()
            .ok_or(PeError::UnsupportedRewriteLayout {
                reason: "the image has no TLS directory to move",
            })?;
        let is_pe32_plus = self.pe.optional.is_pe32_plus();
        let pointer_width = usize::from(self.pe.architecture.pointer_width());
        let section_rva = planned_section_rva(&self.pe)?;

        let mut callbacks = tls.callbacks.clone();
        for callback in additional_callbacks {
            if callbacks.contains(callback) {
                return Err(PeError::UnsupportedRewriteLayout {
                    reason: "a TLS callback is already registered",
                });
            }
            callbacks.push(*callback);
        }

        // The moved structure points at the callback array in the same payload,
        // so the array's address has to be known before the structure is written
        let mut payload = PayloadBuilder::new(section_rva);
        let structure_size = TlsDirectory::size_for(is_pe32_plus) as usize;
        let structure_offset = payload.reserve(structure_size, pointer_width)?;
        let array_offset = payload.reserve(
            callbacks
                .len()
                .checked_add(1)
                .and_then(|slots| slots.checked_mul(pointer_width))
                .ok_or(PeError::Overflow {
                    field: "TLS callback array size",
                })?,
            pointer_width,
        )?;

        let mut moved = tls.clone();
        moved.rva = Rva(payload.rva_of(structure_offset)?);
        moved.callbacks = callbacks.clone();
        // The array is always emitted with its terminator, so the field points
        // at it whenever the original directory declared one or callbacks exist
        moved.address_of_callbacks.rva =
            if callbacks.is_empty() && tls.address_of_callbacks.rva.is_none() {
                None
            } else {
                Some(Rva(payload.rva_of(array_offset)?))
            };
        payload.write_at(
            structure_offset,
            &moved.to_bytes(self.pe.optional.image_base, is_pe32_plus)?,
        )?;

        let mut array = Vec::with_capacity((callbacks.len() + 1) * pointer_width);
        for callback in &callbacks {
            tls::push_address(
                &mut array,
                *callback,
                self.pe.optional.image_base,
                is_pe32_plus,
                "TLS callback address",
            )?;
        }
        // The array is NULL-terminated, which is also what makes an empty one legal
        tls::push_zero(&mut array, is_pe32_plus);
        payload.write_at(array_offset, &array)?;

        let mut placements = vec![DirectoryPlacement {
            directory: directory::TLS,
            offset: payload_offset(structure_offset)?,
            size: TlsDirectory::size_for(is_pe32_plus),
        }];
        let mut models = ExpectedModels {
            tls: Some(moved.clone()),
            ..ExpectedModels::default()
        };

        // Without a relocation table the loader cannot move the image, so the
        // absolute addresses just written stay correct and need no fixups
        if self.pe.base_relocations.is_some() {
            let mut relocations = self.relocatable_table()?;
            let kind = FixupKind::for_architecture(self.pe.architecture);
            for field in moved.relocatable_fields() {
                relocations.insert(Fixup {
                    rva: Rva(payload.rva_of(structure_offset + field.field_offset as usize)?),
                    kind,
                })?;
            }
            for index in 0..callbacks.len() {
                relocations.insert(Fixup {
                    rva: Rva(payload.rva_of(array_offset + index * pointer_width)?),
                    kind,
                })?;
            }
            let table = relocations.to_bytes()?;
            let offset = payload.append(&table, 4)?;
            placements.push(DirectoryPlacement {
                directory: directory::BASERELOC,
                offset: payload_offset(offset)?,
                size: PeError::u32_len(table.len(), "relocation payload size")?,
            });
            models.relocations = Some(relocations);
        }

        let data = payload.finish();
        self.commit(
            NewSection {
                name,
                data: &data,
                characteristics: PAYLOAD_CHARACTERISTICS,
            },
            &placements,
            models,
        )
    }

    /// Rewrites the exception directory with `additional` functions added.
    ///
    /// The new `RUNTIME_FUNCTION` array and the unwind info for the new
    /// functions go into one appended section, and directory 3 is re-pointed at
    /// the array. Unwind info belonging to existing functions is left exactly
    /// where it is: its total length depends on language-specific handler data
    /// this crate does not model, so moving it could not be done safely.
    pub fn extend_exception_table(
        &mut self,
        name: &str,
        additional: &[NewFunction],
    ) -> Result<(), PeError> {
        if self.pe.architecture != vmp_types::Architecture::X64 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "only x64 images have a RUNTIME_FUNCTION exception directory",
            });
        }
        let section_rva = planned_section_rva(&self.pe)?;
        let mut table = self.pe.exception_table.clone().unwrap_or_default();
        let mut payload = PayloadBuilder::new(section_rva);

        // Unwind info first: each entry needs its blob's address before the
        // array that references it can be serialized
        for function in additional {
            let blob = function.unwind.to_bytes()?;
            let offset = payload.append(&blob, 4)?;
            table.insert(FunctionEntry {
                function: RuntimeFunction {
                    begin: function.begin,
                    end: function.end,
                    unwind_info: Rva(payload.rva_of(offset)?),
                },
                unwind: function.unwind.clone(),
            })?;
        }
        let array = table.to_bytes()?;
        let array_offset = payload.append(&array, 4)?;
        let data = payload.finish();

        self.commit(
            NewSection {
                name,
                data: &data,
                characteristics: PAYLOAD_CHARACTERISTICS,
            },
            &[DirectoryPlacement {
                directory: directory::EXCEPTION,
                offset: payload_offset(array_offset)?,
                size: PeError::u32_len(array.len(), "exception payload size")?,
            }],
            ExpectedModels {
                exception: Some(table),
                ..ExpectedModels::default()
            },
        )
    }

    /// The current relocation table, if the image is one the loader relocates.
    fn relocatable_table(&self) -> Result<BaseRelocations, PeError> {
        if self.pe.coff.characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the image declares its relocations stripped, so the loader ignores them",
            });
        }
        self.pe
            .base_relocations
            .clone()
            .ok_or(PeError::UnsupportedRewriteLayout {
                reason: "the image declares no base relocations, so adding fixups would change how the loader maps it",
            })
    }

    /// Builds, verifies and atomically commits one candidate output.
    fn commit(
        &mut self,
        section: NewSection<'_>,
        placements: &[DirectoryPlacement],
        models: ExpectedModels,
    ) -> Result<(), PeError> {
        let (candidate, expected) =
            build_with_section(&self.bytes, &self.pe, section, placements, models)?;
        let pe = PeFile::parse(&candidate)?;
        verify_candidate(&self.bytes, &candidate, &self.pe, &pe, &expected)?;
        self.bytes = candidate;
        self.pe = pe;
        Ok(())
    }
}

/// Assembles the payload of one appended section, tracking where each part
/// lands so self-referential addresses can be computed before writing.
struct PayloadBuilder {
    section_rva: u32,
    data: Vec<u8>,
}

impl PayloadBuilder {
    fn new(section_rva: u32) -> PayloadBuilder {
        PayloadBuilder {
            section_rva,
            data: Vec::new(),
        }
    }

    /// Reserves aligned space and returns its offset.
    fn reserve(&mut self, size: usize, alignment: usize) -> Result<usize, PeError> {
        let offset = self.align(alignment)?;
        let end = offset.checked_add(size).ok_or(PeError::Overflow {
            field: "section payload size",
        })?;
        self.data.resize(end, 0);
        Ok(offset)
    }

    /// Appends aligned bytes and returns their offset.
    fn append(&mut self, bytes: &[u8], alignment: usize) -> Result<usize, PeError> {
        let offset = self.reserve(bytes.len(), alignment)?;
        self.write_at(offset, bytes)?;
        Ok(offset)
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), PeError> {
        let end = offset.checked_add(bytes.len()).ok_or(PeError::Overflow {
            field: "section payload size",
        })?;
        self.data
            .get_mut(offset..end)
            .ok_or(PeError::Overflow {
                field: "section payload write",
            })?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn align(&mut self, alignment: usize) -> Result<usize, PeError> {
        let aligned = self
            .data
            .len()
            .checked_next_multiple_of(alignment.max(1))
            .ok_or(PeError::Overflow {
                field: "section payload alignment",
            })?;
        self.data.resize(aligned, 0);
        Ok(aligned)
    }

    /// The RVA a payload offset will have once the section is mapped.
    fn rva_of(&self, offset: usize) -> Result<u32, PeError> {
        u32::try_from(offset)
            .ok()
            .and_then(|offset| self.section_rva.checked_add(offset))
            .ok_or(PeError::Overflow {
                field: "payload RVA",
            })
    }

    fn finish(self) -> Vec<u8> {
        self.data
    }
}

/// Narrows a payload offset to the width a directory entry stores.
///
/// The payload cannot exceed `u32::MAX` — `build_with_section` rejects that — but
/// the conversion is checked here anyway, so no caller has to reason across
/// functions to know the offset was not silently truncated.
fn payload_offset(offset: usize) -> Result<u32, PeError> {
    u32::try_from(offset).map_err(|_| PeError::Overflow {
        field: "directory payload offset",
    })
}

/// The RVA the next appended section will receive.
///
/// It is derived the same way [`build_with_section`] derives it, so a payload
/// containing addresses inside itself can be built before the section exists.
/// A disagreement would still be caught: the reparsed directory models would no
/// longer match the ones the caller planned.
pub(crate) fn planned_section_rva(pe: &PeFile) -> Result<u32, PeError> {
    validate_rewrite_alignment_profile(pe)?;
    let expected = expected_size_of_image(pe, pe.optional.section_alignment)?;
    if pe.optional.size_of_image != expected {
        return Err(PeError::UnsupportedRewriteLayout {
            reason: "SizeOfImage does not match the existing section layout",
        });
    }
    Ok(pe.optional.size_of_image)
}

pub(crate) fn build_with_section(
    original: &[u8],
    pe: &PeFile,
    section: NewSection<'_>,
    placements: &[DirectoryPlacement],
    models: ExpectedModels,
) -> Result<(Vec<u8>, ExpectedLayout), PeError> {
    let name = validate_name(section.name)?;
    if section.data.is_empty() {
        return Err(PeError::EmptySection);
    }
    let data_len = PeError::u32_len(section.data.len(), "new section data length")?;

    if pe
        .data_directory(directory::SECURITY)
        .is_some_and(|entry| entry.is_present())
    {
        return Err(PeError::CertificateTablePresent);
    }
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && pe.features.control_flow_guard {
        return Err(PeError::ControlFlowGuardUnsupported);
    }

    let nt_offset = u64::from(pe.dos.e_lfanew);
    let coff_offset = nt_offset.checked_add(4).ok_or(PeError::Overflow {
        field: "COFF header offset",
    })?;
    let optional_offset = coff_offset.checked_add(20).ok_or(PeError::Overflow {
        field: "optional header offset",
    })?;
    let section_table_offset = optional_offset
        .checked_add(u64::from(pe.coff.size_of_optional_header))
        .ok_or(PeError::Overflow {
            field: "section table offset",
        })?;
    let section_count = pe
        .coff
        .number_of_sections
        .checked_add(1)
        .ok_or(PeError::TooManySections)?;
    if section_count > MAX_IMAGE_SECTIONS {
        return Err(PeError::TooManySections);
    }
    let slot_offset = section_table_offset
        .checked_add(
            u64::from(pe.coff.number_of_sections)
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or(PeError::Overflow {
                    field: "section header offset",
                })?,
        )
        .ok_or(PeError::Overflow {
            field: "section header offset",
        })?;
    let slot_end = slot_offset
        .checked_add(SECTION_HEADER_SIZE)
        .ok_or(PeError::Overflow {
            field: "section header end",
        })?;
    let first_raw_offset = pe
        .sections
        .iter()
        .filter(|existing| existing.size_of_raw_data != 0)
        .map(|existing| existing.pointer_to_raw_data.get())
        .min()
        .unwrap_or(u64::from(pe.optional.size_of_headers));
    let header_limit = u64::from(pe.optional.size_of_headers).min(first_raw_offset);
    if slot_end > header_limit {
        return Err(PeError::NoSectionHeaderSpace {
            required_end: slot_end,
            limit: header_limit,
        });
    }
    reject_directory_slot_overlap(pe, slot_offset, slot_end)?;
    let slot = slice(original, slot_offset, SECTION_HEADER_SIZE)?;
    if slot.iter().any(|byte| *byte != 0) {
        return Err(PeError::SectionHeaderSlotNotEmpty {
            offset: slot_offset,
        });
    }

    let last_raw_end = pe
        .sections
        .iter()
        .filter(|existing| existing.size_of_raw_data != 0)
        .try_fold(
            u64::from(pe.optional.size_of_headers),
            |maximum, existing| {
                let end = existing.raw_end().ok_or(PeError::Overflow {
                    field: "existing section raw end",
                })?;
                Ok::<u64, PeError>(maximum.max(end))
            },
        )?;
    let file_len = original.len() as u64;
    if file_len > last_raw_end {
        return Err(PeError::OverlayPresent {
            offset: last_raw_end,
            size: file_len - last_raw_end,
        });
    }
    if file_len < last_raw_end {
        return Err(PeError::UnsupportedRewriteLayout {
            reason: "section raw data extends beyond the input",
        });
    }

    validate_rewrite_alignment_profile(pe)?;
    let file_alignment = pe.optional.file_alignment;
    let section_alignment = pe.optional.section_alignment;
    let expected_image_size = expected_size_of_image(pe, section_alignment)?;
    if pe.optional.size_of_image != expected_image_size {
        return Err(PeError::UnsupportedRewriteLayout {
            reason: "SizeOfImage does not match the existing section layout",
        });
    }

    let raw_offset = align_up_u64(file_len, u64::from(file_alignment), "new raw offset")?;
    let raw_size = align_up_u32(data_len, file_alignment, "new raw size")?;
    let virtual_address = pe.optional.size_of_image;
    let virtual_end = virtual_address
        .checked_add(data_len)
        .ok_or(PeError::Overflow {
            field: "new section virtual end",
        })?;
    let size_of_image = align_up_u32(virtual_end, section_alignment, "SizeOfImage")?;
    let raw_offset_u32 = u32::try_from(raw_offset).map_err(|_| PeError::Overflow {
        field: "new section PointerToRawData",
    })?;
    let output_len = raw_offset
        .checked_add(u64::from(raw_size))
        .ok_or(PeError::Overflow {
            field: "output file size",
        })?;
    let output_len = usize::try_from(output_len).map_err(|_| PeError::Overflow {
        field: "output allocation size",
    })?;

    let directories_offset = optional_offset
        .checked_add(crate::optional_header_fixed_size(pe.optional.magic))
        .ok_or(PeError::Overflow {
            field: "data directory offset",
        })?;
    let directories = plan_directories(pe, placements, virtual_address, data_len)?;

    let aggregate_offset = aggregate_size_offset(section.characteristics, optional_offset)?;
    let old_aggregate = le_u32(slice(original, aggregate_offset, 4)?, 0);
    let new_aggregate = old_aggregate
        .checked_add(raw_size)
        .ok_or(PeError::Overflow {
            field: "optional header aggregate section size",
        })?;

    let mut output = original.to_vec();
    output.resize(output_len, 0);
    let payload_start = usize::try_from(raw_offset).map_err(|_| PeError::Overflow {
        field: "new section payload offset",
    })?;
    let payload_end = payload_start
        .checked_add(section.data.len())
        .ok_or(PeError::Overflow {
            field: "new section payload end",
        })?;
    output[payload_start..payload_end].copy_from_slice(section.data);

    write_section_header(
        &mut output,
        slot_offset,
        name,
        data_len,
        virtual_address,
        raw_size,
        raw_offset_u32,
        section.characteristics,
    )?;
    write_u16(&mut output, coff_offset + 2, section_count)?;
    write_u32(&mut output, aggregate_offset, new_aggregate)?;
    write_u32(&mut output, optional_offset + 56, size_of_image)?;

    for placement in placements {
        let entry = directories_offset
            .checked_add(placement.directory as u64 * DIRECTORY_ENTRY_SIZE)
            .ok_or(PeError::Overflow {
                field: "data directory entry offset",
            })?;
        let rva = virtual_address
            .checked_add(placement.offset)
            .ok_or(PeError::Overflow {
                field: "placed directory RVA",
            })?;
        write_u32(&mut output, entry, rva)?;
        write_u32(&mut output, entry + 4, placement.size)?;
    }

    let checksum_offset = optional_offset.checked_add(64).ok_or(PeError::Overflow {
        field: "checksum offset",
    })?;
    write_u32(&mut output, checksum_offset, 0)?;
    let checksum = pe_checksum(&output, checksum_offset)?;
    write_u32(&mut output, checksum_offset, checksum)?;

    let expected = ExpectedLayout {
        section_table_offset,
        old_section_count: pe.sections.len(),
        section_count,
        name: section.name.to_owned(),
        virtual_size: data_len,
        virtual_address,
        raw_size,
        raw_offset: raw_offset_u32,
        characteristics: section.characteristics,
        size_of_image,
        directories,
        models,
    };
    Ok((output, expected))
}

/// Computes how the whole data directory array must read after the rewrite.
///
/// Returning the full array — not just the changed entries — is what lets
/// verification assert that nothing else moved.
fn plan_directories(
    pe: &PeFile,
    placements: &[DirectoryPlacement],
    section_rva: u32,
    section_size: u32,
) -> Result<Vec<(u64, u32)>, PeError> {
    let mut planned: Vec<(u64, u32)> = pe
        .data_directories
        .iter()
        .map(|entry| (entry.address.raw(), entry.size))
        .collect();

    for (index, placement) in placements.iter().enumerate() {
        if placement.directory == directory::SECURITY {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the certificate table is addressed by file offset, not by RVA",
            });
        }
        if placement.directory >= planned.len() {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the image declares no data directory slot for this placement",
            });
        }
        if placements[..index]
            .iter()
            .any(|earlier| earlier.directory == placement.directory)
        {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "two placements claim the same data directory",
            });
        }
        if placement.size == 0 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "a placed directory must describe at least one byte",
            });
        }
        let end = placement
            .offset
            .checked_add(placement.size)
            .ok_or(PeError::Overflow {
                field: "placed directory range",
            })?;
        if end > section_size {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "a placed directory does not fit inside the new section",
            });
        }
        let rva = section_rva
            .checked_add(placement.offset)
            .ok_or(PeError::Overflow {
                field: "placed directory RVA",
            })?;
        planned[placement.directory] = (u64::from(rva), placement.size);
    }
    Ok(planned)
}

pub(crate) fn verify_candidate(
    original: &[u8],
    candidate: &[u8],
    previous: &PeFile,
    parsed: &PeFile,
    expected: &ExpectedLayout,
) -> Result<(), PeError> {
    let failed = |reason| PeError::CandidateVerificationFailed { reason };
    if parsed.coff.number_of_sections != expected.section_count
        || parsed.sections.len() != expected.old_section_count + 1
    {
        return Err(failed("section count differs from the layout plan"));
    }

    let old_headers_size = u64::try_from(expected.old_section_count)
        .ok()
        .and_then(|count| count.checked_mul(SECTION_HEADER_SIZE))
        .ok_or_else(|| failed("old section-header range overflows"))?;
    let old_headers = slice(original, expected.section_table_offset, old_headers_size)
        .map_err(|_| failed("old section headers are unavailable in the input"))?;
    let candidate_old_headers =
        slice(candidate, expected.section_table_offset, old_headers_size)
            .map_err(|_| failed("old section headers are unavailable in the candidate"))?;
    if candidate_old_headers != old_headers {
        return Err(failed("an existing section header changed"));
    }

    let section = parsed
        .sections
        .last()
        .ok_or_else(|| failed("new section is missing"))?;
    if section.name != expected.name {
        return Err(failed("new section name differs from the layout plan"));
    }
    if section.virtual_address.get() != expected.virtual_address {
        return Err(failed("new section RVA differs from the layout plan"));
    }
    if section.virtual_size != expected.virtual_size {
        return Err(failed(
            "new section virtual size differs from the layout plan",
        ));
    }
    if section.pointer_to_raw_data.get() != u64::from(expected.raw_offset) {
        return Err(failed(
            "new section raw offset differs from the layout plan",
        ));
    }
    if section.size_of_raw_data != expected.raw_size {
        return Err(failed("new section raw size differs from the layout plan"));
    }
    if section.characteristics != expected.characteristics {
        return Err(failed(
            "new section characteristics differ from the layout plan",
        ));
    }
    if parsed.optional.size_of_image != expected.size_of_image {
        return Err(failed("SizeOfImage differs from the layout plan"));
    }

    // Every directory entry must read exactly as planned: the placed ones point
    // into the new section, all others are untouched
    if parsed.data_directories.len() != expected.directories.len() {
        return Err(failed("the data directory count changed"));
    }
    for (entry, (address, size)) in parsed.data_directories.iter().zip(&expected.directories) {
        if entry.address.raw() != *address || entry.size != *size {
            return Err(failed(
                "a data directory entry differs from the layout plan",
            ));
        }
    }

    // Reparsing proves the bytes are readable; comparing the models proves the
    // rewrite preserved their meaning. An untouched directory has to come back
    // identical, and a rewritten one has to match what the caller planned.
    if parsed.base_relocations.as_ref()
        != expected
            .models
            .relocations
            .as_ref()
            .or(previous.base_relocations.as_ref())
    {
        return Err(failed("the base relocation model differs from the plan"));
    }
    if parsed.tls.as_ref() != expected.models.tls.as_ref().or(previous.tls.as_ref()) {
        return Err(failed("the TLS model differs from the plan"));
    }
    if parsed.exception_table.as_ref()
        != expected
            .models
            .exception
            .as_ref()
            .or(previous.exception_table.as_ref())
    {
        return Err(failed("the exception model differs from the plan"));
    }
    // No operation rewrites imports or exports, so they must come back identical
    if parsed.imports != previous.imports {
        return Err(failed("the import model changed"));
    }
    if parsed.exports != previous.exports {
        return Err(failed("the export model changed"));
    }
    Ok(())
}

fn reject_directory_slot_overlap(
    pe: &PeFile,
    slot_start: u64,
    slot_end: u64,
) -> Result<(), PeError> {
    for (index, entry) in pe.data_directories.iter().copied().enumerate() {
        if !entry.is_present() || index == directory::SECURITY {
            continue;
        }
        let rva = entry
            .address
            .rva()
            .ok_or(PeError::UnsupportedRewriteLayout {
                reason: "an RVA data directory has a non-RVA address",
            })?;
        let offset = crate::rva_range_to_offset_in(
            &pe.sections,
            pe.optional.size_of_headers,
            rva,
            entry.size,
        )
        .ok_or(PeError::UnsupportedRewriteLayout {
            reason: "a data directory is not fully backed by file data",
        })?
        .get();
        let end = offset
            .checked_add(u64::from(entry.size))
            .ok_or(PeError::Overflow {
                field: "data directory file range",
            })?;
        if offset < slot_end && slot_start < end {
            return Err(PeError::HeaderDirectoryOverlapsSlot {
                directory: index,
                offset,
            });
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<[u8; 8], PeError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(PeError::InvalidSectionName {
            reason: "name is empty",
        });
    }
    if bytes.len() > 8 {
        return Err(PeError::InvalidSectionName {
            reason: "UTF-8 encoding exceeds eight bytes",
        });
    }
    if bytes.contains(&0) {
        return Err(PeError::InvalidSectionName {
            reason: "name contains a NUL byte",
        });
    }
    let mut encoded = [0u8; 8];
    encoded[..bytes.len()].copy_from_slice(bytes);
    Ok(encoded)
}

/// Rejects alignment profiles this writer cannot lay out.
///
/// `PeFile::parse` already guarantees that both alignments are powers of two,
/// that they are mutually compatible, and that every existing section and
/// `SizeOfImage` respect them. What remains is a writer policy: below a page the
/// loader maps the file one-to-one, so a section's RVA must equal its raw
/// offset — an invariant the append-only layout below does not maintain.
fn validate_rewrite_alignment_profile(pe: &PeFile) -> Result<(), PeError> {
    if pe.optional.section_alignment < crate::PAGE_SIZE {
        return Err(PeError::UnsupportedRewriteLayout {
            reason: "low-alignment images are mapped 1:1 and are not supported",
        });
    }
    Ok(())
}

fn expected_size_of_image(pe: &PeFile, alignment: u32) -> Result<u32, PeError> {
    let max_end =
        pe.sections
            .iter()
            .try_fold(pe.optional.size_of_headers, |maximum, section| {
                let end = section.virtual_end().ok_or(PeError::Overflow {
                    field: "existing section virtual end",
                })?;
                Ok::<u32, PeError>(maximum.max(end))
            })?;
    align_up_u32(max_end, alignment, "existing SizeOfImage")
}

fn aggregate_size_offset(characteristics: u32, optional_offset: u64) -> Result<u64, PeError> {
    let content_type = characteristics
        & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA);

    let field_delta = match content_type {
        IMAGE_SCN_CNT_CODE => 4,
        IMAGE_SCN_CNT_INITIALIZED_DATA => 8,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA => {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "initialized payload cannot be emitted as uninitialized data",
            });
        }
        _ => {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "new section must have exactly one supported content-type flag",
            });
        }
    };

    optional_offset
        .checked_add(field_delta)
        .ok_or(PeError::Overflow {
            field: "aggregate section size offset",
        })
}

#[allow(clippy::too_many_arguments)]
fn write_section_header(
    output: &mut [u8],
    offset: u64,
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) -> Result<(), PeError> {
    slice_mut(output, offset, SECTION_HEADER_SIZE)?.fill(0);
    slice_mut(output, offset, 8)?.copy_from_slice(&name);
    write_u32(output, offset + 8, virtual_size)?;
    write_u32(output, offset + 12, virtual_address)?;
    write_u32(output, offset + 16, raw_size)?;
    write_u32(output, offset + 20, raw_offset)?;
    write_u32(output, offset + 36, characteristics)
}

/// [`align_up_u64`] narrowed back to the `u32` a header field holds.
///
/// Rounding in the wider type first means a result that no longer fits is
/// reported as the same `Overflow` the 32-bit arithmetic would have produced.
fn align_up_u32(value: u32, alignment: u32, field: &'static str) -> Result<u32, PeError> {
    let aligned = align_up_u64(u64::from(value), u64::from(alignment), field)?;
    u32::try_from(aligned).map_err(|_| PeError::Overflow { field })
}

/// Rounds `value` up to the next multiple of `alignment`.
fn align_up_u64(value: u64, alignment: u64, field: &'static str) -> Result<u64, PeError> {
    if alignment == 0 {
        return Err(PeError::InvalidAlignment { field, value: 0 });
    }
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|aligned| aligned & !mask)
        .ok_or(PeError::Overflow { field })
}

pub(crate) fn pe_checksum(data: &[u8], checksum_offset: u64) -> Result<u32, PeError> {
    let checksum_start = usize::try_from(checksum_offset).map_err(|_| PeError::Overflow {
        field: "checksum field offset",
    })?;
    let checksum_end = checksum_start.checked_add(4).ok_or(PeError::Overflow {
        field: "checksum field end",
    })?;
    if checksum_end > data.len() {
        return Err(PeError::Truncated {
            offset: checksum_offset,
            needed: 4,
            available: data.len() as u64,
        });
    }

    let masked_byte = |offset: usize| {
        if offset >= checksum_start && offset < checksum_end {
            0
        } else {
            data[offset]
        }
    };

    let mut sum = 0u64;
    let mut offset = 0usize;
    while offset + 1 < data.len() {
        let word = u16::from_le_bytes([masked_byte(offset), masked_byte(offset + 1)]);
        sum += u64::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
        offset += 2;
    }
    if offset < data.len() {
        sum += u64::from(masked_byte(offset));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;
    let folded = sum & 0xffff;
    let length = PeError::u32_len(data.len(), "checksum file length")?;
    Ok((folded as u32).wrapping_add(length))
}

fn write_u16(data: &mut [u8], offset: u64, value: u16) -> Result<(), PeError> {
    slice_mut(data, offset, 2)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: u64, value: u32) -> Result<(), PeError> {
    slice_mut(data, offset, 4)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        minimal_pe64, put_u16, put_u32, set_directory, PAYLOAD_RVA, PE64_SECTION_TABLE,
    };
    use crate::PeImage;

    const PE64_BASE: u64 = 0x1_4000_0000;
    /// File offset of the payload section's raw data.
    const PAYLOAD_OFFSET: usize = 0x600;
    /// RVA the writer will give the first appended section.
    const APPENDED_RVA: u32 = 0x3000;
    /// File offset the first appended section's raw data lands at.
    const APPENDED_OFFSET: u64 = 0x1600;

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// One `IMAGE_BASE_RELOCATION` block covering `page`.
    fn reloc_block(page: u32, entries: &[(u16, u16)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&page.to_le_bytes());
        bytes.extend_from_slice(&((8 + entries.len() * 2) as u32).to_le_bytes());
        for (kind, offset) in entries {
            bytes.extend_from_slice(&((kind << 12) | offset).to_le_bytes());
        }
        bytes
    }

    /// A PE32+ image with a one-page `.rdata` payload section and enough header
    /// room for several appended sections.
    fn image() -> Vec<u8> {
        let mut data = minimal_pe64(0x400);
        data.resize(0x1600, 0);
        // .text's raw data follows the enlarged header region
        put_u32(&mut data, PE64_SECTION_TABLE + 20, 0x400);

        put_u16(&mut data, 0x46, 2); // NumberOfSections
        let s = PE64_SECTION_TABLE + 40;
        data[s..s + 6].copy_from_slice(b".rdata");
        put_u32(&mut data, s + 8, 0x1000); // VirtualSize
        put_u32(&mut data, s + 12, PAYLOAD_RVA);
        put_u32(&mut data, s + 16, 0x1000); // SizeOfRawData
        put_u32(&mut data, s + 20, PAYLOAD_OFFSET as u32);
        put_u32(&mut data, s + 36, PAYLOAD_CHARACTERISTICS);
        put_u32(&mut data, 0x58 + 56, 0x3000); // SizeOfImage
        data
    }

    /// Writes `bytes` into the payload section at `offset` and returns its RVA.
    fn place(data: &mut [u8], offset: usize, bytes: &[u8]) -> u32 {
        data[PAYLOAD_OFFSET + offset..PAYLOAD_OFFSET + offset + bytes.len()].copy_from_slice(bytes);
        PAYLOAD_RVA + offset as u32
    }

    /// An image whose relocation directory holds a single `.text` fixup.
    fn image_with_relocations() -> Vec<u8> {
        let mut data = image();
        let table = reloc_block(0x1000, &[(10, 0)]);
        let rva = place(&mut data, 0, &table);
        set_directory(&mut data, directory::BASERELOC, rva, table.len() as u32);
        data
    }

    /// An image with relocations, a TLS directory at payload offset 0x100 and a
    /// one-entry callback array at 0x200.
    fn image_with_tls() -> Vec<u8> {
        let mut data = image_with_relocations();
        put_u64(&mut data, PAYLOAD_OFFSET + 0x100, PE64_BASE + 0x1000); // start
        put_u64(&mut data, PAYLOAD_OFFSET + 0x108, PE64_BASE + 0x1100); // end
        put_u64(
            &mut data,
            PAYLOAD_OFFSET + 0x110,
            PE64_BASE + u64::from(PAYLOAD_RVA) + 0x400,
        ); // index
        put_u64(
            &mut data,
            PAYLOAD_OFFSET + 0x118,
            PE64_BASE + u64::from(PAYLOAD_RVA) + 0x200,
        ); // callbacks
        put_u64(&mut data, PAYLOAD_OFFSET + 0x200, PE64_BASE + 0x1010);
        set_directory(&mut data, directory::TLS, PAYLOAD_RVA + 0x100, 40);
        data
    }

    /// An image with one runtime function whose unwind info is at 0x100.
    fn image_with_exception_table() -> Vec<u8> {
        let mut data = image();
        place(&mut data, 0x100, &[1, 0, 0, 0]);
        let mut array = Vec::new();
        array.extend_from_slice(&0x1000u32.to_le_bytes());
        array.extend_from_slice(&0x1010u32.to_le_bytes());
        array.extend_from_slice(&(PAYLOAD_RVA + 0x100).to_le_bytes());
        let rva = place(&mut data, 0, &array);
        set_directory(&mut data, directory::EXCEPTION, rva, array.len() as u32);
        data
    }

    #[test]
    fn extends_the_relocation_table_and_repoints_the_directory() {
        let original = image_with_relocations();
        let mut owned = PeImage::from_bytes(original.clone()).expect("image is valid");
        owned
            .extend_base_relocations(
                ".vmprel",
                &[Fixup {
                    rva: Rva(0x1010),
                    kind: FixupKind::Dir64,
                }],
            )
            .expect("the table must be extendable");

        let pe = owned.pe();
        let table = pe
            .base_relocations
            .as_ref()
            .expect("the directory is present");
        assert_eq!(
            table.fixups(),
            [
                Fixup {
                    rva: Rva(0x1000),
                    kind: FixupKind::Dir64
                },
                Fixup {
                    rva: Rva(0x1010),
                    kind: FixupKind::Dir64
                },
            ]
        );

        let entry = pe
            .data_directory(directory::BASERELOC)
            .expect("the entry exists");
        assert_eq!(entry.address.raw(), u64::from(APPENDED_RVA));
        assert_eq!(entry.size, 12, "two fixups fill one block exactly");
        assert_eq!(pe.sections.last().expect("new section").name, ".vmprel");

        // The old table's bytes are still in the file, merely unreferenced
        assert_eq!(
            &owned.bytes()[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 12],
            &original[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 12]
        );
    }

    #[test]
    fn moving_tls_relocates_its_address_fields_and_callbacks() {
        let mut owned = PeImage::from_bytes(image_with_tls()).expect("image is valid");
        owned
            .relocate_tls(".vmptls", &[Rva(0x1020)])
            .expect("TLS must be movable");

        let pe = owned.pe();
        let tls = pe.tls.as_ref().expect("the directory is present");
        assert_eq!(tls.rva, Rva(APPENDED_RVA));
        assert_eq!(tls.raw_data_start.rva, Some(Rva(0x1000)));
        assert_eq!(
            tls.address_of_callbacks.rva,
            Some(Rva(APPENDED_RVA + 0x28)),
            "the array follows the 40-byte structure"
        );
        assert_eq!(tls.callbacks, [Rva(0x1010), Rva(0x1020)]);

        let entry = pe.data_directory(directory::TLS).expect("the entry exists");
        assert_eq!(entry.address.raw(), u64::from(APPENDED_RVA));
        assert_eq!(entry.size, 40);

        // Four address fields plus two callback slots need fixups, on top of the
        // one the image already had
        let table = pe
            .base_relocations
            .as_ref()
            .expect("relocations are present");
        let addresses: Vec<u32> = table.fixups().iter().map(|fixup| fixup.rva.get()).collect();
        assert_eq!(
            addresses,
            [
                0x1000,
                APPENDED_RVA,
                APPENDED_RVA + 8,
                APPENDED_RVA + 16,
                APPENDED_RVA + 24,
                APPENDED_RVA + 0x28,
                APPENDED_RVA + 0x30,
            ]
        );
        let relocations = pe
            .data_directory(directory::BASERELOC)
            .expect("the entry exists");
        assert_eq!(
            relocations.address.raw(),
            u64::from(APPENDED_RVA + 0x40),
            "the table follows the callback array"
        );
    }

    /// The PE32 counterpart of [`image_with_tls`]: four-byte addresses, a
    /// 24-byte directory and `HIGHLOW` fixups.
    fn pe32_image_with_tls() -> Vec<u8> {
        const PE32_BASE: u32 = 0x0040_0000;
        let mut data = crate::testing::minimal_pe32(0x400);
        data.resize(0x1600, 0);
        let table = crate::testing::PE32_SECTION_TABLE;
        put_u32(&mut data, table + 20, 0x400); // .text PointerToRawData

        put_u16(&mut data, 0x46, 2);
        let s = table + 40;
        data[s..s + 6].copy_from_slice(b".rdata");
        put_u32(&mut data, s + 8, 0x1000);
        put_u32(&mut data, s + 12, PAYLOAD_RVA);
        put_u32(&mut data, s + 16, 0x1000);
        put_u32(&mut data, s + 20, PAYLOAD_OFFSET as u32);
        put_u32(&mut data, s + 36, PAYLOAD_CHARACTERISTICS);
        put_u32(&mut data, 0x58 + 56, 0x3000); // SizeOfImage

        let relocations = reloc_block(0x1000, &[(3, 0)]);
        place(&mut data, 0, &relocations);
        set_directory(
            &mut data,
            directory::BASERELOC,
            PAYLOAD_RVA,
            relocations.len() as u32,
        );

        put_u32(&mut data, PAYLOAD_OFFSET + 0x100, PE32_BASE + 0x1000); // start
        put_u32(&mut data, PAYLOAD_OFFSET + 0x104, PE32_BASE + 0x1100); // end
        put_u32(
            &mut data,
            PAYLOAD_OFFSET + 0x108,
            PE32_BASE + PAYLOAD_RVA + 0x400,
        ); // index
        put_u32(
            &mut data,
            PAYLOAD_OFFSET + 0x10c,
            PE32_BASE + PAYLOAD_RVA + 0x200,
        ); // callbacks
        put_u32(&mut data, PAYLOAD_OFFSET + 0x200, PE32_BASE + 0x1010);
        set_directory(&mut data, directory::TLS, PAYLOAD_RVA + 0x100, 24);
        data
    }

    #[test]
    fn moving_tls_in_a_pe32_image_uses_narrow_addresses_and_highlow_fixups() {
        let mut owned = PeImage::from_bytes(pe32_image_with_tls()).expect("image is valid");
        owned
            .relocate_tls(".vmptls", &[Rva(0x1020)])
            .expect("TLS must be movable");

        let pe = owned.pe();
        let tls = pe.tls.as_ref().expect("the directory is present");
        assert_eq!(tls.rva, Rva(APPENDED_RVA));
        assert_eq!(tls.raw_data_start.rva, Some(Rva(0x1000)));
        assert_eq!(
            tls.address_of_callbacks.rva,
            Some(Rva(APPENDED_RVA + 24)),
            "the array follows the 24-byte PE32 structure"
        );
        assert_eq!(tls.callbacks, [Rva(0x1010), Rva(0x1020)]);
        assert_eq!(
            pe.data_directory(directory::TLS).expect("entry").size,
            24,
            "the PE32 directory is 24 bytes"
        );

        let table = pe
            .base_relocations
            .as_ref()
            .expect("relocations are present");
        assert!(
            table
                .fixups()
                .iter()
                .all(|fixup| fixup.kind == FixupKind::HighLow),
            "a PE32 image relocates four-byte pointers"
        );
        let addresses: Vec<u32> = table.fixups().iter().map(|fixup| fixup.rva.get()).collect();
        assert_eq!(
            addresses,
            [
                0x1000,
                APPENDED_RVA,
                APPENDED_RVA + 4,
                APPENDED_RVA + 8,
                APPENDED_RVA + 12,
                APPENDED_RVA + 24,
                APPENDED_RVA + 28,
            ],
            "four address fields at four-byte spacing plus two callback slots"
        );
    }

    #[test]
    fn a_repeated_tls_move_keeps_the_abandoned_copys_fixups() {
        // Pins the documented contract of `relocate_tls`: it is meant to be
        // applied once, and a second application leaves the first copy's fixups
        // in place rather than withdrawing metadata it inherited
        let mut owned = PeImage::from_bytes(image_with_tls()).expect("image is valid");
        let count = |image: &PeImage| {
            image
                .pe()
                .base_relocations
                .as_ref()
                .expect("relocations are present")
                .len()
        };
        assert_eq!(count(&owned), 1);

        owned.relocate_tls(".vmptls1", &[]).expect("first move");
        // One fixup per non-zero address field plus the single existing callback
        assert_eq!(count(&owned), 6);
        let first = owned.pe().tls.as_ref().expect("present").rva;

        owned.relocate_tls(".vmptls2", &[]).expect("second move");
        assert_eq!(
            count(&owned),
            11,
            "the abandoned copy's fixups are kept, so the table grows again"
        );
        assert_ne!(
            owned.pe().tls.as_ref().expect("present").rva,
            first,
            "the directory really did move again"
        );
        // The abandoned fixups still target mapped memory, so the image is valid
        PeFile::parse(owned.bytes()).expect("output must reparse");
    }

    #[test]
    fn moving_tls_without_relocations_adds_no_fixups() {
        let mut data = image_with_tls();
        // Drop the relocation directory: the loader cannot move such an image, so
        // the absolute addresses stay valid where they are written
        set_directory(&mut data, directory::BASERELOC, 0, 0);
        let mut owned = PeImage::from_bytes(data).expect("image is valid");
        owned
            .relocate_tls(".vmptls", &[])
            .expect("a non-relocatable image still allows the move");

        assert_eq!(owned.pe().base_relocations, None);
        assert_eq!(
            owned.pe().tls.as_ref().expect("present").rva,
            Rva(APPENDED_RVA)
        );
    }

    #[test]
    fn extends_the_exception_table_with_new_unwind_info() {
        let mut owned = PeImage::from_bytes(image_with_exception_table()).expect("image is valid");
        owned
            .extend_exception_table(
                ".vmpexc",
                &[NewFunction {
                    begin: Rva(0x1020),
                    end: Rva(0x1030),
                    unwind: UnwindInfo::leaf(),
                }],
            )
            .expect("the table must be extendable");

        let pe = owned.pe();
        let table = pe
            .exception_table
            .as_ref()
            .expect("the directory is present");
        let functions: Vec<RuntimeFunction> = table.functions().collect();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].begin, Rva(0x1000));
        assert_eq!(
            functions[0].unwind_info,
            Rva(PAYLOAD_RVA + 0x100),
            "existing unwind info is left where it is"
        );
        assert_eq!(functions[1].begin, Rva(0x1020));
        assert_eq!(
            functions[1].unwind_info,
            Rva(APPENDED_RVA),
            "new unwind info precedes the array in the new section"
        );

        let entry = pe
            .data_directory(directory::EXCEPTION)
            .expect("the entry exists");
        assert_eq!(entry.address.raw(), u64::from(APPENDED_RVA + 4));
        assert_eq!(entry.size, 24);
    }

    #[test]
    fn a_plain_append_leaves_every_directory_entry_alone() {
        let original = image_with_tls();
        let before = PeFile::parse(&original).expect("image is valid");
        let mut owned = PeImage::from_bytes(original).expect("image is valid");
        owned
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1, 2, 3],
                characteristics: PAYLOAD_CHARACTERISTICS,
            })
            .expect("append must succeed");

        let after = owned.pe();
        assert_eq!(after.data_directories.len(), before.data_directories.len());
        for (old, new) in before.data_directories.iter().zip(&after.data_directories) {
            assert_eq!(new.address, old.address);
            assert_eq!(new.size, old.size);
        }
        assert_eq!(after.tls, before.tls);
        assert_eq!(after.base_relocations, before.base_relocations);
    }

    #[test]
    fn aggregate_section_size_accepts_the_exact_u32_boundary() {
        for (field_offset, characteristics) in [
            (
                0x58 + 4,
                IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            ),
            (0x58 + 8, PAYLOAD_CHARACTERISTICS),
        ] {
            let mut original = image();
            put_u32(&mut original, field_offset, u32::MAX - 0x200);
            let mut owned = PeImage::from_bytes(original).expect("boundary image is valid");

            owned
                .add_section(NewSection {
                    name: ".vmpdat",
                    data: &[1],
                    characteristics,
                })
                .expect("exact aggregate boundary must be accepted");

            assert_eq!(
                le_u32(&owned.bytes()[field_offset..field_offset + 4], 0),
                u32::MAX
            );
        }
    }

    #[test]
    fn aggregate_section_size_overflow_is_typed_and_atomic() {
        for (field_offset, characteristics) in [
            (
                0x58 + 4,
                IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            ),
            (0x58 + 8, PAYLOAD_CHARACTERISTICS),
        ] {
            let mut original = image();
            put_u32(&mut original, field_offset, u32::MAX - 0x1ff);
            let mut owned = PeImage::from_bytes(original).expect("overflow image is valid");
            let before = owned.bytes().to_vec();

            let error = owned
                .add_section(NewSection {
                    name: ".vmpdat",
                    data: &[1],
                    characteristics,
                })
                .expect_err("one over the aggregate boundary must fail");

            assert!(matches!(
                error,
                PeError::Overflow {
                    field: "optional header aggregate section size"
                }
            ));
            assert_eq!(
                owned.bytes(),
                before,
                "failed append must be byte-exact atomic"
            );
            assert_eq!(
                owned.pe().sections.len(),
                2,
                "parsed model must be unchanged"
            );
        }
    }

    #[test]
    fn rejects_placements_that_do_not_describe_the_new_section() {
        let cases = [
            DirectoryPlacement {
                directory: directory::SECURITY,
                offset: 0,
                size: 4,
            },
            DirectoryPlacement {
                directory: 40,
                offset: 0,
                size: 4,
            },
            DirectoryPlacement {
                directory: directory::DEBUG,
                offset: 0,
                size: 0,
            },
            DirectoryPlacement {
                directory: directory::DEBUG,
                offset: 2,
                size: 4,
            },
        ];
        for placement in cases {
            let mut owned = PeImage::from_bytes(image()).expect("image is valid");
            assert!(
                matches!(
                    owned.add_section_with_directories(
                        NewSection {
                            name: ".vmpdat",
                            data: &[1, 2, 3, 4],
                            characteristics: PAYLOAD_CHARACTERISTICS,
                        },
                        &[placement],
                    ),
                    Err(PeError::UnsupportedRewriteLayout { .. })
                ),
                "{placement:?} must be refused"
            );
            assert_eq!(owned.pe().sections.len(), 2, "the image is unchanged");
        }
    }

    #[test]
    fn rejects_two_placements_for_one_directory() {
        let mut owned = PeImage::from_bytes(image()).expect("image is valid");
        let placement = DirectoryPlacement {
            directory: directory::DEBUG,
            offset: 0,
            size: 2,
        };

        assert!(matches!(
            owned.add_section_with_directories(
                NewSection {
                    name: ".vmpdat",
                    data: &[1, 2, 3, 4],
                    characteristics: PAYLOAD_CHARACTERISTICS,
                },
                &[placement, placement],
            ),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "two placements claim the same data directory"
            })
        ));
    }

    #[test]
    fn refuses_to_make_a_non_relocatable_image_relocatable() {
        let mut owned = PeImage::from_bytes(image()).expect("image is valid");

        assert!(matches!(
            owned.extend_base_relocations(
                ".vmprel",
                &[Fixup {
                    rva: Rva(0x1000),
                    kind: FixupKind::Dir64,
                }],
            ),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
    }

    #[test]
    fn refuses_relocation_work_on_a_stripped_image() {
        let mut data = image_with_relocations();
        put_u16(&mut data, 0x44 + 18, IMAGE_FILE_RELOCS_STRIPPED);
        let mut owned = PeImage::from_bytes(data).expect("image is valid");

        assert!(matches!(
            owned.extend_base_relocations(
                ".vmprel",
                &[Fixup {
                    rva: Rva(0x1010),
                    kind: FixupKind::Dir64,
                }],
            ),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "the image declares its relocations stripped, so the loader ignores them"
            })
        ));
    }

    #[test]
    fn refuses_to_move_a_missing_tls_directory() {
        let mut owned = PeImage::from_bytes(image()).expect("image is valid");

        assert!(matches!(
            owned.relocate_tls(".vmptls", &[]),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "the image has no TLS directory to move"
            })
        ));
    }

    #[test]
    fn refuses_a_duplicate_tls_callback() {
        let mut owned = PeImage::from_bytes(image_with_tls()).expect("image is valid");

        assert!(matches!(
            owned.relocate_tls(".vmptls", &[Rva(0x1010)]),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "a TLS callback is already registered"
            })
        ));
    }

    #[test]
    fn refuses_unwind_info_that_cannot_be_re_emitted() {
        let mut owned = PeImage::from_bytes(image_with_exception_table()).expect("image is valid");
        let mut unwind = UnwindInfo::leaf();
        unwind.flags = crate::exception::UNW_FLAG_EHANDLER;
        unwind.handler = Some(Rva(0x1000));

        assert!(matches!(
            owned.extend_exception_table(
                ".vmpexc",
                &[NewFunction {
                    begin: Rva(0x1020),
                    end: Rva(0x1030),
                    unwind,
                }],
            ),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
    }

    /// An image carrying relocations, TLS and unwind data at once.
    fn image_with_all_directories() -> Vec<u8> {
        let mut data = image_with_tls();
        place(&mut data, 0x380, &[1, 0, 0, 0]);
        let mut array = Vec::new();
        array.extend_from_slice(&0x1000u32.to_le_bytes());
        array.extend_from_slice(&0x1010u32.to_le_bytes());
        array.extend_from_slice(&(PAYLOAD_RVA + 0x380).to_le_bytes());
        let rva = place(&mut data, 0x300, &array);
        set_directory(&mut data, directory::EXCEPTION, rva, array.len() as u32);
        data
    }

    /// Runs the full sequence of rewrites an image goes through.
    fn rewrite_everything(original: &[u8]) -> PeImage {
        let mut owned = PeImage::from_bytes(original.to_vec()).expect("image is valid");
        owned
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1, 2, 3],
                characteristics: PAYLOAD_CHARACTERISTICS,
            })
            .expect("plain append");
        owned
            .extend_base_relocations(
                ".vmprel",
                &[Fixup {
                    rva: Rva(0x1010),
                    kind: FixupKind::Dir64,
                }],
            )
            .expect("relocation rewrite");
        owned
            .relocate_tls(".vmptls", &[Rva(0x1020)])
            .expect("TLS move");
        owned
            .extend_exception_table(
                ".vmpexc",
                &[NewFunction {
                    begin: Rva(0x1020),
                    end: Rva(0x1030),
                    unwind: UnwindInfo::leaf(),
                }],
            )
            .expect("exception rewrite");
        owned
    }

    #[test]
    fn sequential_rewrites_keep_every_invariant() {
        let original = image_with_all_directories();
        let before = PeFile::parse(&original).expect("image is valid");
        let owned = rewrite_everything(&original);

        let pe = owned.pe();
        assert_eq!(pe.coff.number_of_sections, 6);
        assert_eq!(pe.sections.len(), 6);
        let appended: Vec<(&str, u32, u64)> = pe.sections[2..]
            .iter()
            .map(|section| {
                (
                    section.name.as_str(),
                    section.virtual_address.get(),
                    section.pointer_to_raw_data.get(),
                )
            })
            .collect();
        assert_eq!(
            appended,
            [
                (".vmpdat", 0x3000, APPENDED_OFFSET),
                (".vmprel", 0x4000, APPENDED_OFFSET + 0x200),
                (".vmptls", 0x5000, APPENDED_OFFSET + 0x400),
                (".vmpexc", 0x6000, APPENDED_OFFSET + 0x600),
            ],
            "each section is appended at the next aligned RVA and file offset"
        );
        assert_eq!(pe.optional.size_of_image, 0x7000);

        // Every original section header survives byte for byte
        assert_eq!(
            &owned.bytes()[PE64_SECTION_TABLE..PE64_SECTION_TABLE + 2 * 40],
            &original[PE64_SECTION_TABLE..PE64_SECTION_TABLE + 2 * 40]
        );
        for section in &before.sections {
            let start = section.pointer_to_raw_data.get() as usize;
            let end = start + section.size_of_raw_data as usize;
            assert_eq!(&owned.bytes()[start..end], &original[start..end]);
        }

        // Each rewritten directory ends up where the last operation put it
        assert_eq!(
            pe.data_directory(directory::TLS)
                .expect("entry")
                .address
                .raw(),
            0x5000
        );
        assert_eq!(
            pe.data_directory(directory::BASERELOC)
                .expect("entry")
                .address
                .raw(),
            0x5040
        );
        assert_eq!(
            pe.data_directory(directory::EXCEPTION)
                .expect("entry")
                .address
                .raw(),
            0x6004
        );

        // The models survive the whole sequence
        let tls = pe.tls.as_ref().expect("TLS is present");
        assert_eq!(tls.rva, Rva(0x5000));
        assert_eq!(tls.callbacks, [Rva(0x1010), Rva(0x1020)]);
        assert_eq!(
            pe.base_relocations
                .as_ref()
                .expect("relocations are present")
                .len(),
            8,
            "the original fixup, the added one, four TLS fields and two callbacks"
        );
        assert_eq!(
            pe.exception_table
                .as_ref()
                .expect("unwind data is present")
                .len(),
            2
        );

        // The final image is independently parseable and reproducible
        let reparsed = PeFile::parse(owned.bytes()).expect("output must reparse");
        assert_eq!(reparsed.tls, pe.tls);
        assert_eq!(reparsed.base_relocations, pe.base_relocations);
        assert_eq!(reparsed.exception_table, pe.exception_table);
        assert_eq!(
            rewrite_everything(&original).into_bytes(),
            owned.into_bytes(),
            "the same sequence must be byte-for-byte reproducible"
        );
    }

    #[test]
    fn a_late_reparse_failure_leaves_the_image_untouched() {
        let original = image_with_relocations();
        let mut owned = PeImage::from_bytes(original.clone()).expect("image is valid");

        // The candidate is built and written in full, then rejected when the
        // reparse tries to read the directory it now points at
        let result = owned.add_section_with_directories(
            NewSection {
                name: ".vmpbad",
                data: &[0xff; 16],
                characteristics: PAYLOAD_CHARACTERISTICS,
            },
            &[DirectoryPlacement {
                directory: directory::BASERELOC,
                offset: 0,
                size: 16,
            }],
        );
        assert!(
            matches!(
                result,
                Err(PeError::MalformedDirectory {
                    directory: directory::BASERELOC,
                    ..
                })
            ),
            "unexpected error: {result:?}"
        );

        assert_eq!(owned.bytes(), original);
        assert_eq!(owned.pe().sections.len(), 2);
        assert_eq!(
            owned
                .pe()
                .base_relocations
                .as_ref()
                .expect("relocations survive")
                .len(),
            1
        );
        // The image is still usable after the rejected mutation
        owned
            .add_section(NewSection {
                name: ".vmpdat",
                data: &[1],
                characteristics: PAYLOAD_CHARACTERISTICS,
            })
            .expect("a valid append still works");
    }

    #[test]
    fn a_late_verification_failure_leaves_the_image_untouched() {
        let original = image_with_relocations();
        let mut owned = PeImage::from_bytes(original.clone()).expect("image is valid");

        // A well-formed relocation table, but routed through the primitive, which
        // promises that no directory model changes meaning
        let table = reloc_block(0x1000, &[(10, 0), (10, 8)]);
        let result = owned.add_section_with_directories(
            NewSection {
                name: ".vmprel",
                data: &table,
                characteristics: PAYLOAD_CHARACTERISTICS,
            },
            &[DirectoryPlacement {
                directory: directory::BASERELOC,
                offset: 0,
                size: table.len() as u32,
            }],
        );
        assert!(
            matches!(
                result,
                Err(PeError::CandidateVerificationFailed {
                    reason: "the base relocation model differs from the plan"
                })
            ),
            "unexpected error: {result:?}"
        );

        assert_eq!(owned.bytes(), original);
        assert_eq!(owned.pe().sections.len(), 2);
    }

    #[test]
    fn directory_rewrites_stay_atomic_on_failure() {
        let original = image_with_tls();
        let mut owned = PeImage::from_bytes(original.clone()).expect("image is valid");
        // An oversized name fails after the models have been built
        assert!(owned.relocate_tls(".toolongname", &[]).is_err());

        assert_eq!(owned.bytes(), original);
        assert_eq!(owned.pe().sections.len(), 2);
        assert_eq!(
            owned.pe().tls.as_ref().expect("present").rva,
            Rva(PAYLOAD_RVA + 0x100)
        );
    }

    #[test]
    fn checksum_ignores_its_own_field_and_handles_odd_length() {
        let mut data = vec![1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd, 5];
        let first = pe_checksum(&data, 4).expect("checksum must compute");
        data[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let second = pe_checksum(&data, 4).expect("checksum must compute");
        assert_eq!(first, second);
    }

    #[test]
    fn checksum_matches_an_independent_even_length_aligned_vector() {
        let mut data = vec![
            0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40,
        ];
        assert_eq!(
            pe_checksum(&data, 4).expect("even checksum vector must compute"),
            0x0000_6650
        );

        data[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(
            pe_checksum(&data, 4).expect("stored checksum bytes must stay masked"),
            0x0000_6650
        );
    }

    #[test]
    fn checksum_masks_exact_field_bytes_at_an_odd_offset() {
        let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let baseline = pe_checksum(&data, 3).expect("checksum must compute");

        data[3..7].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let changed_field = pe_checksum(&data, 3).expect("checksum must compute");
        assert_eq!(baseline, changed_field, "checksum field bytes are excluded");

        data[7] ^= 0xff;
        let changed_data = pe_checksum(&data, 3).expect("checksum must compute");
        assert_ne!(
            changed_field, changed_data,
            "the byte immediately after the checksum field remains input data"
        );
    }
}
