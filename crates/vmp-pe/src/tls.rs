//! Thread local storage directory (`IMAGE_TLS_DIRECTORY32` / `..._64`).
//!
//! The four address fields are absolute virtual addresses rather than RVAs — the
//! only directory in the format that works that way — so the loader relies on
//! base relocations to fix them up when the image moves. The model stores them
//! as RVAs and remembers where each one lives inside the structure, which is
//! what lets the writer re-emit the directory at a new address together with the
//! relocations the moved copy needs.
//!
//! `StartAddressOfRawData` commonly points at a section with no raw data at all
//! (a `.tls` template is zero-filled), so address fields are required to be
//! mapped, not file-backed.

use crate::reader::{le_address, le_u32};
use crate::{directory, PeError, PeFile};
use vmp_types::{ImageBase, Rva};

/// `IMAGE_TLS_DIRECTORY32`: four 32-bit addresses plus two 32-bit words.
const SIZE_PE32: u32 = 24;
/// `IMAGE_TLS_DIRECTORY64`: four 64-bit addresses plus two 32-bit words.
const SIZE_PE32PLUS: u32 = 40;

/// One address field of the directory.
///
/// A zero field is "not present" and must not be relocated: adding the
/// relocation delta to zero would produce a wild pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsAddress {
    /// The target, or `None` when the field is zero.
    pub rva: Option<Rva>,
    /// Byte offset of the field inside the directory structure.
    pub field_offset: u32,
}

/// The parsed TLS directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory {
    /// RVA the directory itself is stored at.
    pub rva: Rva,
    pub raw_data_start: TlsAddress,
    pub raw_data_end: TlsAddress,
    pub address_of_index: TlsAddress,
    pub address_of_callbacks: TlsAddress,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    /// Callback entry points, in array order. Empty when the array is absent or
    /// immediately terminated.
    pub callbacks: Vec<Rva>,
}

impl TlsDirectory {
    /// Bytes the structure occupies for the image's bitness.
    pub const fn size_for(is_pe32_plus: bool) -> u32 {
        if is_pe32_plus {
            SIZE_PE32PLUS
        } else {
            SIZE_PE32
        }
    }

    /// Parses the TLS directory, or returns `None` when the image declares none.
    ///
    /// The declared directory size is only used to decide presence: linkers
    /// disagree about it and the loader reads the fixed structure regardless, so
    /// the structure is required to be mapped at its own full length instead.
    pub fn parse(pe: &PeFile, data: &[u8]) -> Result<Option<TlsDirectory>, PeError> {
        let Some(entry) = pe.data_directory(directory::TLS) else {
            return Ok(None);
        };
        if !entry.is_present() {
            return Ok(None);
        }
        let rva = entry
            .address
            .rva()
            .ok_or(malformed("entry is not an RVA"))?;

        let plus = pe.optional.is_pe32_plus();
        let bytes = pe
            .mapped_range(data, rva, Self::size_for(plus))
            .map_err(|_| malformed("the structure is not backed by file data"))?;

        let mut addresses = [TlsAddress::default(); 4];
        let address_width = u32::from(pe.architecture.pointer_width());
        for (index, address) in addresses.iter_mut().enumerate() {
            let field_offset = index as u32 * address_width;
            let raw = le_address(bytes, field_offset as usize, plus);
            *address = TlsAddress {
                rva: to_rva(raw, pe.optional.image_base)?,
                field_offset,
            };
        }
        let words = (address_width * 4) as usize;
        let size_of_zero_fill = le_u32(bytes, words);
        let characteristics = le_u32(bytes, words + 4);

        let [raw_data_start, raw_data_end, address_of_index, address_of_callbacks] = addresses;
        for address in [raw_data_start, address_of_index, address_of_callbacks] {
            if let Some(target) = address.rva {
                if !is_mapped(pe, target) {
                    return Err(malformed("an address field is not mapped by the image"));
                }
            }
        }
        // `EndAddressOfRawData` is the exclusive end of the template, so it may
        // sit exactly on the end of the section holding it — which is what a
        // `.tls` section sized to its template does
        if let Some(end) = raw_data_end.rva {
            if !is_mapped_bound(pe, end) {
                return Err(malformed("the raw data range ends outside the image"));
            }
        }
        if let (Some(start), Some(end)) = (raw_data_start.rva, raw_data_end.rva) {
            if end.get() < start.get() {
                return Err(malformed("the raw data range ends before it starts"));
            }
        }

        let callbacks = match address_of_callbacks.rva {
            None => Vec::new(),
            Some(array) => read_callbacks(pe, data, array, plus)?,
        };

        Ok(Some(TlsDirectory {
            rva,
            raw_data_start,
            raw_data_end,
            address_of_index,
            address_of_callbacks,
            size_of_zero_fill,
            characteristics,
            callbacks,
        }))
    }

    /// Every address field that holds a non-zero value, with its offset inside
    /// the structure.
    ///
    /// A copy of the directory placed at a new address needs one base relocation
    /// per entry, because the loader patches these fields in place.
    pub fn relocatable_fields(&self) -> Vec<TlsAddress> {
        [
            self.raw_data_start,
            self.raw_data_end,
            self.address_of_index,
            self.address_of_callbacks,
        ]
        .into_iter()
        .filter(|address| address.rva.is_some())
        .collect()
    }

    /// Serializes the directory for an image with the given base and bitness.
    ///
    /// The callback array is not part of the output: it lives at its own address
    /// and is referenced, not embedded.
    pub fn to_bytes(&self, image_base: ImageBase, is_pe32_plus: bool) -> Result<Vec<u8>, PeError> {
        let mut output = Vec::with_capacity(Self::size_for(is_pe32_plus) as usize);
        for address in [
            self.raw_data_start,
            self.raw_data_end,
            self.address_of_index,
            self.address_of_callbacks,
        ] {
            match address.rva {
                None => push_zero(&mut output, is_pe32_plus),
                Some(rva) => push_address(
                    &mut output,
                    rva,
                    image_base,
                    is_pe32_plus,
                    "TLS address field",
                )?,
            }
        }
        output.extend_from_slice(&self.size_of_zero_fill.to_le_bytes());
        output.extend_from_slice(&self.characteristics.to_le_bytes());
        Ok(output)
    }
}

/// Appends `rva` as a pointer-width absolute virtual address.
///
/// TLS is the one directory that stores absolute addresses, so both the
/// structure itself and its callback array are written this way; `field` names
/// whichever of the two overflowed.
pub(crate) fn push_address(
    output: &mut Vec<u8>,
    rva: Rva,
    image_base: ImageBase,
    is_pe32_plus: bool,
    field: &'static str,
) -> Result<(), PeError> {
    let va = rva
        .to_va(image_base)
        .ok_or(PeError::Overflow { field })?
        .get();
    if is_pe32_plus {
        output.extend_from_slice(&va.to_le_bytes());
    } else {
        let narrow = u32::try_from(va).map_err(|_| PeError::Overflow { field })?;
        output.extend_from_slice(&narrow.to_le_bytes());
    }
    Ok(())
}

/// Appends one pointer-width zero: an absent address field or an array
/// terminator.
pub(crate) fn push_zero(output: &mut Vec<u8>, is_pe32_plus: bool) {
    output.extend_from_slice(&0u64.to_le_bytes()[..if is_pe32_plus { 8 } else { 4 }]);
}

/// Converts an absolute virtual address field to an RVA.
fn to_rva(value: u64, image_base: ImageBase) -> Result<Option<Rva>, PeError> {
    if value == 0 {
        return Ok(None);
    }
    let relative = value
        .checked_sub(image_base.get())
        .ok_or(malformed("an address field points below the image base"))?;
    let relative = u32::try_from(relative)
        .map_err(|_| malformed("an address field is too far above the image base"))?;
    Ok(Some(Rva(relative)))
}

/// Reads the NULL-terminated callback array.
///
/// The walk is bounded by the raw data holding the array, so a missing
/// terminator is an error rather than an unbounded scan.
fn read_callbacks(
    pe: &PeFile,
    data: &[u8],
    array: Rva,
    is_pe32_plus: bool,
) -> Result<Vec<Rva>, PeError> {
    let bytes = pe
        .mapped_from(data, array)
        .map_err(|_| malformed("the callback array is not backed by file data"))?;
    let width = usize::from(pe.architecture.pointer_width());

    let mut callbacks = Vec::new();
    let mut cursor = 0usize;
    loop {
        if cursor + width > bytes.len() {
            return Err(malformed("the callback array has no terminating entry"));
        }
        let value = le_address(bytes, cursor, is_pe32_plus);
        if value == 0 {
            return Ok(callbacks);
        }
        let Some(target) = to_rva(value, pe.optional.image_base)? else {
            return Ok(callbacks);
        };
        if !is_mapped(pe, target) {
            return Err(malformed("a callback target is not mapped by the image"));
        }
        callbacks.push(target);
        cursor += width;
    }
}

/// Whether the RVA falls inside a section's loaded extent.
fn is_mapped(pe: &PeFile, rva: Rva) -> bool {
    pe.covers_virtual_range(rva, 1)
}

/// Whether the RVA is a legal exclusive end of a mapped range.
fn is_mapped_bound(pe: &PeFile, rva: Rva) -> bool {
    is_mapped(pe, rva)
        || pe
            .sections
            .iter()
            .any(|section| section.virtual_end() == Some(rva.get()))
}

/// The TLS-directory-scoped malformed error.
fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::TLS, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        add_payload_section, minimal_pe32, minimal_pe64, put_u32, set_directory, PAYLOAD_RAW,
        PAYLOAD_RVA,
    };

    const PE64_BASE: u64 = 0x1_4000_0000;
    const PE32_BASE: u64 = 0x0040_0000;

    /// Builds a PE32+ image whose payload section holds a TLS directory at
    /// `PAYLOAD_RVA`, followed by a callback array at `PAYLOAD_RVA + 0x40`.
    fn pe64_with_tls(callbacks: &[u64], index_rva: u32) -> Vec<u8> {
        let mut data = minimal_pe64(0x200);
        add_payload_section(&mut data, 0x1000);
        set_directory(&mut data, directory::TLS, PAYLOAD_RVA, SIZE_PE32PLUS);

        let put_u64 = |data: &mut [u8], offset: usize, value: u64| {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        // StartAddressOfRawData / EndAddressOfRawData inside .text
        put_u64(&mut data, PAYLOAD_RAW, PE64_BASE + 0x1000);
        put_u64(&mut data, PAYLOAD_RAW + 8, PE64_BASE + 0x1100);
        put_u64(
            &mut data,
            PAYLOAD_RAW + 16,
            PE64_BASE + u64::from(index_rva),
        );
        let array_rva = PAYLOAD_RVA + 0x40;
        put_u64(
            &mut data,
            PAYLOAD_RAW + 24,
            PE64_BASE + u64::from(array_rva),
        );
        put_u32(&mut data, PAYLOAD_RAW + 32, 0x10); // SizeOfZeroFill
        put_u32(&mut data, PAYLOAD_RAW + 36, 0x20); // Characteristics

        for (index, callback) in callbacks.iter().enumerate() {
            put_u64(&mut data, PAYLOAD_RAW + 0x40 + index * 8, *callback);
        }
        data
    }

    /// Parses through `PeFile::parse`, which is where the model is built.
    fn parse64(data: &[u8]) -> Result<Option<TlsDirectory>, PeError> {
        PeFile::parse(data).map(|pe| pe.tls)
    }

    #[test]
    fn absent_directory_has_no_model() {
        let data = minimal_pe64(0x200);
        assert_eq!(parse64(&data).expect("absence is not an error"), None);
    }

    #[test]
    fn parses_a_pe32_plus_directory_with_callbacks() {
        let data = pe64_with_tls(&[PE64_BASE + 0x1010, PE64_BASE + 0x1020, 0], 0x2100);
        let tls = parse64(&data)
            .expect("well-formed directory must parse")
            .expect("directory is present");

        assert_eq!(tls.rva, Rva(PAYLOAD_RVA));
        assert_eq!(tls.raw_data_start.rva, Some(Rva(0x1000)));
        assert_eq!(tls.raw_data_start.field_offset, 0);
        assert_eq!(tls.raw_data_end.rva, Some(Rva(0x1100)));
        assert_eq!(tls.address_of_index.rva, Some(Rva(0x2100)));
        assert_eq!(tls.address_of_callbacks.rva, Some(Rva(PAYLOAD_RVA + 0x40)));
        assert_eq!(tls.address_of_callbacks.field_offset, 24);
        assert_eq!(tls.size_of_zero_fill, 0x10);
        assert_eq!(tls.characteristics, 0x20);
        assert_eq!(tls.callbacks, [Rva(0x1010), Rva(0x1020)]);
    }

    #[test]
    fn parses_a_pe32_directory() {
        let mut data = minimal_pe32(0x200);
        // The PE32 builder has its section table 0x10 lower, so place the
        // payload by hand
        data.resize(0x600, 0);
        let s = crate::testing::PE32_SECTION_TABLE + 40;
        crate::testing::put_u16(&mut data, 0x46, 2);
        data[s..s + 6].copy_from_slice(b".rdata");
        put_u32(&mut data, s + 8, 0x1000); // VirtualSize
        put_u32(&mut data, s + 12, PAYLOAD_RVA);
        put_u32(&mut data, s + 16, 0x200); // SizeOfRawData
        put_u32(&mut data, s + 20, 0x400); // PointerToRawData
        put_u32(&mut data, s + 36, 0x4000_0040);
        put_u32(&mut data, 0x58 + 56, 0x3000); // SizeOfImage
        set_directory(&mut data, directory::TLS, PAYLOAD_RVA, SIZE_PE32);

        put_u32(&mut data, PAYLOAD_RAW, PE32_BASE as u32 + 0x1000);
        put_u32(&mut data, PAYLOAD_RAW + 4, PE32_BASE as u32 + 0x1100);
        put_u32(&mut data, PAYLOAD_RAW + 8, PE32_BASE as u32 + 0x2100);
        put_u32(&mut data, PAYLOAD_RAW + 12, 0); // no callbacks
        put_u32(&mut data, PAYLOAD_RAW + 16, 4); // SizeOfZeroFill

        let tls = PeFile::parse(&data)
            .expect("synthetic PE32 must parse")
            .tls
            .expect("directory is present");

        assert_eq!(tls.raw_data_start.rva, Some(Rva(0x1000)));
        assert_eq!(tls.address_of_index.field_offset, 8);
        assert_eq!(tls.address_of_callbacks.rva, None);
        assert!(tls.callbacks.is_empty());
        assert_eq!(tls.relocatable_fields().len(), 3);
    }

    #[test]
    fn zero_fields_are_absent_rather_than_image_base() {
        let mut data = pe64_with_tls(&[0], 0x2100);
        data[PAYLOAD_RAW..PAYLOAD_RAW + 8].fill(0); // StartAddressOfRawData
        let tls = parse64(&data)
            .expect("a zero field is legal")
            .expect("directory is present");

        assert_eq!(tls.raw_data_start.rva, None);
        assert_eq!(
            tls.relocatable_fields().len(),
            3,
            "a zero field must not be relocated"
        );
    }

    #[test]
    fn rejects_an_address_below_the_image_base() {
        let mut data = pe64_with_tls(&[0], 0x2100);
        data[PAYLOAD_RAW..PAYLOAD_RAW + 8].copy_from_slice(&0x1000u64.to_le_bytes());

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "an address field points below the image base",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unmapped_address_field() {
        let data = pe64_with_tls(&[0], 0x9000);

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "an address field is not mapped by the image",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unterminated_callback_array() {
        // Fill the rest of the payload section with non-zero callback entries
        let mut data = pe64_with_tls(&[], 0x2100);
        for offset in (PAYLOAD_RAW + 0x40..PAYLOAD_RAW + 0x1000).step_by(8) {
            data[offset..offset + 8].copy_from_slice(&(PE64_BASE + 0x1000).to_le_bytes());
        }

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "the callback array has no terminating entry",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unmapped_callback_target() {
        let data = pe64_with_tls(&[PE64_BASE + 0x9_0000, 0], 0x2100);

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "a callback target is not mapped by the image",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_inverted_raw_data_range() {
        let mut data = pe64_with_tls(&[0], 0x2100);
        data[PAYLOAD_RAW..PAYLOAD_RAW + 8].copy_from_slice(&(PE64_BASE + 0x1100).to_le_bytes());
        data[PAYLOAD_RAW + 8..PAYLOAD_RAW + 16]
            .copy_from_slice(&(PE64_BASE + 0x1000).to_le_bytes());

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "the raw data range ends before it starts",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_structure_outside_file_data() {
        let mut data = minimal_pe64(0x200);
        // Only 0x10 bytes of .text remain mapped from this address, so the
        // 40-byte structure cannot be read in full
        set_directory(&mut data, directory::TLS, 0x11f0, SIZE_PE32PLUS);

        assert!(matches!(
            parse64(&data),
            Err(PeError::MalformedDirectory {
                reason: "the structure is not backed by file data",
                ..
            })
        ));
    }

    #[test]
    fn serialization_round_trips_through_the_parser() {
        let data = pe64_with_tls(&[PE64_BASE + 0x1010, 0], 0x2100);
        let tls = parse64(&data)
            .expect("directory parses")
            .expect("directory is present");
        let serialized = tls
            .to_bytes(ImageBase(PE64_BASE), true)
            .expect("directory serializes");

        assert_eq!(serialized.len(), SIZE_PE32PLUS as usize);
        assert_eq!(
            &serialized,
            &data[PAYLOAD_RAW..PAYLOAD_RAW + SIZE_PE32PLUS as usize],
            "re-emitting an unmoved directory reproduces its bytes"
        );
    }
}
