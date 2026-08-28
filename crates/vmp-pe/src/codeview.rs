//! Lazy parsing of PE CodeView debug records used to identify a sidecar PDB.

use crate::reader::{le_u16, le_u32};
use crate::{directory, PeError, PeFile, Rva};

const DEBUG_DIRECTORY_SIZE: usize = 28;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const RSDS_HEADER_SIZE: usize = 24;
const RSDS_SIGNATURE: &[u8; 4] = b"RSDS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdbGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdbIdentity {
    pub guid: PdbGuid,
    pub age: u32,
}

fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::DEBUG, reason)
}

impl PeFile {
    /// Reads the first CodeView entry, matching the legacy source-selection rule.
    /// The PDB path is validated as NUL-terminated but is not retained.
    pub fn codeview_pdb_identity(&self, image: &[u8]) -> Result<Option<PdbIdentity>, PeError> {
        let Some(directory) = self.directory_bytes(image, directory::DEBUG)? else {
            return Ok(None);
        };
        if directory.len() % DEBUG_DIRECTORY_SIZE != 0 {
            return Err(malformed("entry table size is not a multiple of 28"));
        }

        for entry in directory.as_chunks::<DEBUG_DIRECTORY_SIZE>().0 {
            if le_u32(entry, 12) != IMAGE_DEBUG_TYPE_CODEVIEW {
                continue;
            }
            let size = le_u32(entry, 16);
            let rva = Rva(le_u32(entry, 20));
            let record = self
                .mapped_range(image, rva, size)
                .map_err(|_| malformed("CodeView record is not fully file-backed"))?;
            if record.len() < RSDS_HEADER_SIZE {
                return Err(malformed("CodeView record is shorter than an RSDS header"));
            }
            if record.get(..4) != Some(RSDS_SIGNATURE) {
                return Err(malformed("unsupported CodeView signature"));
            }
            if !record
                .get(RSDS_HEADER_SIZE..)
                .is_some_and(|path| path.contains(&0))
            {
                return Err(malformed("CodeView PDB path is not NUL-terminated"));
            }
            let Some(data4) = record.get(12..20).and_then(|bytes| bytes.try_into().ok()) else {
                return Err(malformed("CodeView GUID is truncated"));
            };
            return Ok(Some(PdbIdentity {
                guid: PdbGuid {
                    data1: le_u32(record, 4),
                    data2: le_u16(record, 8),
                    data3: le_u16(record, 10),
                    data4,
                },
                age: le_u32(record, 20),
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{
        add_payload_section, minimal_pe64, put32, put_bytes, set_directory, PAYLOAD_RVA,
    };
    use crate::{directory, PeError, PeFile};

    const RECORD_RVA: u32 = PAYLOAD_RVA + 0x40;

    fn valid_rsds_image() -> Vec<u8> {
        let mut image = minimal_pe64(0x200);
        add_payload_section(&mut image, 0x100);
        set_directory(&mut image, directory::DEBUG, PAYLOAD_RVA, 28);
        put32(&mut image, PAYLOAD_RVA + 12, 2);
        put32(&mut image, PAYLOAD_RVA + 16, 30);
        put32(&mut image, PAYLOAD_RVA + 20, RECORD_RVA);
        put_bytes(
            &mut image,
            RECORD_RVA,
            &[
                b'R', b'S', b'D', b'S', 0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x90, 0xab,
                0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 7, 0, 0, 0, b'x', b'.', b'p', b'd', b'b', 0,
            ],
        );
        image
    }

    #[test]
    fn reads_rsds_identity_with_windows_guid_field_endianness() {
        let image = valid_rsds_image();
        let pe = PeFile::parse(&image).expect("synthetic PE must parse");
        let identity = pe
            .codeview_pdb_identity(&image)
            .expect("debug directory must parse")
            .expect("RSDS identity must exist");

        assert_eq!(identity.guid.data1, 0x1122_3344);
        assert_eq!(identity.guid.data2, 0x5566);
        assert_eq!(identity.guid.data3, 0x7788);
        assert_eq!(
            identity.guid.data4,
            [0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(identity.age, 7);
    }

    #[test]
    fn absent_debug_directory_has_no_pdb_identity() {
        let image = minimal_pe64(0x200);
        let pe = PeFile::parse(&image).expect("synthetic PE must parse");
        assert_eq!(pe.codeview_pdb_identity(&image), Ok(None));
    }

    #[test]
    fn rejects_malformed_codeview_boundaries_and_signature() {
        let mut malformed = Vec::new();

        let mut table_remainder = valid_rsds_image();
        set_directory(&mut table_remainder, directory::DEBUG, PAYLOAD_RVA, 29);
        malformed.push(table_remainder);

        let mut short_record = valid_rsds_image();
        put32(&mut short_record, PAYLOAD_RVA + 16, 23);
        malformed.push(short_record);

        let mut unsupported = valid_rsds_image();
        put_bytes(&mut unsupported, RECORD_RVA, b"NB10");
        malformed.push(unsupported);

        let mut unterminated = valid_rsds_image();
        put_bytes(&mut unterminated, RECORD_RVA + 29, b"x");
        malformed.push(unterminated);

        for image in malformed {
            let pe = PeFile::parse(&image).expect("debug corruption is lazy");
            assert!(matches!(
                pe.codeview_pdb_identity(&image),
                Err(PeError::MalformedDirectory {
                    directory: directory::DEBUG,
                    ..
                })
            ));
        }
    }
}
