//! SDK marker discovery in file-backed executable PE sections.

use vmp_types::Rva;

use crate::PeFile;

const BEGIN_PREFIX: &[u8] = b"\xeb\x10VMProtect begin";
const END_MARKER: &[u8] = b"\xeb\x0eVMProtect end\0";

/// Maximum number of retained markers from one image.
pub const MAX_SDK_MARKERS: usize = 262_144;

/// Compilation policy encoded by a static assembly begin marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerCompilationType {
    Default,
    Virtualization,
    Mutation,
    Ultra,
    Reserved(u8),
}

/// One marker found in executable, file-backed section bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkMarker {
    Begin {
        rva: Rva,
        next_rva: Rva,
        tag: u8,
        compilation_type: MarkerCompilationType,
    },
    End {
        rva: Rva,
        next_rva: Rva,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MarkerError {
    #[error("SDK marker count exceeds the limit of {limit}")]
    TooManyMarkers { limit: usize },
    #[error("memory allocation failed while retaining SDK markers")]
    AllocationFailed,
    #[error("SDK marker RVA overflows the image coordinate space")]
    RvaOverflow,
    #[error("executable section {section} raw bytes are unavailable")]
    SectionDataUnavailable { section: usize },
}

/// Finds static assembly SDK markers in executable sections.
pub fn discover_asm_markers(pe: &PeFile, data: &[u8]) -> Result<Vec<SdkMarker>, MarkerError> {
    discover_asm_markers_with_limit(pe, data, MAX_SDK_MARKERS)
}

fn discover_asm_markers_with_limit(
    pe: &PeFile,
    data: &[u8],
    marker_limit: usize,
) -> Result<Vec<SdkMarker>, MarkerError> {
    let mut markers = Vec::new();
    for (section_index, section) in pe.sections.iter().enumerate() {
        if !section.permissions.execute || section.size_of_raw_data == 0 {
            continue;
        }

        let start = usize::try_from(section.pointer_to_raw_data.get())
            .map_err(|_| MarkerError::RvaOverflow)?;
        let raw_size =
            usize::try_from(section.size_of_raw_data).map_err(|_| MarkerError::RvaOverflow)?;
        let end = start
            .checked_add(raw_size)
            .ok_or(MarkerError::RvaOverflow)?;
        let bytes = data
            .get(start..end)
            .ok_or(MarkerError::SectionDataUnavailable {
                section: section_index,
            })?;

        let mut offset = 0usize;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let marker = if remaining.starts_with(BEGIN_PREFIX) {
                remaining.get(BEGIN_PREFIX.len()).and_then(|&tag| {
                    (tag <= 0x0f).then(|| {
                        let compilation_type = match tag {
                            0 => MarkerCompilationType::Default,
                            1 => MarkerCompilationType::Virtualization,
                            2 => MarkerCompilationType::Mutation,
                            3 => MarkerCompilationType::Ultra,
                            reserved => MarkerCompilationType::Reserved(reserved),
                        };
                        (BEGIN_PREFIX.len() + 1, tag, Some(compilation_type))
                    })
                })
            } else if remaining.starts_with(END_MARKER) {
                Some((END_MARKER.len(), 0, None))
            } else {
                None
            };

            let Some((length, tag, compilation_type)) = marker else {
                offset += 1;
                continue;
            };
            if markers.len() == marker_limit {
                return Err(MarkerError::TooManyMarkers {
                    limit: marker_limit,
                });
            }
            markers
                .try_reserve(1)
                .map_err(|_| MarkerError::AllocationFailed)?;
            let relative = u32::try_from(offset).map_err(|_| MarkerError::RvaOverflow)?;
            let rva = section
                .virtual_address
                .checked_add(relative)
                .ok_or(MarkerError::RvaOverflow)?;
            let found = match compilation_type {
                Some(compilation_type) => SdkMarker::Begin {
                    rva,
                    next_rva: rva
                        .checked_add(u32::try_from(length).map_err(|_| MarkerError::RvaOverflow)?)
                        .ok_or(MarkerError::RvaOverflow)?,
                    tag,
                    compilation_type,
                },
                None => SdkMarker::End {
                    rva,
                    next_rva: rva
                        .checked_add(u32::try_from(length).map_err(|_| MarkerError::RvaOverflow)?)
                        .ok_or(MarkerError::RvaOverflow)?,
                },
            };
            markers.push(found);
            offset += length;
        }
    }
    Ok(markers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_second_section, minimal_pe64, put_u32, PE64_SECTION_TABLE};
    use crate::PeFile;

    const BEGIN_LEN: usize = 18;
    const END_LEN: usize = 16;

    fn begin(tag: u8) -> Vec<u8> {
        let mut bytes = BEGIN_PREFIX.to_vec();
        bytes.push(tag);
        bytes
    }

    fn parse(data: &[u8]) -> PeFile {
        PeFile::parse(data).expect("synthetic PE must parse")
    }

    #[test]
    fn discovers_cpp_static_asm_markers_in_source_order() {
        let mut data = minimal_pe64(0x200);
        let first = begin(2);
        data[0x210..0x210 + first.len()].copy_from_slice(&first);
        data[0x240..0x240 + END_MARKER.len()].copy_from_slice(END_MARKER);
        let second = begin(1);
        data[0x270..0x270 + second.len()].copy_from_slice(&second);

        let pe = parse(&data);
        assert_eq!(
            discover_asm_markers(&pe, &data).expect("markers must parse"),
            vec![
                SdkMarker::Begin {
                    rva: Rva(0x1010),
                    next_rva: Rva(0x1022),
                    tag: 2,
                    compilation_type: MarkerCompilationType::Mutation,
                },
                SdkMarker::End {
                    rva: Rva(0x1040),
                    next_rva: Rva(0x1050),
                },
                SdkMarker::Begin {
                    rva: Rva(0x1070),
                    next_rva: Rva(0x1082),
                    tag: 1,
                    compilation_type: MarkerCompilationType::Virtualization,
                },
            ]
        );
    }

    #[test]
    fn preserves_default_ultra_and_reserved_tags() {
        let mut data = minimal_pe64(0x200);
        for (index, tag) in [0, 3, 4, 15].into_iter().enumerate() {
            let marker = begin(tag);
            let offset = 0x200 + index * 0x20;
            data[offset..offset + marker.len()].copy_from_slice(&marker);
        }

        let pe = parse(&data);
        let types: Vec<MarkerCompilationType> = discover_asm_markers(&pe, &data)
            .expect("markers must parse")
            .into_iter()
            .map(|marker| match marker {
                SdkMarker::Begin {
                    compilation_type, ..
                } => compilation_type,
                SdkMarker::End { .. } => panic!("fixture contains only begin markers"),
            })
            .collect();
        assert_eq!(
            types,
            vec![
                MarkerCompilationType::Default,
                MarkerCompilationType::Ultra,
                MarkerCompilationType::Reserved(4),
                MarkerCompilationType::Reserved(15),
            ]
        );
    }

    #[test]
    fn rejects_high_nibble_tag_as_not_the_cpp_signature() {
        let mut data = minimal_pe64(0x200);
        let marker = begin(0x82);
        data[0x220..0x220 + marker.len()].copy_from_slice(&marker);
        let pe = parse(&data);
        assert!(discover_asm_markers(&pe, &data)
            .expect("scan must succeed")
            .is_empty());
    }

    #[test]
    fn ignores_marker_bytes_in_non_executable_sections() {
        let mut data = minimal_pe64(0x200);
        add_second_section(&mut data, 0x2000, 0x200, 0x400, 0x200);
        put_u32(&mut data, 0x58 + 56, 0x3000);
        let marker = begin(2);
        data[0x410..0x410 + marker.len()].copy_from_slice(&marker);

        let pe = parse(&data);
        assert!(discover_asm_markers(&pe, &data)
            .expect("scan must succeed")
            .is_empty());
    }

    #[test]
    fn does_not_match_across_section_raw_boundaries() {
        let mut data = minimal_pe64(0x200);
        add_second_section(&mut data, 0x2000, 0x200, 0x400, 0x200);
        put_u32(&mut data, 0x58 + 56, 0x3000);
        put_u32(&mut data, PE64_SECTION_TABLE + 40 + 36, 0x6000_0020);
        let marker = begin(2);
        data[0x3f8..0x400].copy_from_slice(&marker[..8]);
        data[0x400..0x400 + marker.len() - 8].copy_from_slice(&marker[8..]);

        let pe = parse(&data);
        assert!(discover_asm_markers(&pe, &data)
            .expect("scan must succeed")
            .is_empty());
    }

    #[test]
    fn marker_limit_accepts_exact_and_rejects_one_over() {
        let mut data = minimal_pe64(0x200);
        for (index, tag) in [0, 1, 2].into_iter().enumerate() {
            let marker = begin(tag);
            let offset = 0x200 + index * 0x20;
            data[offset..offset + marker.len()].copy_from_slice(&marker);
        }
        let pe = parse(&data);

        assert_eq!(
            discover_asm_markers_with_limit(&pe, &data, 3)
                .expect("the exact marker limit must be accepted")
                .len(),
            3
        );
        assert_eq!(
            discover_asm_markers_with_limit(&pe, &data, 2),
            Err(MarkerError::TooManyMarkers { limit: 2 })
        );
    }

    #[test]
    fn mismatched_file_bytes_are_a_typed_error() {
        let data = minimal_pe64(0x200);
        let pe = parse(&data);
        assert_eq!(
            discover_asm_markers(&pe, &data[..0x300]),
            Err(MarkerError::SectionDataUnavailable { section: 0 })
        );
    }

    #[test]
    fn marker_lengths_match_the_cpp_signatures() {
        assert_eq!(BEGIN_PREFIX.len() + 1, BEGIN_LEN);
        assert_eq!(END_MARKER.len(), END_LEN);
    }
}
