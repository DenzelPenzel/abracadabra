#![forbid(unsafe_code)]

use std::mem::size_of;
use thiserror::Error;

const MSF7_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const SUPERBLOCK_SIZE: usize = 52;
const MISSING_STREAM: u32 = u32::MAX;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("PDB resource limit exceeded: {resource}")]
    ResourceLimit { resource: &'static str },
    #[error("allocation failed while parsing PDB")]
    Allocation,
    #[error("unrecognized MSF format")]
    UnrecognizedFormat,
    #[error("invalid MSF page size")]
    InvalidPageSize,
    #[error("malformed MSF/PDB: {0}")]
    Malformed(&'static str),
    #[error("PDB stream {0} is absent")]
    MissingStream(u32),
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub input_bytes: usize,
    pub directory_bytes: usize,
    pub streams: usize,
    pub page_references: usize,
    pub logical_stream_bytes: usize,
    pub working_bytes: usize,
    pub omap_records: usize,
    pub modules: usize,
    pub scanned_records: usize,
    pub symbols: usize,
    pub retained_name_bytes: usize,
    pub total_owned_bytes: usize,
}

impl Limits {
    pub const fn production() -> Self {
        Self {
            input_bytes: 64 * 1024 * 1024,
            directory_bytes: 16 * 1024 * 1024,
            streams: 262_144,
            page_references: 262_144,
            logical_stream_bytes: 128 * 1024 * 1024,
            working_bytes: 64 * 1024 * 1024,
            omap_records: 262_144,
            modules: 65_536,
            scanned_records: 2_000_000,
            symbols: 262_144,
            retained_name_bytes: 64 * 1024 * 1024,
            total_owned_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub guid: Guid,
    pub age: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugHeader {
    pub age: u32,
    pub symbol_records_stream: u16,
    pub module_list_size: u32,
    pub section_contribution_size: u32,
    pub section_map_size: u32,
    pub file_info_size: u32,
    pub type_server_map_size: u32,
    pub debug_header_size: u32,
    pub ec_substream_size: u32,
    pub machine: u16,
    debug_header_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolStreams {
    pub global: Vec<Symbol>,
    pub modules: Vec<Symbol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub rva: u32,
}

#[derive(Debug, Clone, Copy)]
struct AddressPlan {
    sections_stream: u16,
    omap_from_src: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct Stream {
    size: Option<usize>,
    page_start: usize,
    page_count: usize,
}

pub struct Database<'a> {
    data: &'a [u8],
    page_size: usize,
    streams: Vec<Stream>,
    pages: Vec<u32>,
    owned_budget_used: usize,
}

fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8], Error> {
    let end = offset
        .checked_add(size)
        .ok_or(Error::Malformed("range overflow"))?;
    data.get(offset..end)
        .ok_or(Error::Malformed("range is outside the file"))
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, Error> {
    let raw: [u8; 2] = bytes(data, offset, 2)?
        .try_into()
        .map_err(|_| Error::Malformed("truncated u16"))?;
    Ok(u16::from_le_bytes(raw))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes(data, offset, 4)?
        .try_into()
        .map_err(|_| Error::Malformed("truncated u32"))?;
    Ok(u32::from_le_bytes(raw))
}

fn pages_needed(size: usize, page_size: usize) -> Result<usize, Error> {
    size.checked_add(page_size - 1)
        .map(|rounded| rounded / page_size)
        .ok_or(Error::Malformed("page count overflow"))
}

fn page_slice(data: &[u8], page_size: usize, pages_used: usize, page: u32) -> Result<&[u8], Error> {
    let page = usize::try_from(page).map_err(|_| Error::Malformed("invalid page number"))?;
    if page == 0 || page >= pages_used {
        return Err(Error::Malformed("page reference is out of range"));
    }
    let offset = page
        .checked_mul(page_size)
        .ok_or(Error::Malformed("page offset overflow"))?;
    bytes(data, offset, page_size)
}

impl<'a> Database<'a> {
    pub fn parse(data: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if data.len() > limits.input_bytes {
            return Err(Error::ResourceLimit {
                resource: "PDB input bytes",
            });
        }
        if bytes(data, 0, 32)? != MSF7_MAGIC {
            return Err(Error::UnrecognizedFormat);
        }
        let page_size = usize::try_from(u32_at(data, 32)?).map_err(|_| Error::InvalidPageSize)?;
        if !page_size.is_power_of_two() || !(0x100..=8 * 1024 * 1024).contains(&page_size) {
            return Err(Error::InvalidPageSize);
        }
        let pages_used = usize::try_from(u32_at(data, 40)?)
            .map_err(|_| Error::Malformed("page count does not fit usize"))?;
        let declared_file = pages_used
            .checked_mul(page_size)
            .ok_or(Error::Malformed("file size overflow"))?;
        if pages_used == 0 || declared_file > data.len() {
            return Err(Error::Malformed("declared pages exceed the file"));
        }
        let directory_size = usize::try_from(u32_at(data, 44)?)
            .map_err(|_| Error::Malformed("directory size does not fit usize"))?;
        if directory_size > limits.directory_bytes {
            return Err(Error::ResourceLimit {
                resource: "MSF directory bytes",
            });
        }
        let directory_pages = pages_needed(directory_size, page_size)?;
        let block_map_bytes = directory_pages
            .checked_mul(4)
            .ok_or(Error::Malformed("directory page-list overflow"))?;
        if block_map_bytes > page_size {
            return Err(Error::Malformed(
                "MSF7 directory block array does not fit its block-map page",
            ));
        }
        let header_list_bytes = if directory_pages == 0 {
            SUPERBLOCK_SIZE
        } else {
            SUPERBLOCK_SIZE
                .checked_add(4)
                .ok_or(Error::Malformed("superblock page-list overflow"))?
        };
        if header_list_bytes > page_size || header_list_bytes > data.len() {
            return Err(Error::Malformed(
                "directory indirection does not fit the superblock",
            ));
        }
        if directory_pages > limits.page_references {
            return Err(Error::ResourceLimit {
                resource: "MSF page references",
            });
        }
        let first_working = directory_pages
            .checked_mul(size_of::<u32>())
            .and_then(|bytes| bytes.checked_add(directory_size))
            .ok_or(Error::ResourceLimit {
                resource: "PDB working bytes",
            })?;
        if first_working > limits.working_bytes {
            return Err(Error::ResourceLimit {
                resource: "PDB working bytes",
            });
        }

        let mut directory_page_numbers = Vec::new();
        directory_page_numbers
            .try_reserve_exact(directory_pages)
            .map_err(|_| Error::Allocation)?;
        if directory_pages > 0 {
            let block_page = u32_at(data, SUPERBLOCK_SIZE)?;
            let block = page_slice(data, page_size, pages_used, block_page)?;
            for index in 0..directory_pages {
                let page = u32_at(block, index * 4)?;
                page_slice(data, page_size, pages_used, page)?;
                directory_page_numbers.push(page);
            }
        }
        if directory_page_numbers.len() != directory_pages {
            return Err(Error::Malformed("directory page list is truncated"));
        }

        let mut directory = Vec::new();
        directory
            .try_reserve_exact(directory_size)
            .map_err(|_| Error::Allocation)?;
        directory.resize(directory_size, 0);
        let mut copied = 0usize;
        for page in directory_page_numbers {
            let source = page_slice(data, page_size, pages_used, page)?;
            let count = (directory_size - copied).min(page_size);
            let destination = directory
                .get_mut(copied..copied + count)
                .ok_or(Error::Malformed("directory copy range overflow"))?;
            destination.copy_from_slice(bytes(source, 0, count)?);
            copied += count;
        }

        let stream_count = usize::try_from(u32_at(&directory, 0)?)
            .map_err(|_| Error::Malformed("stream count does not fit usize"))?;
        if stream_count > limits.streams {
            return Err(Error::ResourceLimit {
                resource: "MSF streams",
            });
        }
        let sizes_bytes = stream_count
            .checked_mul(4)
            .ok_or(Error::Malformed("stream-size table overflow"))?;
        bytes(&directory, 4, sizes_bytes)?;
        let mut page_count = 0usize;
        let mut logical_stream_bytes = 0usize;
        for index in 0..stream_count {
            let size = u32_at(&directory, 4 + index * 4)?;
            if size != MISSING_STREAM {
                logical_stream_bytes = logical_stream_bytes.checked_add(size as usize).ok_or(
                    Error::ResourceLimit {
                        resource: "PDB logical stream bytes",
                    },
                )?;
                if logical_stream_bytes > limits.logical_stream_bytes {
                    return Err(Error::ResourceLimit {
                        resource: "PDB logical stream bytes",
                    });
                }
                page_count = page_count
                    .checked_add(pages_needed(size as usize, page_size)?)
                    .ok_or(Error::Malformed("stream page count overflow"))?;
            }
        }
        if page_count > limits.page_references {
            return Err(Error::ResourceLimit {
                resource: "MSF page references",
            });
        }
        let page_bytes = page_count
            .checked_mul(size_of::<u32>())
            .ok_or(Error::ResourceLimit {
                resource: "PDB working bytes",
            })?;
        let stream_bytes =
            stream_count
                .checked_mul(size_of::<Stream>())
                .ok_or(Error::ResourceLimit {
                    resource: "PDB working bytes",
                })?;
        let total_working = first_working
            .checked_add(page_bytes)
            .and_then(|bytes| bytes.checked_add(stream_bytes))
            .ok_or(Error::ResourceLimit {
                resource: "PDB working bytes",
            })?;
        if total_working > limits.working_bytes {
            return Err(Error::ResourceLimit {
                resource: "PDB working bytes",
            });
        }
        let page_table_offset = 4usize
            .checked_add(sizes_bytes)
            .ok_or(Error::Malformed("stream page-table offset overflow"))?;
        bytes(&directory, page_table_offset, page_bytes)?;

        let mut streams = Vec::new();
        streams
            .try_reserve_exact(stream_count)
            .map_err(|_| Error::Allocation)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(page_count)
            .map_err(|_| Error::Allocation)?;
        let mut page_cursor = page_table_offset;
        for index in 0..stream_count {
            let raw_size = u32_at(&directory, 4 + index * 4)?;
            let size = (raw_size != MISSING_STREAM).then_some(raw_size as usize);
            let count = match size {
                Some(value) => pages_needed(value, page_size)?,
                None => 0,
            };
            let page_start = pages.len();
            for _ in 0..count {
                let page = u32_at(&directory, page_cursor)?;
                page_slice(data, page_size, pages_used, page)?;
                pages.push(page);
                page_cursor += 4;
            }
            streams.push(Stream {
                size,
                page_start,
                page_count: count,
            });
        }
        Ok(Self {
            data,
            page_size,
            streams,
            pages,
            owned_budget_used: total_working,
        })
    }

    fn stream(&self, number: u32) -> Result<Stream, Error> {
        let index = usize::try_from(number)
            .map_err(|_| Error::Malformed("stream index does not fit usize"))?;
        let stream = *self
            .streams
            .get(index)
            .ok_or(Error::MissingStream(number))?;
        if stream.size.is_none() {
            return Err(Error::MissingStream(number));
        }
        Ok(stream)
    }

    fn read_stream_exact<const N: usize>(
        &self,
        stream_number: u32,
        offset: usize,
    ) -> Result<[u8; N], Error> {
        let stream = self.stream(stream_number)?;
        let size = stream.size.ok_or(Error::MissingStream(stream_number))?;
        let end = offset
            .checked_add(N)
            .ok_or(Error::Malformed("stream range overflow"))?;
        if end > size {
            return Err(Error::Malformed("stream is truncated"));
        }
        let mut output = [0u8; N];
        let mut output_offset = 0usize;
        let mut logical = offset;
        while output_offset < N {
            let page_index = logical / self.page_size;
            if page_index >= stream.page_count {
                return Err(Error::Malformed("stream page list is truncated"));
            }
            let page_number = *self
                .pages
                .get(stream.page_start + page_index)
                .ok_or(Error::Malformed("stream page index is out of range"))?;
            let page_offset = logical % self.page_size;
            let count = (N - output_offset).min(self.page_size - page_offset);
            let file_offset = usize::try_from(page_number)
                .ok()
                .and_then(|page| page.checked_mul(self.page_size))
                .and_then(|base| base.checked_add(page_offset))
                .ok_or(Error::Malformed("stream file offset overflow"))?;
            let source = bytes(self.data, file_offset, count)?;
            output
                .get_mut(output_offset..output_offset + count)
                .ok_or(Error::Malformed("stream output range overflow"))?
                .copy_from_slice(source);
            logical += count;
            output_offset += count;
        }
        Ok(output)
    }

    fn read_stream_into(
        &self,
        stream_number: u32,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let stream = self.stream(stream_number)?;
        let size = stream.size.ok_or(Error::MissingStream(stream_number))?;
        let end = offset
            .checked_add(output.len())
            .ok_or(Error::Malformed("stream range overflow"))?;
        if end > size {
            return Err(Error::Malformed("stream is truncated"));
        }
        let mut output_offset = 0usize;
        let mut logical = offset;
        while output_offset < output.len() {
            let page_index = logical / self.page_size;
            if page_index >= stream.page_count {
                return Err(Error::Malformed("stream page list is truncated"));
            }
            let page_number = *self
                .pages
                .get(stream.page_start + page_index)
                .ok_or(Error::Malformed("stream page index is out of range"))?;
            let page_offset = logical % self.page_size;
            let count = (output.len() - output_offset).min(self.page_size - page_offset);
            let file_offset = usize::try_from(page_number)
                .ok()
                .and_then(|page| page.checked_mul(self.page_size))
                .and_then(|base| base.checked_add(page_offset))
                .ok_or(Error::Malformed("stream file offset overflow"))?;
            let source = bytes(self.data, file_offset, count)?;
            output
                .get_mut(output_offset..output_offset + count)
                .ok_or(Error::Malformed("stream output range overflow"))?
                .copy_from_slice(source);
            logical += count;
            output_offset += count;
        }
        Ok(())
    }

    fn stream_u8(&self, stream: u32, offset: usize) -> Result<u8, Error> {
        let mut raw = [0u8; 1];
        self.read_stream_into(stream, offset, &mut raw)?;
        Ok(raw[0])
    }

    fn stream_u16(&self, stream: u32, offset: usize) -> Result<u16, Error> {
        let mut raw = [0u8; 2];
        self.read_stream_into(stream, offset, &mut raw)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn stream_u32(&self, stream: u32, offset: usize) -> Result<u32, Error> {
        let mut raw = [0u8; 4];
        self.read_stream_into(stream, offset, &mut raw)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn debug_stream_index(&self, header: &DebugHeader, index: usize) -> Result<u16, Error> {
        let relative = index
            .checked_mul(2)
            .ok_or(Error::Malformed("DBI debug stream index overflow"))?;
        if relative + 2 > header.debug_header_size as usize {
            return Ok(u16::MAX);
        }
        self.stream_u16(3, header.debug_header_offset + relative)
    }

    fn public_name_range(
        &self,
        stream: u32,
        record_start: usize,
        record_length: usize,
        kind: u16,
    ) -> Result<(usize, usize), Error> {
        const PUBLIC_FIXED: usize = 12;
        let record_end = record_start
            .checked_add(2)
            .and_then(|offset| offset.checked_add(record_length))
            .ok_or(Error::Malformed("symbol record range overflow"))?;
        let name_field = record_start
            .checked_add(2 + PUBLIC_FIXED)
            .ok_or(Error::Malformed("symbol name offset overflow"))?;
        if name_field > record_end {
            return Err(Error::Malformed("public symbol is truncated"));
        }
        if kind < 0x1100 {
            let length = usize::from(self.stream_u8(stream, name_field)?);
            let start = name_field + 1;
            let end = start
                .checked_add(length)
                .ok_or(Error::Malformed("Pascal symbol name overflow"))?;
            if end > record_end {
                return Err(Error::Malformed("Pascal symbol name is truncated"));
            }
            return Ok((start, length));
        }
        let mut cursor = name_field;
        while cursor < record_end {
            if self.stream_u8(stream, cursor)? == 0 {
                return Ok((name_field, cursor - name_field));
            }
            cursor += 1;
        }
        Err(Error::Malformed("symbol name is not terminated"))
    }

    fn copy_stream_name(
        &self,
        stream: u32,
        start: usize,
        length: usize,
        scratch: &mut Vec<u8>,
    ) -> Result<(), Error> {
        scratch.clear();
        scratch.resize(length, 0);
        self.read_stream_into(stream, start, scratch)
    }

    fn validate_section_stream(&self, stream: u16) -> Result<(), Error> {
        if stream == u16::MAX {
            return Err(Error::Malformed("PDB section headers are absent"));
        }
        let size = self
            .stream(u32::from(stream))?
            .size
            .ok_or(Error::MissingStream(u32::from(stream)))?;
        if size % 40 != 0 {
            return Err(Error::Malformed(
                "section-header stream length is not a multiple of 40",
            ));
        }
        Ok(())
    }

    fn validate_omap_stream(&self, stream: u16, limits: Limits) -> Result<(), Error> {
        let stream = u32::from(stream);
        let size = self
            .stream(stream)?
            .size
            .ok_or(Error::MissingStream(stream))?;
        if size % 8 != 0 {
            return Err(Error::Malformed(
                "OMAP stream length is not a multiple of 8",
            ));
        }
        if size / 8 > limits.omap_records {
            return Err(Error::ResourceLimit {
                resource: "PDB OMAP records",
            });
        }
        let mut previous = None;
        for index in 0..size / 8 {
            let source = self.stream_u32(stream, index * 8)?;
            if previous.is_some_and(|value| source <= value) {
                return Err(Error::Malformed(
                    "OMAP source addresses are not strictly sorted",
                ));
            }
            previous = Some(source);
        }
        Ok(())
    }

    fn address_plan(&self, header: &DebugHeader, limits: Limits) -> Result<AddressPlan, Error> {
        let transformed = self.debug_stream_index(header, 5)?;
        self.validate_section_stream(transformed)?;
        let original = self.debug_stream_index(header, 10)?;
        if original == u16::MAX {
            return Ok(AddressPlan {
                sections_stream: transformed,
                omap_from_src: None,
            });
        }
        self.validate_section_stream(original)?;
        let omap_to_src = self.debug_stream_index(header, 3)?;
        let omap_from_src = self.debug_stream_index(header, 4)?;
        if omap_to_src == u16::MAX || omap_from_src == u16::MAX {
            return Err(Error::Malformed(
                "original sections require both OMAP streams",
            ));
        }
        self.validate_omap_stream(omap_to_src, limits)?;
        self.validate_omap_stream(omap_from_src, limits)?;
        Ok(AddressPlan {
            sections_stream: original,
            omap_from_src: Some(omap_from_src),
        })
    }

    fn omap_lookup(&self, stream: u16, source: u32) -> Result<Option<u32>, Error> {
        let stream = u32::from(stream);
        let size = self
            .stream(stream)?
            .size
            .ok_or(Error::MissingStream(stream))?;
        let mut low = 0usize;
        let mut high = size / 8;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.stream_u32(stream, middle * 8)? <= source {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let Some(index) = low.checked_sub(1) else {
            return Ok(None);
        };
        let record_source = self.stream_u32(stream, index * 8)?;
        let target = self.stream_u32(stream, index * 8 + 4)?;
        if target == 0 {
            return Ok(None);
        }
        target
            .checked_add(source - record_source)
            .map(Some)
            .ok_or(Error::Malformed("OMAP target RVA overflow"))
    }

    fn section_offset_to_rva(
        &self,
        plan: AddressPlan,
        section: u16,
        offset: u32,
    ) -> Result<Option<u32>, Error> {
        if section == 0 {
            return Ok(None);
        }
        let stream = u32::from(plan.sections_stream);
        let size = self
            .stream(stream)?
            .size
            .ok_or(Error::MissingStream(stream))?;
        let index = usize::from(section - 1);
        if index >= size / 40 {
            return Ok(None);
        }
        let header = index
            .checked_mul(40)
            .ok_or(Error::Malformed("section-header offset overflow"))?;
        let internal_rva = self
            .stream_u32(stream, header + 12)?
            .checked_add(offset)
            .ok_or(Error::Malformed("symbol RVA overflow"))?;
        match plan.omap_from_src {
            Some(omap) => self.omap_lookup(omap, internal_rva),
            None => Ok(Some(internal_rva)),
        }
    }

    fn module_end_of_cstring(
        &self,
        stream: u32,
        mut cursor: usize,
        end: usize,
    ) -> Result<usize, Error> {
        while cursor < end {
            if self.stream_u8(stream, cursor)? == 0 {
                return cursor
                    .checked_add(1)
                    .ok_or(Error::Malformed("module name offset overflow"));
            }
            cursor += 1;
        }
        Err(Error::Malformed("module name is not terminated"))
    }

    fn visit_module_records(
        &self,
        limits: Limits,
        mut visitor: impl FnMut(u32, usize, usize, u16) -> Result<(), Error>,
    ) -> Result<(), Error> {
        const DBI_HEADER_SIZE: usize = 64;
        const MODI_FIXED_SIZE: usize = 64;
        let header = self.debug_header()?;
        let module_end = DBI_HEADER_SIZE
            .checked_add(header.module_list_size as usize)
            .ok_or(Error::Malformed("module substream range overflow"))?;
        let mut cursor = DBI_HEADER_SIZE;
        let mut modules = 0usize;
        while cursor < module_end {
            modules = modules.checked_add(1).ok_or(Error::ResourceLimit {
                resource: "PDB modules",
            })?;
            if modules > limits.modules {
                return Err(Error::ResourceLimit {
                    resource: "PDB modules",
                });
            }
            let fixed_end = cursor
                .checked_add(MODI_FIXED_SIZE)
                .ok_or(Error::Malformed("module record range overflow"))?;
            if fixed_end > module_end {
                return Err(Error::Malformed("module record is truncated"));
            }
            let module_stream = self.stream_u16(3, cursor + 34)?;
            let symbols_size = self.stream_u32(3, cursor + 36)? as usize;
            let old_lines_size = self.stream_u32(3, cursor + 40)? as usize;
            let lines_size = self.stream_u32(3, cursor + 44)? as usize;
            let module_name_end = self.module_end_of_cstring(3, fixed_end, module_end)?;
            let object_name_end = self.module_end_of_cstring(3, module_name_end, module_end)?;
            let relative_end = object_name_end
                .checked_sub(DBI_HEADER_SIZE)
                .ok_or(Error::Malformed("module alignment underflow"))?;
            let aligned = relative_end
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or(Error::Malformed("module alignment overflow"))?;
            cursor = DBI_HEADER_SIZE
                .checked_add(aligned)
                .ok_or(Error::Malformed("module offset overflow"))?;
            if cursor > module_end {
                return Err(Error::Malformed("aligned module record exceeds substream"));
            }
            if module_stream == u16::MAX || symbols_size == 0 {
                continue;
            }
            let stream = u32::from(module_stream);
            let available = self
                .stream(stream)?
                .size
                .ok_or(Error::MissingStream(stream))?;
            let declared_size = symbols_size
                .checked_add(old_lines_size)
                .and_then(|size| size.checked_add(lines_size))
                .ok_or(Error::Malformed("module debug extents overflow"))?;
            if declared_size > available || symbols_size < 4 {
                return Err(Error::Malformed("module debug regions exceed their stream"));
            }
            if self.stream_u32(stream, 0)? != 4 {
                return Err(Error::Malformed("unsupported module symbol signature"));
            }
            let mut record = 4usize;
            while record < symbols_size {
                let length = usize::from(self.stream_u16(stream, record)?);
                if length < 2 {
                    return Err(Error::Malformed("symbol record is shorter than its kind"));
                }
                let end = record
                    .checked_add(2)
                    .and_then(|offset| offset.checked_add(length))
                    .ok_or(Error::Malformed("module symbol range overflow"))?;
                if end > symbols_size {
                    return Err(Error::Malformed("module symbol exceeds symbol region"));
                }
                let kind = self.stream_u16(stream, record + 2)?;
                visitor(stream, record, length, kind)?;
                record = end;
            }
            if record != symbols_size {
                return Err(Error::Malformed("module symbol region has trailing bytes"));
            }
        }
        if cursor != module_end {
            return Err(Error::Malformed("module substream has trailing bytes"));
        }
        Ok(())
    }

    fn retained_symbol_layout(kind: u16) -> Option<(usize, usize, usize)> {
        match kind {
            0x1007 | 0x1008 | 0x1009 | 0x1020 | 0x1021 | 0x110c | 0x110d | 0x110e | 0x111c
            | 0x111d => Some((12, 6, 10)),
            0x100a | 0x100b | 0x110f | 0x1110 | 0x1146 | 0x1147 | 0x1155 | 0x1156 => {
                Some((37, 30, 34))
            }
            _ => None,
        }
    }

    fn symbol_name_range(
        &self,
        stream: u32,
        record_start: usize,
        record_length: usize,
        kind: u16,
        fixed_size: usize,
    ) -> Result<(usize, usize), Error> {
        let record_end = record_start
            .checked_add(2)
            .and_then(|offset| offset.checked_add(record_length))
            .ok_or(Error::Malformed("symbol record range overflow"))?;
        let name_field = record_start
            .checked_add(2)
            .and_then(|offset| offset.checked_add(fixed_size))
            .ok_or(Error::Malformed("symbol name offset overflow"))?;
        if name_field > record_end {
            return Err(Error::Malformed("retained symbol is truncated"));
        }
        if kind < 0x1100 {
            let length = usize::from(self.stream_u8(stream, name_field)?);
            let start = name_field + 1;
            let end = start
                .checked_add(length)
                .ok_or(Error::Malformed("Pascal symbol name overflow"))?;
            if end > record_end {
                return Err(Error::Malformed("Pascal symbol name is truncated"));
            }
            return Ok((start, length));
        }
        let mut cursor = name_field;
        while cursor < record_end {
            if self.stream_u8(stream, cursor)? == 0 {
                return Ok((name_field, cursor - name_field));
            }
            cursor += 1;
        }
        Err(Error::Malformed("symbol name is not terminated"))
    }

    pub fn symbols(&self, limits: Limits) -> Result<SymbolStreams, Error> {
        let available = limits
            .total_owned_bytes
            .checked_sub(self.owned_budget_used)
            .ok_or(Error::ResourceLimit {
                resource: "PDB total owned bytes",
            })?;
        let mut per_stream = limits;
        per_stream.total_owned_bytes =
            self.owned_budget_used
                .checked_add(available / 2)
                .ok_or(Error::ResourceLimit {
                    resource: "PDB total owned bytes",
                })?;
        per_stream.symbols /= 2;
        per_stream.retained_name_bytes /= 2;
        per_stream.scanned_records /= 2;
        Ok(SymbolStreams {
            global: self.global_symbols(per_stream)?,
            modules: self.module_symbols(per_stream)?,
        })
    }

    pub fn module_symbols(&self, limits: Limits) -> Result<Vec<Symbol>, Error> {
        let header = self.debug_header()?;
        let address_plan = self.address_plan(&header, limits)?;

        let mut scanned = 0usize;
        let mut count = 0usize;
        let mut name_bytes = 0usize;
        let mut maximum_name = 0usize;
        self.visit_module_records(limits, |stream, record, length, kind| {
            scanned = scanned.checked_add(1).ok_or(Error::ResourceLimit {
                resource: "PDB scanned symbol records",
            })?;
            if scanned > limits.scanned_records {
                return Err(Error::ResourceLimit {
                    resource: "PDB scanned symbol records",
                });
            }
            let Some((fixed, _, _)) = Self::retained_symbol_layout(kind) else {
                return Ok(());
            };
            let (_, length) = self.symbol_name_range(stream, record, length, kind, fixed)?;
            count = count.checked_add(1).ok_or(Error::ResourceLimit {
                resource: "PDB symbols",
            })?;
            if count > limits.symbols {
                return Err(Error::ResourceLimit {
                    resource: "PDB symbols",
                });
            }
            name_bytes = name_bytes.checked_add(length).ok_or(Error::ResourceLimit {
                resource: "PDB retained name bytes",
            })?;
            if name_bytes > limits.retained_name_bytes {
                return Err(Error::ResourceLimit {
                    resource: "PDB retained name bytes",
                });
            }
            maximum_name = maximum_name.max(length);
            Ok(())
        })?;

        let output_bytes = count
            .checked_mul(size_of::<Symbol>())
            .and_then(|bytes| bytes.checked_add(name_bytes))
            .and_then(|bytes| bytes.checked_add(maximum_name))
            .ok_or(Error::ResourceLimit {
                resource: "PDB total owned bytes",
            })?;
        let total_owned =
            self.owned_budget_used
                .checked_add(output_bytes)
                .ok_or(Error::ResourceLimit {
                    resource: "PDB total owned bytes",
                })?;
        if total_owned > limits.total_owned_bytes {
            return Err(Error::ResourceLimit {
                resource: "PDB total owned bytes",
            });
        }

        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(maximum_name)
            .map_err(|_| Error::Allocation)?;
        self.visit_module_records(limits, |stream, record, length, kind| {
            let Some((fixed, _, _)) = Self::retained_symbol_layout(kind) else {
                return Ok(());
            };
            let (start, length) = self.symbol_name_range(stream, record, length, kind, fixed)?;
            self.copy_stream_name(stream, start, length, &mut scratch)?;
            std::str::from_utf8(&scratch)
                .map_err(|_| Error::Malformed("symbol name is not UTF-8"))?;
            Ok(())
        })?;

        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        self.visit_module_records(limits, |stream, record, length, kind| {
            let Some((fixed, offset_field, section_field)) = Self::retained_symbol_layout(kind)
            else {
                return Ok(());
            };
            let (start, name_length) =
                self.symbol_name_range(stream, record, length, kind, fixed)?;
            self.copy_stream_name(stream, start, name_length, &mut scratch)?;
            let valid_name = std::str::from_utf8(&scratch)
                .map_err(|_| Error::Malformed("symbol name is not UTF-8"))?;
            let mut name = String::new();
            name.try_reserve_exact(name_length)
                .map_err(|_| Error::Allocation)?;
            name.push_str(valid_name);
            let data = record + 2;
            let offset = self.stream_u32(stream, data + offset_field)?;
            let section = self.stream_u16(stream, data + section_field)?;
            if let Some(rva) = self.section_offset_to_rva(address_plan, section, offset)? {
                symbols.push(Symbol { name, rva });
            }
            Ok(())
        })?;
        Ok(symbols)
    }

    pub fn global_symbols(&self, limits: Limits) -> Result<Vec<Symbol>, Error> {
        const S_ALIGN: u16 = 0x0402;
        const S_SKIP: u16 = 0x0007;
        const S_LDATA32_ST: u16 = 0x1007;
        const S_GDATA32_ST: u16 = 0x1008;
        const S_PUB32_ST: u16 = 0x1009;
        const S_LMANDATA_ST: u16 = 0x1020;
        const S_GMANDATA_ST: u16 = 0x1021;
        const S_LDATA32: u16 = 0x110c;
        const S_GDATA32: u16 = 0x110d;
        const S_PUB32: u16 = 0x110e;
        const S_LMANDATA: u16 = 0x111c;
        const S_GMANDATA: u16 = 0x111d;
        let retained_kind = |kind| {
            matches!(
                kind,
                S_LDATA32_ST
                    | S_GDATA32_ST
                    | S_PUB32_ST
                    | S_LMANDATA_ST
                    | S_GMANDATA_ST
                    | S_LDATA32
                    | S_GDATA32
                    | S_PUB32
                    | S_LMANDATA
                    | S_GMANDATA
            )
        };

        let header = self.debug_header()?;
        if header.symbol_records_stream == u16::MAX {
            return Err(Error::MissingStream(u32::from(u16::MAX)));
        }
        let address_plan = self.address_plan(&header, limits)?;
        let stream = u32::from(header.symbol_records_stream);
        let stream_size = self
            .stream(stream)?
            .size
            .ok_or(Error::MissingStream(stream))?;

        let mut cursor = 0usize;
        let mut scanned = 0usize;
        let mut public_count = 0usize;
        let mut name_bytes = 0usize;
        let mut maximum_name = 0usize;
        while cursor < stream_size {
            scanned = scanned.checked_add(1).ok_or(Error::ResourceLimit {
                resource: "PDB scanned symbol records",
            })?;
            if scanned > limits.scanned_records {
                return Err(Error::ResourceLimit {
                    resource: "PDB scanned symbol records",
                });
            }
            let length = usize::from(self.stream_u16(stream, cursor)?);
            if length < 2 {
                return Err(Error::Malformed("symbol record is shorter than its kind"));
            }
            let end = cursor
                .checked_add(2)
                .and_then(|offset| offset.checked_add(length))
                .ok_or(Error::Malformed("symbol record range overflow"))?;
            if end > stream_size {
                return Err(Error::Malformed("symbol record exceeds its stream"));
            }
            let kind = self.stream_u16(stream, cursor + 2)?;
            if kind != S_ALIGN && kind != S_SKIP && retained_kind(kind) {
                let (_, length) = self.public_name_range(stream, cursor, length, kind)?;
                public_count = public_count.checked_add(1).ok_or(Error::ResourceLimit {
                    resource: "PDB symbols",
                })?;
                if public_count > limits.symbols {
                    return Err(Error::ResourceLimit {
                        resource: "PDB symbols",
                    });
                }
                name_bytes = name_bytes.checked_add(length).ok_or(Error::ResourceLimit {
                    resource: "PDB retained name bytes",
                })?;
                if name_bytes > limits.retained_name_bytes {
                    return Err(Error::ResourceLimit {
                        resource: "PDB retained name bytes",
                    });
                }
                maximum_name = maximum_name.max(length);
            }
            cursor = end;
        }
        if cursor != stream_size {
            return Err(Error::Malformed("symbol stream has trailing bytes"));
        }

        let output_bytes = public_count
            .checked_mul(size_of::<Symbol>())
            .and_then(|bytes| bytes.checked_add(name_bytes))
            .and_then(|bytes| bytes.checked_add(maximum_name))
            .ok_or(Error::ResourceLimit {
                resource: "PDB total owned bytes",
            })?;
        let total_owned =
            self.owned_budget_used
                .checked_add(output_bytes)
                .ok_or(Error::ResourceLimit {
                    resource: "PDB total owned bytes",
                })?;
        if total_owned > limits.total_owned_bytes {
            return Err(Error::ResourceLimit {
                resource: "PDB total owned bytes",
            });
        }

        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(maximum_name)
            .map_err(|_| Error::Allocation)?;
        cursor = 0;
        while cursor < stream_size {
            let length = usize::from(self.stream_u16(stream, cursor)?);
            let end = cursor + 2 + length;
            let kind = self.stream_u16(stream, cursor + 2)?;
            if retained_kind(kind) {
                let (start, name_length) = self.public_name_range(stream, cursor, length, kind)?;
                self.copy_stream_name(stream, start, name_length, &mut scratch)?;
                std::str::from_utf8(&scratch)
                    .map_err(|_| Error::Malformed("symbol name is not UTF-8"))?;
            }
            cursor = end;
        }

        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(public_count)
            .map_err(|_| Error::Allocation)?;
        cursor = 0;
        while cursor < stream_size {
            let length = usize::from(self.stream_u16(stream, cursor)?);
            let end = cursor + 2 + length;
            let kind = self.stream_u16(stream, cursor + 2)?;
            if retained_kind(kind) {
                let (start, name_length) = self.public_name_range(stream, cursor, length, kind)?;
                self.copy_stream_name(stream, start, name_length, &mut scratch)?;
                let valid_name = std::str::from_utf8(&scratch)
                    .map_err(|_| Error::Malformed("symbol name is not UTF-8"))?;
                let mut name = String::new();
                name.try_reserve_exact(name_length)
                    .map_err(|_| Error::Allocation)?;
                name.push_str(valid_name);
                let offset = self.stream_u32(stream, cursor + 2 + 6)?;
                let section = self.stream_u16(stream, cursor + 2 + 10)?;
                if let Some(rva) = self.section_offset_to_rva(address_plan, section, offset)? {
                    symbols.push(Symbol { name, rva });
                }
            }
            cursor = end;
        }
        Ok(symbols)
    }

    pub fn debug_header(&self) -> Result<DebugHeader, Error> {
        const DBI_HEADER_SIZE: usize = 64;
        let raw = self.read_stream_exact::<DBI_HEADER_SIZE>(3, 0)?;
        if u32_at(&raw, 0)? != u32::MAX {
            return Err(Error::Malformed("ancient DBI header is unsupported"));
        }
        let header = DebugHeader {
            age: u32_at(&raw, 8)?,
            symbol_records_stream: u16_at(&raw, 20)?,
            module_list_size: u32_at(&raw, 24)?,
            section_contribution_size: u32_at(&raw, 28)?,
            section_map_size: u32_at(&raw, 32)?,
            file_info_size: u32_at(&raw, 36)?,
            type_server_map_size: u32_at(&raw, 40)?,
            debug_header_size: u32_at(&raw, 48)?,
            ec_substream_size: u32_at(&raw, 52)?,
            machine: u16_at(&raw, 58)?,
            debug_header_offset: 0,
        };
        let debug_header_offset = [
            header.module_list_size,
            header.section_contribution_size,
            header.section_map_size,
            header.file_info_size,
            header.type_server_map_size,
            header.ec_substream_size,
        ]
        .into_iter()
        .try_fold(DBI_HEADER_SIZE, |offset, size| {
            offset
                .checked_add(size as usize)
                .ok_or(Error::Malformed("DBI substream offset overflow"))
        })?;
        let end = debug_header_offset
            .checked_add(header.debug_header_size as usize)
            .ok_or(Error::Malformed("DBI debug-header range overflow"))?;
        let stream_size = self.stream(3)?.size.ok_or(Error::MissingStream(3))?;
        if end > stream_size {
            return Err(Error::Malformed("DBI substreams exceed stream size"));
        }
        Ok(DebugHeader {
            debug_header_offset,
            ..header
        })
    }

    pub fn identity(&self) -> Result<Identity, Error> {
        let header = self.read_stream_exact::<28>(1, 0)?;
        let data4: [u8; 8] = bytes(&header, 20, 8)?
            .try_into()
            .map_err(|_| Error::Malformed("PDB GUID is truncated"))?;
        Ok(Identity {
            guid: Guid {
                data1: u32_at(&header, 12)?,
                data2: u16_at(&header, 16)?,
                data3: u16_at(&header, 18)?,
                data4,
            },
            age: u32_at(&header, 8)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Database, Error, Limits};
    use std::path::PathBuf;

    fn corpus() -> Vec<u8> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus/foo.pdb");
        std::fs::read(path).expect("required PDB corpus must exist")
    }

    #[test]
    fn parses_required_msf7_identity() {
        let data = corpus();
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        let identity = database.identity().expect("PDB info stream must parse");
        assert_eq!(identity.guid.data1, 0x2b3c_3fa5);
        assert_eq!(identity.guid.data2, 0x5a2e);
        assert_eq!(identity.guid.data3, 0x44b8);
        assert_eq!(
            identity.guid.data4,
            [0x8b, 0xba, 0xc3, 0x30, 0x0f, 0xf6, 0x9f, 0x62]
        );
        assert_eq!(identity.age, 2);
    }

    #[test]
    fn parses_required_dbi_header_and_substream_bounds() {
        let data = corpus();
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        let dbi = database.debug_header().expect("DBI stream must parse");
        assert_ne!(dbi.symbol_records_stream, u16::MAX);
        assert!(dbi.module_list_size > 0);
        assert!(dbi.debug_header_size >= 12);
    }

    #[test]
    fn parses_required_global_symbols_exactly() {
        let data = corpus();
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        let symbols = database
            .global_symbols(Limits::production())
            .expect("global symbols must parse");
        assert_eq!(symbols.len(), 3_658);
        let digest = symbols
            .iter()
            .fold(0xcbf2_9ce4_8422_2325u64, |hash, symbol| {
                symbol
                    .name
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(symbol.rva.to_le_bytes())
                    .fold(hash, |hash, byte| {
                        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
                    })
            });
        assert_eq!(digest, 0x49a3_b0ab_69b9_0169);
        let main = symbols
            .iter()
            .find(|symbol| symbol.name == "main")
            .expect("required global main symbol must exist");
        assert_eq!(main.rva, 0x6560);
    }

    #[test]
    fn parses_required_module_symbols_exactly() {
        let data = corpus();
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        let symbols = database
            .module_symbols(Limits::production())
            .expect("module symbols must parse");
        assert_eq!(symbols.len(), 2_939);
        let digest = symbols
            .iter()
            .fold(0xcbf2_9ce4_8422_2325u64, |hash, symbol| {
                symbol
                    .name
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(symbol.rva.to_le_bytes())
                    .fold(hash, |hash, byte| {
                        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
                    })
            });
        assert_eq!(digest, 0x56f3_e0f0_08de_bcb3);
    }

    #[test]
    fn omap_lookup_maps_intervals_and_preserves_elimination() {
        use super::Stream;

        let mut data = vec![0u8; 512];
        let records = [
            (0x1000u32, 0x2000u32),
            (0x1100u32, 0u32),
            (0x1200u32, 0x3000u32),
        ];
        for (index, (source, target)) in records.into_iter().enumerate() {
            let offset = 256 + index * 8;
            data[offset..offset + 4].copy_from_slice(&source.to_le_bytes());
            data[offset + 4..offset + 8].copy_from_slice(&target.to_le_bytes());
        }
        let database = Database {
            data: &data,
            page_size: 256,
            streams: vec![Stream {
                size: Some(24),
                page_start: 0,
                page_count: 1,
            }],
            pages: vec![1],
            owned_budget_used: 0,
        };
        assert_eq!(database.omap_lookup(0, 0x0fff), Ok(None));
        assert_eq!(database.omap_lookup(0, 0x1005), Ok(Some(0x2005)));
        assert_eq!(database.omap_lookup(0, 0x1105), Ok(None));
        assert_eq!(database.omap_lookup(0, 0x1205), Ok(Some(0x3005)));
        assert_eq!(
            database.validate_omap_stream(0, Limits::production()),
            Ok(())
        );
        let mut tight = Limits::production();
        tight.omap_records = 2;
        assert!(matches!(
            database.validate_omap_stream(0, tight),
            Err(Error::ResourceLimit {
                resource: "PDB OMAP records"
            })
        ));
        drop(database);

        data[256 + 16..256 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        let malformed = Database {
            data: &data,
            page_size: 256,
            streams: vec![Stream {
                size: Some(24),
                page_start: 0,
                page_count: 1,
            }],
            pages: vec![1],
            owned_budget_used: 0,
        };
        assert!(matches!(
            malformed.validate_omap_stream(0, Limits::production()),
            Err(Error::Malformed(
                "OMAP source addresses are not strictly sorted"
            ))
        ));
    }

    #[test]
    fn rejects_nonstandard_multi_page_msf7_block_map() {
        let mut data = corpus();
        let page_size = u32::from_le_bytes(data[32..36].try_into().expect("page size"));
        let directory_size = page_size
            .checked_mul(page_size / 4)
            .and_then(|size| size.checked_add(1))
            .expect("fixture geometry fits u32");
        data[44..48].copy_from_slice(&directory_size.to_le_bytes());
        assert!(matches!(
            Database::parse(&data, Limits::production()),
            Err(Error::Malformed(
                "MSF7 directory block array does not fit its block-map page"
            ))
        ));
    }

    #[test]
    fn rejects_cumulative_logical_stream_amplification() {
        let data = corpus();
        let mut limits = Limits::production();
        limits.logical_stream_bytes = 0;
        assert!(matches!(
            Database::parse(&data, limits),
            Err(Error::ResourceLimit {
                resource: "PDB logical stream bytes"
            })
        ));
    }

    #[test]
    fn validates_complete_module_debug_extents() {
        let mut data = corpus();
        let (page_size, first_dbi_page) = {
            let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
            let stream = database.stream(3).expect("DBI stream must exist");
            (database.page_size, database.pages[stream.page_start])
        };
        let lines_size = usize::try_from(first_dbi_page)
            .expect("page number fits usize")
            .checked_mul(page_size)
            .and_then(|offset| offset.checked_add(64 + 44))
            .expect("DBI fixture offset fits usize");
        data[lines_size..lines_size + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        assert!(matches!(
            database.module_symbols(Limits::production()),
            Err(Error::Malformed("module debug regions exceed their stream"))
                | Err(Error::Malformed("module debug extents overflow"))
        ));
    }

    #[test]
    fn combined_symbol_scan_splits_the_record_budget() {
        let data = corpus();
        let database = Database::parse(&data, Limits::production()).expect("MSF7 must parse");
        let mut limits = Limits::production();
        limits.scanned_records = 1;
        assert!(matches!(
            database.symbols(limits),
            Err(Error::ResourceLimit {
                resource: "PDB scanned symbol records"
            })
        ));
    }

    #[test]
    fn rejects_invalid_page_geometry_before_directory_allocation() {
        let mut data = corpus();
        data[32..36].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Database::parse(&data, Limits::production()),
            Err(Error::InvalidPageSize)
        ));
    }
}
