//! Lazy parser for the PE's deprecated embedded COFF symbol table.

use crate::{PeError, PeFile};

const SYMBOL_SIZE: usize = 18;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_CLASS_STATIC: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoffStorageClass {
    External,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffSymbol {
    pub raw_name: Vec<u8>,
    pub section: u16,
    pub value: u32,
    pub storage_class: CoffStorageClass,
}

impl PeFile {
    /// Reads external/static COFF records. The table is optional and is parsed
    /// only when symbol discovery requests it.
    pub fn coff_symbols(&self, data: &[u8]) -> Result<Vec<CoffSymbol>, PeError> {
        let start = usize::try_from(self.coff.pointer_to_symbol_table.get())
            .map_err(|_| malformed("symbol table offset does not fit usize"))?;
        let count = usize::try_from(self.coff.number_of_symbols)
            .map_err(|_| malformed("symbol count does not fit usize"))?;
        if start == 0 || count == 0 {
            return Ok(Vec::new());
        }

        let records_size = count
            .checked_mul(SYMBOL_SIZE)
            .ok_or_else(|| malformed("symbol table size overflows"))?;
        let records_end = start
            .checked_add(records_size)
            .ok_or_else(|| malformed("symbol table range overflows"))?;
        let records = data
            .get(start..records_end)
            .ok_or_else(|| malformed("symbol records exceed the file"))?;
        let size_end = records_end
            .checked_add(4)
            .ok_or_else(|| malformed("string table header range overflows"))?;
        let string_size_bytes = data
            .get(records_end..size_end)
            .ok_or_else(|| malformed("string table header exceeds the file"))?;
        let string_size = u32::from_le_bytes(
            string_size_bytes
                .try_into()
                .expect("the checked slice contains four bytes"),
        ) as usize;
        if string_size < 4 {
            return Err(malformed("string table is shorter than its size field"));
        }
        let strings_end = records_end
            .checked_add(string_size)
            .ok_or_else(|| malformed("string table range overflows"))?;
        let strings = data
            .get(records_end..strings_end)
            .ok_or_else(|| malformed("string table exceeds the file"))?;

        let mut symbols = Vec::new();
        let mut index = 0usize;
        while index < count {
            let offset = index
                .checked_mul(SYMBOL_SIZE)
                .ok_or_else(|| malformed("symbol record offset overflows"))?;
            let record = &records[offset..offset + SYMBOL_SIZE];
            let auxiliary = usize::from(record[17]);
            let storage_class = match record[16] {
                IMAGE_SYM_CLASS_EXTERNAL => Some(CoffStorageClass::External),
                IMAGE_SYM_CLASS_STATIC => Some(CoffStorageClass::Static),
                _ => None,
            };
            if let Some(storage_class) = storage_class {
                let section = u16::from_le_bytes([record[12], record[13]]);
                if section != 0 && usize::from(section) <= self.sections.len() {
                    symbols.push(CoffSymbol {
                        raw_name: coff_name(record, strings)?,
                        section,
                        value: u32::from_le_bytes(
                            record[8..12]
                                .try_into()
                                .expect("the checked record contains four value bytes"),
                        ),
                        storage_class,
                    });
                }
            }
            index = index
                .checked_add(auxiliary + 1)
                .ok_or_else(|| malformed("auxiliary symbol count overflows"))?;
            if index > count {
                return Err(malformed("auxiliary symbols exceed NumberOfSymbols"));
            }
        }
        Ok(symbols)
    }
}

fn coff_name(record: &[u8], strings: &[u8]) -> Result<Vec<u8>, PeError> {
    if record[..4] != [0; 4] {
        let end = record[..8].iter().position(|&byte| byte == 0).unwrap_or(8);
        return Ok(record[..end].to_vec());
    }

    let offset = u32::from_le_bytes(
        record[4..8]
            .try_into()
            .expect("the checked record contains four offset bytes"),
    ) as usize;
    if offset < 4 {
        return Err(malformed(
            "long symbol name points into the string-table size field",
        ));
    }
    let tail = strings
        .get(offset..)
        .ok_or_else(|| malformed("long symbol name is out of bounds"))?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| malformed("long symbol name is not NUL-terminated"))?;
    Ok(tail[..end].to_vec())
}

fn malformed(reason: &'static str) -> PeError {
    PeError::MalformedCoffSymbolTable { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{minimal_pe64, put_u16, put_u32};

    #[test]
    fn parses_an_external_short_name() {
        let mut data = minimal_pe64(0x200);
        put_u32(&mut data, 0x4c, 0x300);
        put_u32(&mut data, 0x50, 1);
        data[0x300..0x308].copy_from_slice(b"CoffFn\0\0");
        put_u32(&mut data, 0x308, 0x10);
        put_u16(&mut data, 0x30c, 1);
        data[0x310] = IMAGE_SYM_CLASS_EXTERNAL;
        put_u32(&mut data, 0x312, 4);

        let pe = PeFile::parse(&data).expect("synthetic image must parse");
        assert_eq!(
            pe.coff_symbols(&data).expect("COFF table must parse"),
            [CoffSymbol {
                raw_name: b"CoffFn".to_vec(),
                section: 1,
                value: 0x10,
                storage_class: CoffStorageClass::External,
            }]
        );
    }
}
