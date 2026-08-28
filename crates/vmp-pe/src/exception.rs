//! Exception directory: the x64 `RUNTIME_FUNCTION` table and its `UNWIND_INFO`.
//!
//! `RtlLookupFunctionEntry` binary-searches the table, so an unsorted or
//! overlapping array is not a cosmetic defect — it silently breaks unwinding for
//! some addresses. The parser therefore requires the array to be strictly
//! ascending and non-overlapping, which is what every linker emits.
//!
//! Only the `RUNTIME_FUNCTION` array has a length the format declares. An
//! `UNWIND_INFO` blob ends with language-specific handler data whose size only
//! the handler knows, so this module reads the part every version defines —
//! header, unwind codes and the handler or chain field — and deliberately does
//! not claim to know a blob's total length. That is why the writer re-points the
//! array but never moves existing `.xdata`: see
//! [`PeImage::extend_exception_table`](crate::PeImage::extend_exception_table).

use crate::reader::le_u32;
use crate::{directory, PeError, PeFile};
use vmp_types::{Architecture, Rva};

/// Bytes in one `RUNTIME_FUNCTION`.
pub const RUNTIME_FUNCTION_SIZE: u32 = 12;
/// Bytes in the fixed part of `UNWIND_INFO`.
const UNWIND_HEADER_SIZE: u32 = 4;
/// How far a chain of `UNW_FLAG_CHAININFO` nodes is followed before the input is
/// treated as hostile.
const MAX_CHAIN_DEPTH: usize = 16;

/// `UNW_FLAG_EHANDLER`: the function has an exception handler.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
/// `UNW_FLAG_UHANDLER`: the function has a termination handler.
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
/// `UNW_FLAG_CHAININFO`: the unwind info continues in another entry.
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// One `RUNTIME_FUNCTION`: a half-open code range and its unwind data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeFunction {
    pub begin: Rva,
    pub end: Rva,
    pub unwind_info: Rva,
}

impl RuntimeFunction {
    fn read(bytes: &[u8], offset: usize) -> RuntimeFunction {
        RuntimeFunction {
            begin: Rva(le_u32(bytes, offset)),
            end: Rva(le_u32(bytes, offset + 4)),
            unwind_info: Rva(le_u32(bytes, offset + 8)),
        }
    }

    fn write(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.begin.get().to_le_bytes());
        output.extend_from_slice(&self.end.get().to_le_bytes());
        output.extend_from_slice(&self.unwind_info.get().to_le_bytes());
    }
}

/// The parts of `UNWIND_INFO` whose layout every version defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    /// Structure version: 1, or 2 for the epilogue encoding.
    pub version: u8,
    /// `UNW_FLAG_*` bits.
    pub flags: u8,
    pub size_of_prolog: u8,
    /// Register establishing the frame pointer, or zero when there is none.
    pub frame_register: u8,
    /// Scaled offset of the frame pointer within the fixed stack allocation.
    pub frame_offset: u8,
    /// The `CountOfCodes` unwind code words, two bytes each, *without* the
    /// alignment pad.
    ///
    /// The pad is not part of the model: a zero code word decodes as a real
    /// operation (`UWOP_PUSH_NONVOL` of register 0 at prologue offset 0), so
    /// keeping it here would turn an odd code count into an extra instruction the
    /// moment the info was re-emitted.
    pub codes: Vec<u8>,
    /// Handler entry point, when the flags declare one.
    pub handler: Option<Rva>,
    /// Continuation entry, when the flags declare a chain.
    pub chained: Option<RuntimeFunction>,
}

impl UnwindInfo {
    /// Unwind info for a leaf function: no prologue, no handler, no chain.
    ///
    /// This is what a generated stub that never adjusts the stack needs in order
    /// to be unwindable.
    pub fn leaf() -> UnwindInfo {
        UnwindInfo {
            version: 1,
            flags: 0,
            size_of_prolog: 0,
            frame_register: 0,
            frame_offset: 0,
            codes: Vec::new(),
            handler: None,
            chained: None,
        }
    }

    /// Reads the unwind info stored at `rva`.
    pub fn parse(pe: &PeFile, data: &[u8], rva: Rva) -> Result<UnwindInfo, PeError> {
        let header = pe
            .mapped_range(data, rva, UNWIND_HEADER_SIZE)
            .map_err(|_| malformed("unwind info is not backed by file data"))?;
        let version = header[0] & 0x07;
        let flags = header[0] >> 3;
        if version != 1 && version != 2 {
            return Err(malformed("unwind info uses an unknown version"));
        }
        if flags & !(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO) != 0 {
            return Err(malformed("unwind info uses reserved flags"));
        }
        if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            return Err(malformed("unwind info both chains and declares a handler"));
        }
        let count_of_codes = header[2];
        // The field following the codes is 4-byte aligned, so an odd count is
        // followed by one padding word
        let code_words = u32::from(count_of_codes) + u32::from(count_of_codes % 2);
        let code_bytes = code_words
            .checked_mul(2)
            .ok_or(malformed("unwind code array overflows"))?;

        // The whole padded array has to be mapped, but only the declared words
        // are part of the model
        let declared = usize::from(count_of_codes) * 2;
        let codes = pe
            .mapped_range(data, offset_rva(rva, UNWIND_HEADER_SIZE)?, code_bytes)
            .map_err(|_| malformed("unwind codes are not backed by file data"))?
            .get(..declared)
            .unwrap_or_default()
            .to_vec();
        let tail_rva = offset_rva(
            rva,
            UNWIND_HEADER_SIZE
                .checked_add(code_bytes)
                .ok_or(malformed("unwind info overflows"))?,
        )?;

        let mut handler = None;
        let mut chained = None;
        if flags & UNW_FLAG_CHAININFO != 0 {
            let bytes = pe
                .mapped_range(data, tail_rva, RUNTIME_FUNCTION_SIZE)
                .map_err(|_| malformed("chained unwind entry is not backed by file data"))?;
            chained = Some(RuntimeFunction::read(bytes, 0));
        } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            let bytes = pe
                .mapped_range(data, tail_rva, 4)
                .map_err(|_| malformed("exception handler RVA is not backed by file data"))?;
            handler = Some(Rva(le_u32(bytes, 0)));
        }

        Ok(UnwindInfo {
            version,
            flags,
            size_of_prolog: header[1],
            frame_register: header[3] & 0x0f,
            frame_offset: header[3] >> 4,
            codes,
            handler,
            chained,
        })
    }

    /// Serializes the parts this module models.
    ///
    /// Language-specific handler data is not part of the model, so a blob that
    /// declares a handler cannot be re-emitted; only chain-free, handler-free
    /// info — the kind generated for new code — is serializable.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PeError> {
        if self.version != 1 && self.version != 2 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind info uses an unknown version",
            });
        }
        if self.flags & !(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO) != 0 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind info uses reserved flags",
            });
        }
        if self.frame_register > 0x0f || self.frame_offset > 0x0f {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind header fields exceed their encoded width",
            });
        }
        if self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind info declares language-specific handler data",
            });
        }
        if (self.flags & UNW_FLAG_CHAININFO != 0) != self.chained.is_some() {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind chain flags and chain data disagree",
            });
        }
        if self.handler.is_some() {
            return Err(PeError::UnsupportedRewriteLayout {
                reason:
                    "unwind info with a handler carries language data this crate cannot re-emit",
            });
        }
        if !self.codes.len().is_multiple_of(2) {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind codes must be a whole number of two-byte words",
            });
        }
        let count = u8::try_from(self.codes.len() / 2).map_err(|_| PeError::Overflow {
            field: "unwind code count",
        })?;
        let mut output = Vec::with_capacity(UNWIND_HEADER_SIZE as usize + self.codes.len() + 12);
        output.push((self.version & 0x07) | (self.flags << 3));
        output.push(self.size_of_prolog);
        output.push(count);
        output.push((self.frame_register & 0x0f) | (self.frame_offset << 4));
        output.extend_from_slice(&self.codes);
        // The field after the codes is four-byte aligned, so an odd word count is
        // followed by one pad word
        if !count.is_multiple_of(2) {
            output.extend_from_slice(&[0, 0]);
        }
        if let Some(chained) = self.chained {
            chained.write(&mut output);
        }
        Ok(output)
    }
}

/// The x64 exception directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExceptionTable {
    /// Ascending by `begin` and non-overlapping.
    entries: Vec<FunctionEntry>,
}

/// One table entry together with the unwind info it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    pub function: RuntimeFunction,
    pub unwind: UnwindInfo,
}

impl ExceptionTable {
    /// Parses the exception directory, or returns `None` when the image declares
    /// none.
    pub fn parse(pe: &PeFile, data: &[u8]) -> Result<Option<ExceptionTable>, PeError> {
        let Some(bytes) = pe.directory_bytes(data, directory::EXCEPTION)? else {
            return Ok(None);
        };
        if pe.architecture != Architecture::X64 {
            return Err(malformed(
                "only x64 defines a RUNTIME_FUNCTION layout for this directory",
            ));
        }
        if !bytes.len().is_multiple_of(RUNTIME_FUNCTION_SIZE as usize) {
            return Err(malformed(
                "the directory size is not a whole number of RUNTIME_FUNCTION entries",
            ));
        }

        let mut entries = Vec::with_capacity(bytes.len() / RUNTIME_FUNCTION_SIZE as usize);

        for index in 0..bytes.len() / RUNTIME_FUNCTION_SIZE as usize {
            let function = RuntimeFunction::read(bytes, index * RUNTIME_FUNCTION_SIZE as usize);
            if function.end.get() <= function.begin.get() {
                return Err(malformed("a function range is empty or inverted"));
            }
            if let Some(previous) = entries.last() {
                let previous: &FunctionEntry = previous;
                if function.begin.get() < previous.function.end.get() {
                    return Err(malformed(
                        "the table is unsorted or has overlapping functions",
                    ));
                }
            }
            let unwind = UnwindInfo::parse(pe, data, function.unwind_info)?;
            validate_chain(pe, data, &unwind)?;
            entries.push(FunctionEntry { function, unwind });
        }

        Ok(Some(ExceptionTable { entries }))
    }

    pub fn entries(&self) -> &[FunctionEntry] {
        &self.entries
    }

    /// The `RUNTIME_FUNCTION` records, in table order.
    pub fn functions(&self) -> impl Iterator<Item = RuntimeFunction> + '_ {
        self.entries.iter().map(|entry| entry.function)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds an entry, keeping the table sorted and non-overlapping.
    pub fn insert(&mut self, entry: FunctionEntry) -> Result<(), PeError> {
        let function = entry.function;
        if function.end.get() <= function.begin.get() {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "a runtime function range must be non-empty",
            });
        }
        let position = self
            .entries
            .partition_point(|existing| existing.function.begin.get() < function.begin.get());
        let overlaps_before = position
            .checked_sub(1)
            .and_then(|index| self.entries.get(index))
            .is_some_and(|previous| previous.function.end.get() > function.begin.get());
        let overlaps_after = self
            .entries
            .get(position)
            .is_some_and(|next| function.end.get() > next.function.begin.get());
        if overlaps_before || overlaps_after {
            return Err(PeError::OverlappingRuntimeFunction {
                begin: u64::from(function.begin.get()),
            });
        }
        self.entries.insert(position, entry);
        Ok(())
    }

    /// Serializes the `RUNTIME_FUNCTION` array.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PeError> {
        let mut output = Vec::with_capacity(self.entries.len() * RUNTIME_FUNCTION_SIZE as usize);
        for entry in &self.entries {
            entry.function.write(&mut output);
        }
        Ok(output)
    }

    /// Byte length [`ExceptionTable::to_bytes`] would produce.
    pub fn byte_len(&self) -> Result<u32, PeError> {
        u32::try_from(self.entries.len())
            .ok()
            .and_then(|count| count.checked_mul(RUNTIME_FUNCTION_SIZE))
            .ok_or(PeError::Overflow {
                field: "exception table size",
            })
    }
}

/// Follows a chain of `UNW_FLAG_CHAININFO` nodes to prove it is readable and
/// finite.
fn validate_chain(pe: &PeFile, data: &[u8], unwind: &UnwindInfo) -> Result<(), PeError> {
    let mut current = unwind.chained;
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(function) = current else {
            return Ok(());
        };
        if function.end.get() <= function.begin.get() {
            return Err(PeError::MalformedDirectory {
                directory: directory::EXCEPTION,
                reason: "a chained function range is empty or inverted",
            });
        }
        current = UnwindInfo::parse(pe, data, function.unwind_info)?.chained;
    }
    Err(PeError::MalformedDirectory {
        directory: directory::EXCEPTION,
        reason: "the unwind chain is longer than any real function needs",
    })
}

fn offset_rva(rva: Rva, delta: u32) -> Result<Rva, PeError> {
    rva.checked_add(delta).ok_or(PeError::Overflow {
        field: "unwind info RVA",
    })
}

/// The exception-directory-scoped malformed error.
fn malformed(reason: &'static str) -> PeError {
    PeError::malformed(directory::EXCEPTION, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        add_payload_section, minimal_pe64, set_directory, PAYLOAD_RAW, PAYLOAD_RVA,
    };

    /// Serializes a `RUNTIME_FUNCTION`.
    fn function(begin: u32, end: u32, unwind: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&begin.to_le_bytes());
        bytes.extend_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(&unwind.to_le_bytes());
        bytes
    }

    /// Builds an image whose payload section holds `table` at `PAYLOAD_RVA` and
    /// `unwind` blobs starting at `PAYLOAD_RVA + 0x400`.
    fn image_with(table: &[u8], unwind_blobs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut data = minimal_pe64(0x200);
        add_payload_section(&mut data, 0x1000);
        data[PAYLOAD_RAW..PAYLOAD_RAW + table.len()].copy_from_slice(table);
        for (offset, blob) in unwind_blobs {
            let start = PAYLOAD_RAW + *offset as usize;
            data[start..start + blob.len()].copy_from_slice(blob);
        }
        set_directory(
            &mut data,
            directory::EXCEPTION,
            PAYLOAD_RVA,
            table.len() as u32,
        );
        data
    }

    /// Parses through `PeFile::parse`, which is where the model is built.
    fn parse(table: &[u8], blobs: &[(u32, Vec<u8>)]) -> Result<ExceptionTable, PeError> {
        let data = image_with(table, blobs);
        PeFile::parse(&data).map(|pe| {
            pe.exception_table
                .expect("the directory is present in the image")
        })
    }

    /// A leaf `UNWIND_INFO` blob at payload offset 0x400 (RVA 0x2400).
    fn leaf_blob() -> (u32, Vec<u8>) {
        (0x400, vec![1, 0, 0, 0])
    }

    const LEAF_RVA: u32 = PAYLOAD_RVA + 0x400;

    #[test]
    fn absent_directory_has_no_model() {
        let data = minimal_pe64(0x200);
        let pe = PeFile::parse(&data).expect("an image without unwind data is valid");
        assert_eq!(pe.exception_table, None);
    }

    #[test]
    fn parses_a_sorted_table() {
        let table = [
            function(0x1000, 0x1010, LEAF_RVA),
            function(0x1010, 0x1080, LEAF_RVA),
        ]
        .concat();
        let parsed = parse(&table, &[leaf_blob()]).expect("well-formed table must parse");

        assert_eq!(parsed.len(), 2);
        let functions: Vec<RuntimeFunction> = parsed.functions().collect();
        assert_eq!(functions[0].begin, Rva(0x1000));
        assert_eq!(functions[1].end, Rva(0x1080));
        assert_eq!(parsed.entries()[0].unwind, UnwindInfo::leaf());
        assert_eq!(parsed.byte_len().expect("size fits"), 24);
        assert_eq!(parsed.to_bytes().expect("serializes"), table);
    }

    #[test]
    fn rejects_a_size_that_is_not_whole_entries() {
        let mut table = function(0x1000, 0x1010, LEAF_RVA);
        table.truncate(10);

        assert!(matches!(
            parse(&table, &[leaf_blob()]),
            Err(PeError::MalformedDirectory {
                reason: "the directory size is not a whole number of RUNTIME_FUNCTION entries",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_inverted_range() {
        let table = function(0x1010, 0x1000, LEAF_RVA);

        assert!(matches!(
            parse(&table, &[leaf_blob()]),
            Err(PeError::MalformedDirectory {
                reason: "a function range is empty or inverted",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unsorted_table() {
        let table = [
            function(0x1080, 0x1090, LEAF_RVA),
            function(0x1000, 0x1010, LEAF_RVA),
        ]
        .concat();

        assert!(matches!(
            parse(&table, &[leaf_blob()]),
            Err(PeError::MalformedDirectory {
                reason: "the table is unsorted or has overlapping functions",
                ..
            })
        ));
    }

    #[test]
    fn rejects_overlapping_functions() {
        let table = [
            function(0x1000, 0x1020, LEAF_RVA),
            function(0x1010, 0x1030, LEAF_RVA),
        ]
        .concat();

        assert!(matches!(
            parse(&table, &[leaf_blob()]),
            Err(PeError::MalformedDirectory {
                reason: "the table is unsorted or has overlapping functions",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unwind_info_outside_file_data() {
        let table = function(0x1000, 0x1010, 0x9000);

        assert!(matches!(
            parse(&table, &[leaf_blob()]),
            Err(PeError::MalformedDirectory {
                reason: "unwind info is not backed by file data",
                ..
            })
        ));
    }

    #[test]
    fn rejects_an_unknown_unwind_version() {
        let table = function(0x1000, 0x1010, LEAF_RVA);

        assert!(matches!(
            parse(&table, &[(0x400, vec![3, 0, 0, 0])]),
            Err(PeError::MalformedDirectory {
                reason: "unwind info uses an unknown version",
                ..
            })
        ));
    }

    #[test]
    fn rejects_reserved_unwind_flags_during_parse() {
        let table = function(0x1000, 0x1010, LEAF_RVA);
        assert!(matches!(
            parse(&table, &[(0x400, vec![0x41, 0, 0, 0])]),
            Err(PeError::MalformedDirectory {
                reason: "unwind info uses reserved flags",
                ..
            })
        ));
    }

    #[test]
    fn parses_unwind_codes_and_a_handler() {
        let table = function(0x1000, 0x1010, LEAF_RVA);
        // version 1, EHANDLER, prolog 4, one code word, then the handler RVA
        let blob = vec![
            1 | (UNW_FLAG_EHANDLER << 3),
            4,
            1,
            0,
            0xaa,
            0xbb,
            0,
            0,
            0x00,
            0x10,
            0x00,
            0x00,
        ];
        let parsed = parse(&table, &[(0x400, blob)]).expect("handler info must parse");
        let unwind = &parsed.entries()[0].unwind;

        assert_eq!(unwind.flags, UNW_FLAG_EHANDLER);
        assert_eq!(unwind.size_of_prolog, 4);
        assert_eq!(
            unwind.codes,
            [0xaa, 0xbb],
            "only the declared code word is modelled, not the pad"
        );
        assert_eq!(unwind.handler, Some(Rva(0x1000)));
        assert!(
            matches!(
                unwind.to_bytes(),
                Err(PeError::UnsupportedRewriteLayout { .. })
            ),
            "handler data cannot be re-emitted"
        );
    }

    #[test]
    fn follows_a_chained_entry() {
        let table = function(0x1000, 0x1010, LEAF_RVA);
        // The chain target's own unwind info is the leaf blob at 0x2410
        let mut blob = vec![1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0];
        blob.extend_from_slice(&function(0x1020, 0x1030, PAYLOAD_RVA + 0x410));
        let parsed =
            parse(&table, &[(0x400, blob), (0x410, vec![1, 0, 0, 0])]).expect("a chain must parse");

        assert_eq!(
            parsed.entries()[0].unwind.chained,
            Some(RuntimeFunction {
                begin: Rva(0x1020),
                end: Rva(0x1030),
                unwind_info: Rva(PAYLOAD_RVA + 0x410),
            })
        );
    }

    #[test]
    fn rejects_a_self_referential_chain() {
        let table = function(0x1000, 0x1010, LEAF_RVA);
        let mut blob = vec![1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0];
        blob.extend_from_slice(&function(0x1020, 0x1030, LEAF_RVA));

        assert!(matches!(
            parse(&table, &[(0x400, blob)]),
            Err(PeError::MalformedDirectory {
                reason: "the unwind chain is longer than any real function needs",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_chain_that_also_declares_a_handler() {
        let table = function(0x1000, 0x1010, LEAF_RVA);
        let blob = vec![1 | ((UNW_FLAG_CHAININFO | UNW_FLAG_EHANDLER) << 3), 0, 0, 0];

        assert!(matches!(
            parse(&table, &[(0x400, blob)]),
            Err(PeError::MalformedDirectory {
                reason: "unwind info both chains and declares a handler",
                ..
            })
        ));
    }

    #[test]
    fn insert_keeps_the_table_sorted_and_disjoint() {
        let mut table = ExceptionTable::default();
        let entry = |begin, end| FunctionEntry {
            function: RuntimeFunction {
                begin: Rva(begin),
                end: Rva(end),
                unwind_info: Rva(LEAF_RVA),
            },
            unwind: UnwindInfo::leaf(),
        };
        table
            .insert(entry(0x2000, 0x2010))
            .expect("first insertion");
        table
            .insert(entry(0x1000, 0x1010))
            .expect("out-of-order insertion is sorted in");

        let begins: Vec<u32> = table.functions().map(|f| f.begin.get()).collect();
        assert_eq!(begins, [0x1000, 0x2000]);

        assert!(matches!(
            table.insert(entry(0x2008, 0x2020)),
            Err(PeError::OverlappingRuntimeFunction { begin: 0x2008 })
        ));
        assert!(matches!(
            table.insert(entry(0x0fff, 0x1001)),
            Err(PeError::OverlappingRuntimeFunction { .. })
        ));
        assert!(matches!(
            table.insert(entry(0x3000, 0x3000)),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn an_odd_code_count_round_trips_without_gaining_an_operation() {
        // One declared code word, plus the pad the format requires after it. A
        // zero pad word decodes as UWOP_PUSH_NONVOL of register 0, so counting it
        // as a code would add an instruction to the prologue description.
        let blob = vec![1, 4, 1, 0, 0xaa, 0xbb, 0, 0];
        let table = function(0x1000, 0x1010, LEAF_RVA);
        let parsed = parse(&table, &[(0x400, blob.clone())]).expect("blob must parse");
        let unwind = &parsed.entries()[0].unwind;

        assert_eq!(unwind.codes, [0xaa, 0xbb]);
        assert_eq!(
            unwind.to_bytes().expect("serializes"),
            blob,
            "re-emitting must reproduce the same CountOfCodes and pad"
        );
    }

    #[test]
    fn rejects_serializing_a_half_code_word() {
        let mut unwind = UnwindInfo::leaf();
        unwind.codes = vec![0xaa];

        assert!(matches!(
            unwind.to_bytes(),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind codes must be a whole number of two-byte words"
            })
        ));
    }

    #[test]
    fn rejects_serializing_chain_flags_without_a_chain() {
        let mut unwind = UnwindInfo::leaf();
        unwind.flags = UNW_FLAG_CHAININFO;
        assert!(matches!(
            unwind.to_bytes(),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
    }

    #[test]
    fn rejects_serializing_reserved_unwind_flags() {
        let mut unwind = UnwindInfo::leaf();
        unwind.flags = 0x08;
        assert!(matches!(
            unwind.to_bytes(),
            Err(PeError::UnsupportedRewriteLayout {
                reason: "unwind info uses reserved flags"
            })
        ));
    }

    #[test]
    fn rejects_serializing_a_chain_without_chain_flags() {
        let mut unwind = UnwindInfo::leaf();
        unwind.chained = Some(RuntimeFunction {
            begin: Rva(0x1000),
            end: Rva(0x1010),
            unwind_info: Rva(0x2000),
        });
        assert!(matches!(
            unwind.to_bytes(),
            Err(PeError::UnsupportedRewriteLayout { .. })
        ));
    }

    #[test]
    fn leaf_unwind_info_serializes_to_four_bytes() {
        assert_eq!(
            UnwindInfo::leaf().to_bytes().expect("serializes"),
            [1, 0, 0, 0]
        );
    }

    #[test]
    fn x86_exception_directory_is_rejected() {
        let mut data = crate::testing::minimal_pe32(0x200);
        data.resize(0x600, 0);
        let s = crate::testing::PE32_SECTION_TABLE + 40;
        crate::testing::put_u16(&mut data, 0x46, 2);
        data[s..s + 6].copy_from_slice(b".rdata");
        crate::testing::put_u32(&mut data, s + 8, 0x1000);
        crate::testing::put_u32(&mut data, s + 12, PAYLOAD_RVA);
        crate::testing::put_u32(&mut data, s + 16, 0x200);
        crate::testing::put_u32(&mut data, s + 20, 0x400);
        crate::testing::put_u32(&mut data, s + 36, 0x4000_0040);
        crate::testing::put_u32(&mut data, 0x58 + 56, 0x3000);
        set_directory(&mut data, directory::EXCEPTION, PAYLOAD_RVA, 12);

        assert!(matches!(
            PeFile::parse(&data),
            Err(PeError::MalformedDirectory {
                reason: "only x64 defines a RUNTIME_FUNCTION layout for this directory",
                ..
            })
        ));
    }
}
