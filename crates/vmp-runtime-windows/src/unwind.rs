//! Win64 unwind records for the emitted runtime.

use crate::emit::{RuntimeBlob, UnwindFunction, UnwindOperation};
use thiserror::Error;
use vmp_pe::{ExceptionTable, FunctionEntry, PeError, RuntimeFunction, UnwindInfo};
use vmp_types::Rva;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;

#[cfg(all(test, windows, target_arch = "x86_64"))]
mod windows_tests;

#[derive(Debug, Error)]
pub(crate) enum UnwindBuildError {
    #[error("vmp-pe rejected the runtime unwind data: {0}")]
    Pe(#[from] PeError),
    #[error("could not build the runtime unwind layout")]
    Layout,
}

/// Code, unwind records, and the final dynamic function table in one image.
#[derive(Debug)]
pub(crate) struct RuntimeImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) function_table_offset: u32,
}

pub(crate) fn build_runtime_image(blob: &RuntimeBlob) -> Result<RuntimeImage, UnwindBuildError> {
    let mut bytes = blob.bytes().to_vec();
    let mut table = ExceptionTable::default();
    for function in &blob.unwind_plan.functions {
        let unwind = unwind_info(function);
        let unwind_offset = append_aligned(&mut bytes, &unwind.to_bytes()?)?;
        table.insert(FunctionEntry {
            function: RuntimeFunction {
                begin: Rva(function.range.start()),
                end: Rva(function.range.end()),
                unwind_info: Rva(unwind_offset),
            },
            unwind,
        })?;
    }
    let function_table_offset = append_aligned(&mut bytes, &table.to_bytes()?)?;
    Ok(RuntimeImage {
        bytes,
        function_table_offset,
    })
}

fn append_aligned(output: &mut Vec<u8>, bytes: &[u8]) -> Result<u32, UnwindBuildError> {
    let padding = (4 - output.len() % 4) % 4;
    let offset = output
        .len()
        .checked_add(padding)
        .ok_or(UnwindBuildError::Layout)?;
    let end = offset
        .checked_add(bytes.len())
        .ok_or(UnwindBuildError::Layout)?;
    let offset = u32::try_from(offset).map_err(|_| UnwindBuildError::Layout)?;
    output
        .try_reserve(end - output.len())
        .map_err(|_| UnwindBuildError::Layout)?;
    output.resize(offset as usize, 0);
    output.extend_from_slice(bytes);
    Ok(offset)
}

fn unwind_info(function: &UnwindFunction) -> UnwindInfo {
    let mut codes = Vec::with_capacity(function.operations.len() * 2);
    for operation in function.operations.iter().rev().copied() {
        match operation {
            UnwindOperation::PushNonvolatile {
                code_offset,
                register,
            } => {
                codes.extend_from_slice(&[code_offset, (register as u8) << 4 | UWOP_PUSH_NONVOL]);
            }
            UnwindOperation::StackAllocation { code_offset } => {
                codes.extend_from_slice(&[code_offset, UWOP_ALLOC_SMALL]);
            }
            UnwindOperation::SetFramePointer { code_offset } => {
                codes.extend_from_slice(&[code_offset, UWOP_SET_FPREG]);
            }
        }
    }
    UnwindInfo {
        version: 1,
        flags: 0,
        size_of_prolog: function.prologue_size,
        frame_register: function.frame_register.map_or(0, |register| register as u8),
        frame_offset: function.frame_offset,
        codes,
        handler: None,
        chained: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::emit_interpreter;

    #[test]
    fn production_unwind_info_has_the_expected_wire_encoding() {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let production = &blob.unwind_plan.functions[1];

        assert_eq!(
            unwind_info(production)
                .to_bytes()
                .expect("vmp-pe must serialize the info"),
            [
                0x01, 0x1b, 0x11, 0x0f, // Version, prologue size, code count, R15 frame
                0x1b, 0x03, // UWOP_SET_FPREG
                0x18, 0x02, // PUSHFQ as UWOP_ALLOC_SMALL 8
                0x17, 0xf0, // PUSH R15
                0x15, 0xe0, // PUSH R14
                0x13, 0xd0, // PUSH R13
                0x11, 0xc0, // PUSH R12
                0x0f, 0x02, // PUSH R11 as allocation
                0x0d, 0x02, // PUSH R10 as allocation
                0x0b, 0x02, // PUSH R9 as allocation
                0x09, 0x02, // PUSH R8 as allocation
                0x07, 0x70, // PUSH RDI
                0x06, 0x60, // PUSH RSI
                0x05, 0x50, // PUSH RBP
                0x04, 0x30, // PUSH RBX
                0x03, 0x02, // PUSH RDX as allocation
                0x02, 0x02, // PUSH RCX as allocation
                0x01, 0x02, // PUSH RAX as allocation
                0x00, 0x00, // Alignment pad, not an unwind operation
            ]
        );
    }

    #[test]
    fn registered_image_places_xdata_before_its_final_function_table() {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let image = build_runtime_image(&blob).expect("the validated blob must serialize");
        let table_offset = image.function_table_offset as usize;

        assert_eq!(&image.bytes[..blob.bytes().len()], blob.bytes());
        assert_eq!(table_offset % 4, 0);
        assert_eq!(table_offset + 2 * 12, image.bytes.len());

        for (index, function) in blob.unwind_plan.functions.iter().enumerate() {
            let entry = table_offset + index * 12;
            let begin = read_u32(&image.bytes, entry);
            let end = read_u32(&image.bytes, entry + 4);
            let unwind = read_u32(&image.bytes, entry + 8);

            assert_eq!(begin, function.range.start());
            assert_eq!(end, function.range.end());
            assert_eq!(unwind % 4, 0);
            assert!(unwind as usize >= blob.bytes().len());
            assert!((unwind as usize) < table_offset);
        }
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("fixture field is four bytes"),
        )
    }
}
