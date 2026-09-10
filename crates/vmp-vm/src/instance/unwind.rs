//! Native-state shadows and body-only exception reconstruction for scalar leaves
use std::ops::Range;

use super::{relative, BodyInstance};

/// Image-relative body and callback ranges, excluding gate entry and exit
///
/// `codes` is the processor UNWIND_INFO prefix; placement appends the handler RVA
/// The handler and empty-RET ranges use an empty version-1 UNWIND_INFO
#[derive(Debug)]
pub struct LeafUnwind {
    pub processor: Range<usize>,
    pub handler: Range<usize>,
    pub empty_ret: usize,
    pub codes: [u8; 16],
}

pub(super) fn shadows(body: &mut BodyInstance, native_rip: u64) -> usize {
    // RBP still addresses the captured caller registers above the operand stack
    body.image.extend_from_slice(&[0x48, 0xb8]);
    let address = body.image.len();
    body.image.extend_from_slice(&native_rip.to_le_bytes());
    store(&mut body.image, 192);
    body.image
        .extend_from_slice(&[0x48, 0x8d, 0x85, 128, 0, 0, 0]);
    store(&mut body.image, 200);
    for (register, offset) in [
        (crate::operand::Register::Rbp, 208),
        (crate::operand::Register::Rsi, 216),
        (crate::operand::Register::Rdi, 224),
        (crate::operand::Register::Rbx, 232),
    ] {
        let slot = body.register_offset(register);
        body.image.extend_from_slice(&[0x48, 0x8b, 0x45, slot]);
        store(&mut body.image, offset);
    }
    address
}

fn store(image: &mut Vec<u8>, offset: u32) {
    image.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
    image.extend_from_slice(&offset.to_le_bytes());
}

pub(super) fn handler(body: &mut BodyInstance) -> LeafUnwind {
    let empty_ret = body.image.len();
    body.image.push(0xc3);
    let start = body.image.len();
    let image = &mut body.image;
    image.extend_from_slice(&[0x48, 0x8b, 0x82, 192, 0, 0, 0]);
    image.extend_from_slice(&[0x48, 0x8b, 0x8a, 200, 0, 0, 0]);
    image.extend_from_slice(&[0x48, 0x83, 0xe9, 8, 0x48, 0x89, 1]);
    image.extend_from_slice(&[0x48, 0x81, 0xc2, 240, 0, 0, 0]);
    image.extend_from_slice(&[0x48, 0x8d, 5]);
    relative(image, empty_ret as i32);
    let repeat = image.len();
    image.extend_from_slice(&[0x48, 0x39, 0xd1, 0x0f, 0x86]);
    let done = image.len();
    image.extend_from_slice(&[0; 4]);
    image.extend_from_slice(&[0x48, 0x83, 0xe9, 8, 0x48, 0x89, 1, 0xe9]);
    relative(image, repeat as i32);
    let target = image.len() as i32;
    image[done..done + 4].copy_from_slice(&(target - done as i32 - 4).to_le_bytes());
    image.extend_from_slice(&[0x49, 0x8b, 0x49, 0x28]);
    image.extend_from_slice(&[0x48, 0x8b, 0x81, 0x98, 0, 0, 0]);
    image.extend_from_slice(&[0x48, 0x8b, 0]);
    image.extend_from_slice(&[0x48, 0x89, 0x81, 0xf8, 0, 0, 0]);
    image.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xc3]);
    LeafUnwind {
        processor: 0..body.table,
        handler: start..image.len(),
        empty_ret,
        codes: [9, 0, 6, 0, 5, 1, 26, 0, 4, 0x50, 3, 0x60, 2, 0x70, 1, 0x30],
    }
}
