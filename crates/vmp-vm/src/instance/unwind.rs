//! Native-state shadows, entry unwind and body exception reconstruction for scalar leaves
use std::ops::Range;

use super::{relative, BodyInstance};

/// Image-relative gate, body and callback ranges
///
/// `codes` holds the UNWIND_INFO prefixes for the three disjoint processor ranges
/// Placement appends `shifted_handler` for the middle range and `handler.start` otherwise
/// The handler and empty-RET ranges use an empty version-1 UNWIND_INFO
#[derive(Debug)]
pub struct LeafUnwind {
    pub exit: Vec<(Range<usize>, Vec<u8>)>,
    pub entry: Range<usize>,
    pub entry_codes: [u8; 40],
    pub processor: [Range<usize>; 3],
    pub handler: Range<usize>,
    pub shifted_handler: usize,
    pub empty_ret: usize,
    pub codes: [[u8; 16]; 3],
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

pub(super) fn entry_codes(order: [u8; 16], offsets: [u8; 16], end: u8) -> [u8; 40] {
    let mut codes = [0; 40];
    // The entry unwinds saved registers directly, before native shadows are ready
    codes[..8].copy_from_slice(&[1, end, 18, 0, end, 1, 32, 0]);
    for (index, id) in order.into_iter().enumerate() {
        codes[8 + index * 2] = offsets[15 - index];
        codes[9 + index * 2] = match id {
            3 | 5 | 6 | 7 | 12..=15 => id << 4,
            // Volatile registers and flags occupy stack slots but need no restoration
            _ => 2,
        };
    }
    codes
}

pub(super) fn handler(
    body: &mut BodyInstance,
    entry: usize,
    entry_codes: [u8; 40],
    exit: Vec<(Range<usize>, Vec<u8>)>,
) -> LeafUnwind {
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
    let shifted_handler = image.len();
    // Normalize the establisher frame while the flags value occupies one native stack slot
    image.extend_from_slice(&[0x48, 0x83, 0xc2, 8, 0xe9]);
    relative(image, start as i32);
    // Every range starts in a fully established body frame, including its first instruction
    let codes = [9, 0, 6, 0, 0, 1, 26, 0, 0, 0x50, 0, 0x60, 0, 0x70, 0, 0x30];
    let mut shifted_codes = codes;
    shifted_codes[6] = 27;
    LeafUnwind {
        exit,
        entry: entry..empty_ret,
        entry_codes,
        processor: [
            0..body.flags_pop.start,
            body.flags_pop.clone(),
            body.flags_pop.end..body.table,
        ],
        handler: start..image.len(),
        shifted_handler,
        empty_ret,
        codes: [codes, shifted_codes, codes],
    }
}

pub(super) fn exit_codes(order: &[u8], scratch: bool) -> Vec<u8> {
    // Only slots still below the caller return address participate in this unwind
    let mut codes = vec![1, 0, (order.len() + if scratch { 2 } else { 0 }) as u8, 0];
    if scratch {
        codes.extend_from_slice(&[0, 1, 32, 0]);
    }
    for &id in order {
        codes.extend_from_slice(&[
            0,
            match id {
                3 | 5 | 6 | 7 | 12..=15 => id << 4,
                _ => 2,
            },
        ]);
    }
    while codes.len() < 8 || !codes.len().is_multiple_of(4) {
        codes.push(0);
    }
    codes
}
