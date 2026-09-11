use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

#[test]
fn leaf_handler_uses_cpp_shadow_layout_and_reports_native_rip_fixup() {
    let bytes = [0x48, 0x01, 0xd0];
    let raw = Decoder::with_ip(64, &bytes, 0x140001000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    for variant in 0..=u8::MAX {
        let instance =
            NativeInstance::generate_leaf_unwind(&bodies, VirtualAddress(0x140002000), variant)
                .expect("leaf unwind");
        let unwind = instance.unwind().expect("body metadata");
        assert_eq!(unwind.exit.len(), 18);
        assert_eq!(unwind.exit[0].0.start, instance.exit_offset());
        assert_eq!(
            unwind.exit.last().expect("RET range").0.end,
            instance.entry_offset()
        );
        for pair in unwind.exit.windows(2) {
            assert_eq!(pair[0].0.end, pair[1].0.start);
        }
        let mut remaining = Vec::new();
        let mut decoder = Decoder::new(
            64,
            &instance.image()[unwind.exit[1].0.start..instance.entry_offset()],
            DecoderOptions::NONE,
        );
        for _ in 0..16 {
            let instruction = decoder.decode();
            let id = match instruction.op0_register() {
                iced_x86::Register::RBX => 0x30,
                iced_x86::Register::RBP => 0x50,
                iced_x86::Register::RSI => 0x60,
                iced_x86::Register::RDI => 0x70,
                iced_x86::Register::R12 => 0xc0,
                iced_x86::Register::R13 => 0xd0,
                iced_x86::Register::R14 => 0xe0,
                iced_x86::Register::R15 => 0xf0,
                _ => 2,
            };
            remaining.push(id);
        }
        for (index, (_, codes)) in unwind.exit.iter().enumerate() {
            let skip = index.saturating_sub(1);
            let mut expected = vec![1, 0, (16 - skip + if index == 0 { 2 } else { 0 }) as u8, 0];
            if index == 0 {
                expected.extend_from_slice(&[0, 1, 32, 0]);
            }
            for &op in &remaining[skip..] {
                expected.extend_from_slice(&[0, op]);
            }
            while expected.len() < 8 || !expected.len().is_multiple_of(4) {
                expected.push(0);
            }
            assert_eq!(codes, &expected);
        }
        assert_eq!(unwind.entry.start, instance.entry_offset());
        assert_eq!(unwind.entry.end, unwind.empty_ret);
        assert_eq!(
            &instance.image()[unwind.entry.end - 2..unwind.entry.end],
            &[0xff, 0xe0]
        );
        assert_eq!(
            unwind.entry_codes[0], 1,
            "entry must not use the body handler"
        );
        let mut decoder = Decoder::with_ip(
            64,
            &instance.image()[unwind.entry.clone()],
            0,
            DecoderOptions::NONE,
        );
        let mut slots = Vec::new();
        for _ in 0..16 {
            let instruction = decoder.decode();
            let op = match instruction.op0_register() {
                iced_x86::Register::RBX => 0x30,
                iced_x86::Register::RBP => 0x50,
                iced_x86::Register::RSI => 0x60,
                iced_x86::Register::RDI => 0x70,
                iced_x86::Register::R12 => 0xc0,
                iced_x86::Register::R13 => 0xd0,
                iced_x86::Register::R14 => 0xe0,
                iced_x86::Register::R15 => 0xf0,
                _ => 2,
            };
            slots.push([instruction.next_ip() as u8, op]);
        }
        assert_eq!(decoder.decode().mnemonic(), iced_x86::Mnemonic::Mov);
        let allocation = decoder.decode();
        assert_eq!(allocation.mnemonic(), iced_x86::Mnemonic::Sub);
        let end = allocation.next_ip() as u8;
        let mut expected = vec![1, end, 18, 0, end, 1, 32, 0];
        for slot in slots.into_iter().rev() {
            expected.extend_from_slice(&slot);
        }
        assert_eq!(unwind.entry_codes.as_slice(), expected.as_slice());
        assert_eq!(unwind.processor[0].start, 0);
        assert!(unwind.processor[2].end < instance.exit_offset());
        assert_eq!(unwind.processor[0].end, unwind.processor[1].start);
        assert_eq!(unwind.processor[1].end, unwind.processor[2].start);
        assert_eq!(
            &instance.image()[unwind.processor[1].clone()],
            &[0x8f, 0x45, 0]
        );
        assert_eq!(instance.image()[unwind.empty_ret], 0xc3);
        assert!(unwind.handler.start > instance.entry_offset());
        assert_eq!(
            unwind.codes[0],
            [0x09, 0, 6, 0, 0, 1, 26, 0, 0, 0x50, 0, 0x60, 0, 0x70, 0, 0x30]
        );
        assert_eq!(unwind.codes[2], unwind.codes[0]);
        let mut shifted = unwind.codes[0];
        shifted[6] = 27;
        assert_eq!(unwind.codes[1], shifted);
        let pointers: Vec<_> = instance.absolute_address_offsets().collect();
        assert_eq!(pointers.len(), 261);
        assert!(pointers.windows(2).all(|w| w[0] < w[1]));
        assert!(pointers
            .iter()
            .any(|&p| instance.image()[p..p + 8] == 0x140001000u64.to_le_bytes()));
    }
}

#[test]
fn leaf_unwind_refuses_nonvolatile_writes() {
    let bytes = [0x48, 0x89, 0xcb];
    let raw = Decoder::with_ip(64, &bytes, 0x140001000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let bodies = [lower_instruction(Architecture::X64, &native).expect("MOV")];
    assert!(NativeInstance::generate_leaf_unwind(&bodies, VirtualAddress(0x140002000), 0).is_err());
}
