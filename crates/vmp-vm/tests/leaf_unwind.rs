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
        assert_eq!(unwind.processor.start, 0);
        assert!(unwind.processor.end < instance.exit_offset());
        assert_eq!(instance.image()[unwind.empty_ret], 0xc3);
        assert!(unwind.handler.start > instance.entry_offset());
        assert_eq!(
            unwind.codes,
            [0x09, 0, 6, 0, 5, 1, 26, 0, 4, 0x50, 3, 0x60, 2, 0x70, 1, 0x30]
        );
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
