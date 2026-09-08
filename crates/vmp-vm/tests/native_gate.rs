use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

#[test]
fn native_gate_is_generated_with_the_body_layout() {
    let bytes = [0x48, 0x89, 0xc8];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let body = lower_instruction(Architecture::X64, &native).expect("MOV");
    for variant in 0..=u8::MAX {
        let gate = NativeInstance::generate(
            std::slice::from_ref(&body),
            VirtualAddress(0x140000000),
            variant,
        )
        .expect("gate");
        assert!(gate.entry_offset() < gate.image().len());
        assert!(gate.exit_offset() < gate.entry_offset());
        assert_eq!(gate.max_native_stack_bytes(), 392);
    }
}
