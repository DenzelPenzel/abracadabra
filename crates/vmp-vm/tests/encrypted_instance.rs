use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{
    instance::{BodyInstance, NativeInstance},
    logical::lower_instruction,
};

#[test]
fn encrypted_instance_owns_stream_key_and_processor() {
    let bytes = [0x48, 0x89, 0xc8];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let bodies = [lower_instruction(Architecture::X64, &native).expect("MOV")];
    let base = VirtualAddress(0x140000000);
    for variant in 0..=u8::MAX {
        let encrypted = BodyInstance::generate_encrypted(&bodies, base, variant).expect("body");
        assert_eq!(
            encrypted.initial_key(),
            Some(base.0 + encrypted.stream().start as u64)
        );
        let plain = BodyInstance::generate(&bodies, base, variant).expect("plain");
        assert_ne!(
            &encrypted.image()[encrypted.stream()],
            &plain.image()[plain.stream()]
        );
        let gate = NativeInstance::generate_encrypted(&bodies, base, variant).expect("gate");
        assert!(gate.entry_offset() < gate.image().len());
    }
}
