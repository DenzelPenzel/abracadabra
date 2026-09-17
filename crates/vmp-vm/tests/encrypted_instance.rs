use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{
    instance::{BodyInstance, NativeInstance},
    logical::lower_instruction,
};

#[test]
fn qword_immediates_are_loaded_and_decrypted_as_one_full_width_field() {
    let bytes = [0x48, 0x29, 0xd0];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let body = lower_instruction(Architecture::X64, &native).expect("SUB");
    let instance =
        BodyInstance::generate_encrypted(&[body], VirtualAddress(0x140000000), 0).expect("body");
    let handler = &instance.image()[instance.handlers()[6]..instance.handlers()[7]];
    let code: Vec<_> = Decoder::new(64, handler, DecoderOptions::NONE)
        .into_iter()
        .collect();
    let loads: Vec<_> = code
        .iter()
        .filter(|i| i.memory_base() == iced_x86::Register::RSI)
        .collect();
    assert_eq!(loads.len(), 1, "one qword field, not eight byte fields");
    assert_eq!(loads[0].code(), iced_x86::Code::Mov_r64_rm64);
    assert!(code
        .iter()
        .any(|i| i.code() == iced_x86::Code::Xor_rm64_r64
            && i.op0_register() == iced_x86::Register::RDI));
}

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
