use iced_x86::{Code, Decoder, DecoderOptions, Register};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

#[test]
fn fixups_cover_exactly_the_decoded_gate_pointers_and_entire_table() {
    let bytes = [0x48, 0x01, 0xd0];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    let native = Instruction::decoded(Rva(0x1000), raw, &bytes);
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    let base = 0x140005123;
    for encrypted in [false, true] {
        for variant in 0..=u8::MAX {
            let instance = if encrypted {
                NativeInstance::generate_encrypted(&bodies, VirtualAddress(base), variant)
            } else {
                NativeInstance::generate(&bodies, VirtualAddress(base), variant)
            }
            .expect("placed gate");
            let mut decoder = Decoder::with_ip(
                64,
                &instance.image()[instance.entry_offset()..],
                base + instance.entry_offset() as u64,
                DecoderOptions::NONE,
            );
            let mut expected = Vec::new();
            let mut table = None;
            while decoder.can_decode() {
                let instruction = decoder.decode();
                assert!(!instruction.is_invalid());
                if instruction.code() == Code::Mov_r64_imm64 {
                    let fields = decoder.get_constant_offsets(&instruction);
                    assert_eq!(fields.immediate_size(), 8);
                    expected.push((instruction.ip() - base) as usize + fields.immediate_offset());
                    if instruction.op0_register() == Register::R10 {
                        table = Some((instruction.immediate64() - base) as usize);
                    }
                }
            }
            assert_eq!(expected.len(), if encrypted { 4 } else { 3 });
            let table = table.expect("decoded dispatch table pointer");
            expected.extend((table..table + 256 * 8).step_by(8));
            expected.sort_unstable();
            let actual: Vec<_> = instance.absolute_address_offsets().collect();
            assert_eq!(actual, expected, "encrypted={encrypted}, variant={variant}");
            for &offset in &actual {
                let address = u64::from_le_bytes(
                    instance.image()[offset..offset + 8]
                        .try_into()
                        .expect("qword"),
                );
                assert!((base..base + instance.image().len() as u64).contains(&address));
            }
            // Independently apply only reported loader fixups; no replacement image is executed
            let mut relocated = instance.image().to_vec();
            for offset in actual {
                let value =
                    u64::from_le_bytes(relocated[offset..offset + 8].try_into().expect("qword"));
                relocated[offset..offset + 8].copy_from_slice(&(value + 0x10000).to_le_bytes());
            }
            let regenerated = if encrypted {
                NativeInstance::generate_encrypted(&bodies, VirtualAddress(base + 0x10000), variant)
            } else {
                NativeInstance::generate(&bodies, VirtualAddress(base + 0x10000), variant)
            }
            .expect("aligned rebase");
            assert_eq!(relocated, regenerated.image());
        }
    }
}
