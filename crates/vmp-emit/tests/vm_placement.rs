use iced_x86::{Decoder, DecoderOptions};
use vmp_emit::vm::{VmPlacement, VmPlacementError};
use vmp_ir::Instruction;
use vmp_pe::FixupKind;
use vmp_types::{Architecture, ImageBase, Rva};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

fn native() -> Instruction {
    let bytes = [0x48, 0x01, 0xd0];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    Instruction::decoded(Rva(0x1000), raw, &bytes)
}

#[test]
fn placement_translates_owned_fixups_to_pe_coordinates() {
    let native = native();
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    let base = ImageBase(0x140000000);
    for rva in [Rva(0x5123), Rva(0x805123)] {
        for variant in [0, 1, 255] {
            let placed = VmPlacement::generate(&bodies, base, rva, variant).expect("placement");
            let instance =
                NativeInstance::generate_encrypted(&bodies, rva.to_va(base).expect("VA"), variant)
                    .expect("instance");
            assert_eq!(placed.rva(), rva);
            assert_eq!(placed.image(), instance.image());
            assert_eq!(placed.entry_rva().0, rva.0 + instance.entry_offset() as u32);
            let fixups = placed.relocations().fixups();
            assert_eq!(fixups.len(), 260);
            for (fixup, offset) in fixups.iter().zip(instance.absolute_address_offsets()) {
                assert_eq!(fixup.kind, FixupKind::Dir64);
                assert_eq!(fixup.rva.0, rva.0 + offset as u32);
            }
        }
    }
}

#[test]
fn placement_refuses_invalid_base_and_coordinate_overflow() {
    let native = native();
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    let base = ImageBase(0x140000000);
    assert!(matches!(
        VmPlacement::generate(&bodies, ImageBase(base.0 + 1), Rva(0x1000), 0),
        Err(VmPlacementError::ImageBaseAlignment)
    ));
    assert!(matches!(
        VmPlacement::generate(&bodies, ImageBase(!0xffff), Rva(0x10000), 0),
        Err(VmPlacementError::AddressOverflow)
    ));
    assert!(matches!(
        VmPlacement::generate(&bodies, base, Rva(u32::MAX), 0),
        Err(VmPlacementError::RvaOverflow)
    ));
    let placed = VmPlacement::generate(&bodies, base, Rva(0x1000), 0).expect("length");
    let last = u32::MAX - u32::try_from(placed.image().len()).expect("bounded length");
    VmPlacement::generate(&bodies, base, Rva(last), 0).expect("exact RVA extent boundary");
    assert!(matches!(
        VmPlacement::generate(&bodies, base, Rva(last + 1), 0),
        Err(VmPlacementError::RvaOverflow)
    ));
    assert!(matches!(
        VmPlacement::generate(&[], base, Rva(0x1000), 0),
        Err(VmPlacementError::Instance(_))
    ));
}
