use vmp_compiler::virtualization::{protect_virtualization, Error, Request};
use vmp_pe::PeFile;
use vmp_types::Rva;

fn image(target: u32) -> Vec<u8> {
    let mut bytes = vec![0; 0x400];
    for (at, value) in [
        (0, 0x5a4d_u16),
        (0x44, 0x8664),
        (0x46, 1),
        (0x54, 240),
        (0x58, 0x20b),
        (0x9c, 3),
    ] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (0x3c, 0x40_u32),
        (0x40, 0x4550),
        (0x68, 0x1010),
        (0x78, 0x1000),
        (0x7c, 0x200),
        (0x90, 0x2000),
        (0x94, 0x200),
        (0xc4, 16),
        (0x150, 0x200),
        (0x154, 0x1000),
        (0x158, 0x200),
        (0x15c, 0x200),
        (0x16c, 0x6000_0020),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x70..0x78].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    bytes[0x148..0x14d].copy_from_slice(b".text");
    bytes[0x200..0x207].copy_from_slice(&[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3]);
    bytes[0x210] = 0xe8;
    bytes[0x211..0x215].copy_from_slice(&(i64::from(target) - 0x1015).to_le_bytes()[..4]);
    bytes[0x215] = 0xc3;
    bytes[0xf0..0xf4].copy_from_slice(&0x1040_u32.to_le_bytes());
    bytes[0xf4..0xf8].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x248..0x24a].copy_from_slice(&0xa060_u16.to_le_bytes());
    bytes[0x260..0x268].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    PeFile::parse(&bytes).expect("synthetic PE");
    bytes
}

fn request(image: Vec<u8>) -> Request {
    Request {
        image,
        rva: Rva(0x1000),
        external_entries: Vec::new(),
        seed: 37,
    }
}

#[test]
fn redirects_a_leaf_reached_by_a_known_call() {
    let input = image(0x1000);
    let product = protect_virtualization(request(input.clone())).expect("protect leaf");
    let pe = PeFile::parse(&product.image).expect("protected PE");
    let gate = pe
        .mapped_range(&product.image, Rva(0x1000), 7)
        .expect("gate");
    assert_eq!(gate[0], 0xe9);
    let delta = i32::from_le_bytes(gate[1..5].try_into().expect("rel32"));
    assert_eq!(i64::from(product.entry.get()), 0x1005 + i64::from(delta));
    assert_eq!(&gate[5..], &[0x90, 0xc3]);
    assert_eq!(
        product.image,
        protect_virtualization(request(input))
            .expect("replay")
            .image
    );
}

#[test]
fn refuses_a_known_call_into_the_replaced_interior() {
    assert!(matches!(
        protect_virtualization(request(image(0x1003))),
        Err(Error::InteriorEntry {
            target: Rva(0x1003),
            ..
        })
    ));
}

#[test]
fn refuses_a_declared_external_entry_into_the_replaced_interior() {
    let mut input = request(image(0x1000));
    input.external_entries.push(Rva(0x1001));
    assert!(matches!(
        protect_virtualization(input),
        Err(Error::InteriorEntry {
            target: Rva(0x1001),
            ..
        })
    ));
}

#[test]
fn refuses_an_unresolved_indirect_caller() {
    let mut bytes = image(0x1000);
    bytes[0x210..0x213].copy_from_slice(&[0xff, 0xd0, 0xc3]);
    assert!(matches!(
        protect_virtualization(request(bytes)),
        Err(Error::UnresolvedControlFlow { .. })
    ));
}

#[test]
fn refuses_an_instruction_overlapping_the_selected_mov_leaf() {
    let mut bytes = image(0x1000);
    bytes[0x210..0x218].copy_from_slice(&[0xb8, 0x48, 0x89, 0xc8, 0x48, 0x89, 0xc8, 0xc3]);
    let mut input = request(bytes);
    input.rva = Rva(0x1011);
    input.external_entries.push(Rva(0x1010));
    assert!(
        matches!(
            protect_virtualization(input),
            Err(Error::OverlappingCode { rva: Rva(0x1010) })
        ),
        "overlapping MOV must not be patched"
    );
}

#[test]
fn accepts_aligned_fallthrough_to_the_selected_leaf() {
    let mut bytes = image(0x1000);
    bytes[0x210..0x218].copy_from_slice(&[0x90, 0x48, 0x89, 0xc8, 0x48, 0x89, 0xc8, 0xc3]);
    let mut input = request(bytes);
    input.rva = Rva(0x1011);
    input.external_entries.push(Rva(0x1010));
    assert!(protect_virtualization(input).is_ok());
}

#[test]
fn does_not_decode_a_rip_relative_loads_data_as_a_function() {
    let mut bytes = image(0x1000);
    bytes[0x210..0x218].copy_from_slice(&[0x48, 0x8b, 0x05, 0x19, 0, 0, 0, 0xc3]);
    bytes[0x230..0x238].copy_from_slice(&[0xff, 0xe0, 0, 0, 0, 0, 0, 0]);
    assert!(
        protect_virtualization(request(bytes)).is_ok(),
        "data in .text is not a code root"
    );
}

#[test]
fn refuses_an_interior_call_from_an_exception_handler() {
    let mut bytes = image(0x1000);
    bytes[0xe0..0xe4].copy_from_slice(&0x1080_u32.to_le_bytes());
    bytes[0xe4..0xe8].copy_from_slice(&12_u32.to_le_bytes());
    for (offset, value) in [
        (0x280, 0x1010_u32),
        (0x284, 0x1016),
        (0x288, 0x1090),
        (0x294, 0x1030),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x290] = 9;
    bytes[0x230..0x236].copy_from_slice(&[0xe8, 0xce, 0xff, 0xff, 0xff, 0xc3]);
    assert!(matches!(
        protect_virtualization(request(bytes)),
        Err(Error::InteriorEntry {
            target: Rva(0x1003),
            ..
        })
    ));
}

#[test]
fn still_refuses_a_data_reference_into_the_replaced_interior() {
    let mut bytes = image(0x1000);
    bytes[0x210..0x218].copy_from_slice(&[0x48, 0x8b, 0x05, 0xec, 0xff, 0xff, 0xff, 0xc3]);
    assert!(matches!(
        protect_virtualization(request(bytes)),
        Err(Error::InteriorEntry {
            target: Rva(0x1003),
            ..
        })
    ));
}
