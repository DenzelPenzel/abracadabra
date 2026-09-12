use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_pe::PeFile;
use vmp_types::Architecture;
use vmp_vm::logical::lower_instruction;

#[test]
fn redirected_leaf_preserves_ret_and_targets_generated_entry() {
    let mut image = vmp_pe::PeImage::from_bytes(
        include_bytes!("../../vmp-pe/test-corpus/win64-app-msvc-amd64").to_vec(),
    )
    .expect("fixture");
    let rva = image.next_section_rva().expect("leaf RVA");
    let code = [0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3, 0x90];
    image
        .add_section(vmp_pe::NewSection {
            name: ".leaf",
            data: &code,
            characteristics: 0x6000_0020,
        })
        .expect("leaf");
    let va = rva.to_va(image.pe().optional.image_base).expect("VA").0;
    let source: Vec<_> = Decoder::with_ip(64, &code[..6], va, DecoderOptions::NONE)
        .into_iter()
        .map(|raw| {
            let offset = (raw.ip() - va) as usize;
            Instruction::decoded(
                rva.checked_add(offset as u32).expect("RVA"),
                raw,
                &code[offset..offset + raw.len()],
            )
        })
        .collect();
    let bodies: Vec<_> = source
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i).expect("lower"))
        .collect();
    let artifact = vmp_emit::vm::redirect_leaf_vm_instance(image.bytes().to_vec(), &bodies, 37)
        .expect("redirect");
    let pe = PeFile::parse(artifact.bytes()).expect("PE");
    let patched = pe.mapped_range(artifact.bytes(), rva, 7).expect("gate");
    let jump = Decoder::with_ip(64, patched, va, DecoderOptions::NONE).decode();
    assert_eq!(jump.mnemonic(), iced_x86::Mnemonic::Jmp);
    assert_eq!(
        jump.near_branch_target(),
        artifact
            .placement()
            .entry_rva()
            .to_va(pe.optional.image_base)
            .expect("entry VA")
            .0
    );
    assert_eq!(&patched[5..], &[0x90, 0xc3]);
    assert!(matches!(
        vmp_emit::vm::redirect_leaf_vm_instance(image.bytes().to_vec(), &bodies[1..], 37),
        Err(vmp_emit::vm::VmEmbeddingError::LeafSource)
    ));
    image
        .extend_base_relocations(
            ".fix",
            &[vmp_pe::Fixup {
                rva,
                kind: vmp_pe::FixupKind::Dir64,
            }],
        )
        .expect("relocation");
    assert!(matches!(
        vmp_emit::vm::redirect_leaf_vm_instance(image.into_bytes(), &bodies, 37),
        Err(vmp_emit::vm::VmEmbeddingError::LeafSource)
    ));
}
