use iced_x86::{Decoder, DecoderOptions};
use vmp_emit::vm::{append_vm_instance, VmEmbeddingError};
use vmp_ir::Instruction;
use vmp_pe::{PeError, PeFile};
use vmp_types::{Architecture, Rva};
use vmp_vm::logical::lower_instruction;

const X64: &[u8] = include_bytes!("../../vmp-pe/test-corpus/win64-app-msvc-amd64");
const X86: &[u8] = include_bytes!("../../vmp-pe/test-corpus/win32-app-test1-i386");

fn native() -> Instruction {
    let bytes = [0x48, 0x01, 0xd0];
    let raw = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE).decode();
    Instruction::decoded(Rva(0x1000), raw, &bytes)
}

#[test]
fn serialized_vm_preserves_original_image_and_merges_fixups() {
    let native = native();
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    for input in [X64, &include_bytes!("../../vmp-pe/test-corpus/seh-x64")[..]] {
        let before = PeFile::parse(input).expect("fixture");
        let artifact = append_vm_instance(input.to_vec(), &bodies, 37).expect("append VM");
        let output = artifact.bytes();
        let after = PeFile::parse(output).expect("serialized artifact");
        let placement = artifact.placement();
        assert_eq!(after.sections.len(), before.sections.len() + 2);
        assert_eq!(after.optional.entry_point, before.optional.entry_point);
        assert_eq!(after.optional.image_base, before.optional.image_base);
        assert_eq!(after.imports, before.imports);
        assert_eq!(after.exports, before.exports);
        assert_eq!(after.tls, before.tls);
        assert_eq!(after.exception_table, before.exception_table);
        for section in &before.sections {
            let start = section.pointer_to_raw_data.get() as usize;
            let end = start + section.size_of_raw_data as usize;
            assert_eq!(&output[start..end], &input[start..end]);
        }
        let code = &after.sections[before.sections.len()];
        assert_eq!(code.characteristics, 0x6000_0020);
        assert_eq!(code.virtual_address, placement.rva());
        let start = after
            .rva_to_offset(placement.rva())
            .expect("VM mapped")
            .get() as usize;
        assert_eq!(
            &output[start..start + placement.image().len()],
            placement.image()
        );
        let relocations = after.base_relocations.as_ref().expect("merged relocations");
        let old = before
            .base_relocations
            .as_ref()
            .expect("original relocations");
        assert_eq!(relocations.len(), old.len() + placement.relocations().len());
        for fixup in old.fixups().iter().chain(placement.relocations().fixups()) {
            assert!(relocations.fixups().contains(fixup));
        }
        assert_eq!(
            output,
            append_vm_instance(input.to_vec(), &bodies, 37)
                .expect("replay")
                .bytes()
        );
    }
}

#[test]
fn unsupported_images_return_no_partial_artifact() {
    let native = native();
    let bodies = [lower_instruction(Architecture::X64, &native).expect("ADD")];
    assert!(matches!(
        append_vm_instance(X86.to_vec(), &bodies, 0),
        Err(VmEmbeddingError::Architecture)
    ));
    let mut stripped = X64.to_vec();
    let pe = u32::from_le_bytes(stripped[0x3c..0x40].try_into().expect("PE offset")) as usize;
    stripped[pe + 22] |= 1;
    assert!(matches!(
        append_vm_instance(stripped, &bodies, 0),
        Err(VmEmbeddingError::Pe(
            PeError::UnsupportedRewriteLayout { .. }
        ))
    ));
    assert!(matches!(
        append_vm_instance(Vec::new(), &bodies, 0),
        Err(VmEmbeddingError::Pe(_))
    ));
}
