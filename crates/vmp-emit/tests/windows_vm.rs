//! Real Windows loader rebasing and scalar gate execution, without generated unwind
#![cfg(all(windows, target_arch = "x86_64"))]

#[path = "support/windows_vm.rs"]
mod os;

use iced_x86::{Decoder, DecoderOptions};
use vmp_emit::vm::append_vm_instance;
use vmp_ir::Instruction;
use vmp_pe::{directory, ExportTarget, Fixup, FixupKind, PeFile};
use vmp_types::{Architecture, Rva};
use vmp_vm::logical::lower_instruction;

fn export(pe: &PeFile, name: &str) -> Rva {
    let entry = pe
        .exports
        .as_ref()
        .expect("fixture exports")
        .entries
        .iter()
        .find(|e| e.name.as_deref() == Some(name))
        .expect("fixture export");
    match &entry.target {
        ExportTarget::Code(rva) => *rva,
        ExportTarget::Forwarder(_) => panic!("fixture must not forward"),
    }
}

fn omit_fixup(bytes: &[u8], target: Rva) -> Vec<u8> {
    let pe = PeFile::parse(bytes).expect("pristine PE");
    let directory = pe
        .data_directory(directory::BASERELOC)
        .expect("relocation directory");
    let start = pe
        .rva_to_offset(directory.address.rva().expect("directory RVA"))
        .expect("mapped directory")
        .get() as usize;
    let mut result = bytes.to_vec();
    let mut block = start;
    let mut removed = 0;
    while block < start + directory.size as usize {
        let page = u32::from_le_bytes(bytes[block..block + 4].try_into().expect("page"));
        let size =
            u32::from_le_bytes(bytes[block + 4..block + 8].try_into().expect("size")) as usize;
        assert!(size >= 8 && block + size <= start + directory.size as usize);
        for offset in (block + 8..block + size).step_by(2) {
            let word = u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("record"));
            if word >> 12 == 10 && page + u32::from(word & 0xfff) == target.get() {
                result[offset..offset + 2].copy_from_slice(&(word & 0xfff).to_le_bytes());
                removed += 1;
            }
        }
        block += size;
    }
    assert_eq!(removed, 1);
    let checksum = PeFile::parse(&result)
        .expect("mutated PE")
        .compute_checksum(&result)
        .expect("checksum");
    let nt = u32::from_le_bytes(result[0x3c..0x40].try_into().expect("PE offset")) as usize;
    result[nt + 88..nt + 92].copy_from_slice(&checksum.to_le_bytes());
    result
}

#[test]
fn windows_loader_rebases_and_executes_serialized_vm() {
    let path =
        std::env::var_os("VMP_VM_DLL_PROBE").expect("build the CI VM DLL and set VMP_VM_DLL_PROBE");
    let input = std::fs::read(path).expect("read DLL");
    let before = PeFile::parse(&input).expect("fixture PE");
    assert_eq!(before.optional.entry_point, Rva(0));
    assert!(before.tls.is_none());
    let original = export(&before, "VmOriginal");
    let anchor = export(&before, "RelocationAnchor");
    let original_fixups = before.base_relocations.as_ref().expect("original fixups");
    assert!(original_fixups.fixups().contains(&Fixup {
        rva: anchor,
        kind: FixupKind::Dir64,
    }));
    let anchor_offset = before.rva_to_offset(anchor).expect("anchor bytes").get() as usize;
    assert_eq!(
        u64::from_le_bytes(
            input[anchor_offset..anchor_offset + 8]
                .try_into()
                .expect("anchor qword")
        ),
        original
            .to_va(before.optional.image_base)
            .expect("original VA")
            .0,
        "fixture anchor must point to the native oracle"
    );
    let offset = before
        .rva_to_offset(original)
        .expect("original bytes")
        .get() as usize;
    let code = &input[offset..offset + 7];
    assert_eq!(code, &[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3]);
    let instructions: Vec<_> = Decoder::with_ip(
        64,
        &code[..6],
        u64::from(original.get()),
        DecoderOptions::NONE,
    )
    .into_iter()
    .map(|raw| {
        let start = (raw.ip() - u64::from(original.get())) as usize;
        Instruction::decoded(Rva(raw.ip() as u32), raw, &code[start..start + raw.len()])
    })
    .collect();
    let bodies = instructions
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i))
        .collect::<Result<Vec<_>, _>>()
        .expect("lower actual fixture instructions");
    let dir = std::env::temp_dir().join(format!("vmp-windows-vm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let _reservation = os::Reservation::at(before.optional.image_base.0);
    for variant in [0, 1, 15, 255] {
        let artifact = append_vm_instance(input.clone(), &bodies, variant).expect("embed VM");
        let entry = artifact.placement().entry_rva();
        let omitted = artifact.placement().relocations().fixups()[0].rva;
        let expected_fixups: Vec<_> = original_fixups
            .fixups()
            .iter()
            .chain(artifact.placement().relocations().fixups())
            .copied()
            .collect();
        let bytes = artifact.into_bytes();
        let pe = PeFile::parse(&bytes).expect("serialized PE");
        let serialized_fixups = pe
            .base_relocations
            .as_ref()
            .expect("serialized fixups")
            .fixups();
        assert_eq!(
            serialized_fixups.len(),
            expected_fixups.len(),
            "complete fixup count"
        );
        for fixup in &expected_fixups {
            assert!(
                serialized_fixups.contains(fixup),
                "lost expected fixup: {fixup:?}"
            );
        }
        for negative in [false, true] {
            let file = dir.join(format!("vm-{variant}-{negative}.dll"));
            std::fs::write(
                &file,
                if negative {
                    omit_fixup(&bytes, omitted)
                } else {
                    bytes.clone()
                },
            )
            .expect("write DLL");
            let loaded = os::Module::load(&file, pe.optional.size_of_image as usize);
            let delta = i128::from(loaded.base()) - i128::from(pe.optional.image_base.0);
            assert_ne!(delta, 0, "must exercise loader relocation");
            assert_eq!(loaded.base() & 0xffff, 0);
            assert_eq!(
                loaded.qword(anchor),
                loaded
                    .base()
                    .checked_add(u64::from(original.get()))
                    .expect("loaded original VA"),
                "Windows must relocate the inherited anchor"
            );
            let mut mismatches = Vec::new();
            for fixup in &expected_fixups {
                assert_eq!(fixup.kind, FixupKind::Dir64);
                let pos = pe.rva_to_offset(fixup.rva).expect("fixup bytes").get() as usize;
                let old = u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("qword"));
                let expected = u64::try_from(i128::from(old) + delta).expect("relocated pointer");
                if loaded.qword(fixup.rva) != expected {
                    mismatches.push(fixup.rva);
                }
            }
            println!("variant={variant} negative={negative} preferred={:#x} loaded={:#x} delta={delta} mismatches={mismatches:?}", pe.optional.image_base.0, loaded.base());
            if negative {
                assert_eq!(
                    mismatches,
                    [omitted],
                    "serialized omission must be observable"
                );
            } else {
                assert!(mismatches.is_empty());
                for (lhs, rhs, result, flags) in [
                    (0, 0, 0, 0x246),
                    (1, 2, 3, 0x206),
                    (u64::MAX, 1, 0, 0x257),
                    (i64::MAX as u64, 1, 1 << 63, 0xa96),
                ] {
                    let native = loaded.snapshot(original, lhs, rhs);
                    let vm = loaded.snapshot(entry, lhs, rhs);
                    assert_eq!(vm[..16], native[..16], "GPRs and flags after RET");
                    assert_eq!(vm[0], result);
                    assert_eq!(vm[15], flags);
                    for snapshot in [native, vm] {
                        assert_eq!(snapshot[16], snapshot[17], "balanced RSP");
                        assert_eq!(snapshot[18], 0x5a5a5a5a5a5a5a5a, "stack canary");
                    }
                }
            }
            drop(loaded);
            std::fs::remove_file(file).expect("remove unloaded DLL");
        }
    }
    std::fs::remove_dir(dir).expect("remove scratch directory");
}
