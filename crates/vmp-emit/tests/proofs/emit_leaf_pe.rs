//! Emits a DLL with generated body unwind through the production PE writer
use iced_x86::{Decoder, DecoderOptions};
use vmp_emit::vm::{append_leaf_vm_instance, redirect_leaf_vm_instance};
use vmp_ir::Instruction;
use vmp_pe::{ExportTarget, PeFile};
use vmp_types::{Architecture, Rva};
use vmp_vm::logical::lower_instruction;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 && !(args.len() == 4 && args[3] == "--redirect") {
        return Err("input DLL, output DLL, variant required".into());
    }
    let input = std::fs::read(&args[0])?;
    let pe = PeFile::parse(&input)?;
    let export = pe
        .exports
        .as_ref()
        .ok_or("exports")?
        .entries
        .iter()
        .find(|e| e.name.as_deref() == Some("VmOriginal"))
        .ok_or("VmOriginal")?;
    let ExportTarget::Code(rva) = export.target else {
        return Err("forwarder".into());
    };
    let code = pe.mapped_range(&input, rva, 7)?;
    if code != [0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3] {
        return Err("fixture bytes".into());
    }
    let va = rva.to_va(pe.optional.image_base).ok_or("VA")?.0;
    let native: Vec<_> = Decoder::with_ip(64, &code[..6], va, DecoderOptions::NONE)
        .into_iter()
        .map(|raw| {
            let offset = (raw.ip() - va) as usize;
            Instruction::decoded(
                Rva(rva.get() + offset as u32),
                raw,
                &code[offset..offset + raw.len()],
            )
        })
        .collect();
    let bodies = native
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i))
        .collect::<Result<Vec<_>, _>>()?;
    let artifact = if args.len() == 4 {
        redirect_leaf_vm_instance(input, &bodies, args[2].parse()?)?
    } else {
        append_leaf_vm_instance(input, &bodies, args[2].parse()?)?
    };
    println!(
        "{{\"entry\":{},\"instance\":{}}}",
        artifact.placement().entry_rva().get(),
        artifact.placement().rva().get()
    );
    std::fs::write(&args[1], artifact.into_bytes())?;
    Ok(())
}
