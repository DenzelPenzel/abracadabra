//! Writes a PE proof artifact without redirecting its original entry point
use iced_x86::{Decoder, DecoderOptions};
use vmp_emit::vm::append_vm_instance;
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva};
use vmp_vm::logical::lower_instruction;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let output = args.next().ok_or("expected output path and variant")?;
    let variant: u8 = args.next().ok_or("expected variant")?.parse()?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let code = [0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0];
    let native: Vec<_> = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE)
        .into_iter()
        .map(|raw| {
            let offset = (raw.ip() - 0x1000) as usize;
            Instruction::decoded(Rva(raw.ip() as u32), raw, &code[offset..offset + raw.len()])
        })
        .collect();
    let bodies = native
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i))
        .collect::<Result<Vec<_>, _>>()?;
    let artifact = append_vm_instance(
        include_bytes!("../../../vmp-pe/test-corpus/win64-app-msvc-amd64").to_vec(),
        &bodies,
        variant,
    )?;
    let placement = artifact.placement();
    println!(
        "{{\"variant\":{},\"entry_rva\":{},\"instance_rva\":{},\"instance_len\":{}}}",
        variant,
        placement.entry_rva().get(),
        placement.rva().get(),
        placement.image().len()
    );
    std::fs::write(output, artifact.into_bytes())?;
    Ok(())
}
