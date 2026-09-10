//! Exports generated leaf processors for the independent Windows SEH catcher
use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut native = Vec::new();
    for (offset, bytes) in [(0, [0x48, 0x89, 0xc8]), (3, [0x48, 0x01, 0xd0])] {
        let raw = Decoder::with_ip(64, &bytes, 0x140001000 + offset, DecoderOptions::NONE).decode();
        native.push(Instruction::decoded(
            Rva(0x1000 + offset as u32),
            raw,
            &bytes,
        ));
    }
    let bodies = native
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i))
        .collect::<Result<Vec<_>, _>>()?;
    for variant in [0, 1, 127, 255] {
        let instance =
            NativeInstance::generate_leaf_unwind(&bodies, VirtualAddress(0x140002000), variant)?;
        let u = instance.unwind().expect("leaf metadata");
        println!("{{\"variant\":{},\"image\":{:?},\"entry\":{},\"processor\":{:?},\"handler\":[{},{}],\"shifted_handler\":{},\"empty\":{},\"codes\":{:?}}}",
            variant, instance.image(), instance.entry_offset(), u.processor.each_ref().map(|r| [r.start, r.end]),
            u.handler.start, u.handler.end, u.shifted_handler, u.empty_ret, u.codes);
    }
    Ok(())
}
