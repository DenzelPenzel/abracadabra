//! Exports generated leaf processors for the independent Windows SEH catcher
use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut native = Vec::new();
    let operation = if std::env::args().any(|arg| arg == "--sub") {
        0x29
    } else {
        0x01
    };
    for (offset, bytes) in [(0, [0x48, 0x89, 0xc8]), (3, [0x48, operation, 0xd0])] {
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
        println!("{{\"variant\":{},\"image\":{:?},\"entry\":{},\"processor\":{:?},\"processor_codes\":{:?},\"processor_handlers\":{:?},\"handler\":[{},{}],\"empty\":{},\"entry_codes\":{:?},\"exit_ranges\":{:?},\"exit_codes\":{:?}}}",
            variant, instance.image(), instance.entry_offset(),
            u.processor.iter().map(|p| [p.range.start, p.range.end]).collect::<Vec<_>>(),
            u.processor.iter().map(|p| p.codes).collect::<Vec<_>>(),
            u.processor.iter().map(|p| p.handler).collect::<Vec<_>>(),
            u.handler.start, u.handler.end, u.empty_ret, u.entry_codes,
            u.exit.iter().map(|(r, _)| [r.start, r.end]).collect::<Vec<_>>(),
            u.exit.iter().map(|(_, c)| c).collect::<Vec<_>>());
    }
    Ok(())
}
