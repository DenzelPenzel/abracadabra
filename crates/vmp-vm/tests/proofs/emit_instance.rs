//! Emits a test artifact description, not a product file format or execution adapter
use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::BodyInstance, logical::lower_instruction, operand::Register};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let native: Vec<_> = [&[0x48, 0x89, 0xc8][..], &[0x48, 0x01, 0xd0][..]]
        .into_iter()
        .map(|bytes| {
            let raw = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE).decode();
            Instruction::decoded(Rva(0x1000), raw, bytes)
        })
        .collect();
    let bodies = native
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i))
        .collect::<Result<Vec<_>, _>>()?;
    let registers = [
        Register::Rax,
        Register::Rcx,
        Register::Rdx,
        Register::Rbx,
        Register::Rbp,
        Register::Rsi,
        Register::Rdi,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    for variant in 0..=u8::MAX {
        let instance = if std::env::args().any(|arg| arg == "--encrypted") {
            BodyInstance::generate_encrypted(&bodies, VirtualAddress(0x140000000), variant)?
        } else {
            BodyInstance::generate(&bodies, VirtualAddress(0x140000000), variant)?
        };
        let offsets: Vec<_> = registers
            .iter()
            .map(|r| instance.register_offset(*r))
            .collect();
        println!("{{\"variant\":{},\"image\":{:?},\"entry\":{},\"done\":{},\"table\":{},\"stream\":[{},{}],\"handlers\":{:?},\"opcodes\":{:?},\"registers\":{:?},\"flags\":{},\"key\":{}}}",
            variant, instance.image(), instance.entry_offset(), instance.completion_offset(),
            instance.table_offset(), instance.stream().start, instance.stream().end,
            instance.handlers(), instance.opcodes(), offsets, instance.flags_offset(),
            instance.initial_key().map_or("null".to_owned(), |key| key.to_string()));
    }
    Ok(())
}
