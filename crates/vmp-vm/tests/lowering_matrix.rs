use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction as IcedInstruction,
    Register as IcedRegister,
};
use vmp_ir::{
    BasicBlock, BlockId, CompileStage, Function, Instruction as NativeInstruction, Terminator,
};
use vmp_types::{Architecture, Rva};
use vmp_vm::{
    bytecode::{Instruction, Register, Width},
    lowering::lower,
};

fn straight_line_function(bytes: &[u8]) -> Function {
    let entry = Rva(0x1000);
    let mut decoder = Decoder::with_ip(64, bytes, u64::from(entry.get()), DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let raw = decoder.decode();
        let offset = usize::try_from(raw.ip() - u64::from(entry.get())).expect("small fixture");
        instructions.push(NativeInstruction::decoded(
            Rva(u32::try_from(raw.ip()).expect("small fixture")),
            raw,
            &bytes[offset..offset + raw.len()],
        ));
    }
    Function {
        architecture: Architecture::X64,
        entry,
        blocks: vec![BasicBlock {
            id: BlockId(0),
            start: entry,
            end: entry
                .checked_add(u32::try_from(bytes.len()).expect("small fixture"))
                .expect("small fixture"),
            instructions,
            terminator: Terminator::Return,
            successors: vec![],
            predecessors: vec![],
        }],
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    }
}

#[test]
fn lowers_every_supported_gpr_width_operation_and_source_form() {
    let logical = [
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
    let byte = [
        IcedRegister::AL,
        IcedRegister::CL,
        IcedRegister::DL,
        IcedRegister::BL,
        IcedRegister::BPL,
        IcedRegister::SIL,
        IcedRegister::DIL,
        IcedRegister::R8L,
        IcedRegister::R9L,
        IcedRegister::R10L,
        IcedRegister::R11L,
        IcedRegister::R12L,
        IcedRegister::R13L,
        IcedRegister::R14L,
        IcedRegister::R15L,
    ];
    let word = [
        IcedRegister::AX,
        IcedRegister::CX,
        IcedRegister::DX,
        IcedRegister::BX,
        IcedRegister::BP,
        IcedRegister::SI,
        IcedRegister::DI,
        IcedRegister::R8W,
        IcedRegister::R9W,
        IcedRegister::R10W,
        IcedRegister::R11W,
        IcedRegister::R12W,
        IcedRegister::R13W,
        IcedRegister::R14W,
        IcedRegister::R15W,
    ];
    let dword = [
        IcedRegister::EAX,
        IcedRegister::ECX,
        IcedRegister::EDX,
        IcedRegister::EBX,
        IcedRegister::EBP,
        IcedRegister::ESI,
        IcedRegister::EDI,
        IcedRegister::R8D,
        IcedRegister::R9D,
        IcedRegister::R10D,
        IcedRegister::R11D,
        IcedRegister::R12D,
        IcedRegister::R13D,
        IcedRegister::R14D,
        IcedRegister::R15D,
    ];
    let qword = [
        IcedRegister::RAX,
        IcedRegister::RCX,
        IcedRegister::RDX,
        IcedRegister::RBX,
        IcedRegister::RBP,
        IcedRegister::RSI,
        IcedRegister::RDI,
        IcedRegister::R8,
        IcedRegister::R9,
        IcedRegister::R10,
        IcedRegister::R11,
        IcedRegister::R12,
        IcedRegister::R13,
        IcedRegister::R14,
        IcedRegister::R15,
    ];
    let matrices = [
        (
            &byte,
            Width::Byte,
            [
                Code::Mov_r8_rm8,
                Code::Add_rm8_r8,
                Code::Sub_rm8_r8,
                Code::Xor_rm8_r8,
            ],
            [
                Code::Mov_r8_imm8,
                Code::Add_rm8_imm8,
                Code::Sub_rm8_imm8,
                Code::Xor_rm8_imm8,
            ],
        ),
        (
            &word,
            Width::Word,
            [
                Code::Mov_r16_rm16,
                Code::Add_rm16_r16,
                Code::Sub_rm16_r16,
                Code::Xor_rm16_r16,
            ],
            [
                Code::Mov_r16_imm16,
                Code::Add_rm16_imm16,
                Code::Sub_rm16_imm16,
                Code::Xor_rm16_imm16,
            ],
        ),
        (
            &dword,
            Width::Dword,
            [
                Code::Mov_r32_rm32,
                Code::Add_rm32_r32,
                Code::Sub_rm32_r32,
                Code::Xor_rm32_r32,
            ],
            [
                Code::Mov_r32_imm32,
                Code::Add_rm32_imm32,
                Code::Sub_rm32_imm32,
                Code::Xor_rm32_imm32,
            ],
        ),
        (
            &qword,
            Width::Qword,
            [
                Code::Mov_r64_rm64,
                Code::Add_rm64_r64,
                Code::Sub_rm64_r64,
                Code::Xor_rm64_r64,
            ],
            [
                Code::Mov_r64_imm64,
                Code::Add_rm64_imm32,
                Code::Sub_rm64_imm32,
                Code::Xor_rm64_imm32,
            ],
        ),
    ];
    let encode_with_ret = |instruction: &IcedInstruction| {
        let mut encoder = Encoder::new(64);
        encoder
            .encode(instruction, 0x1000)
            .expect("matrix instruction must encode");
        let mut bytes = encoder.take_buffer();
        bytes.push(0xc3);
        bytes
    };

    for (native, width, register_codes, immediate_codes) in matrices {
        for (destination_index, destination) in native.iter().copied().enumerate() {
            let source_index = (destination_index + 1) % native.len();
            let source = native[source_index];
            let logical_destination = logical[destination_index];
            let logical_source = logical[source_index];
            for operation_index in 0..4 {
                let raw =
                    IcedInstruction::with2(register_codes[operation_index], destination, source)
                        .expect("matrix register form must construct");
                let function = straight_line_function(&encode_with_ret(&raw));
                let mut expected = expected_register_form(
                    operation_index,
                    width,
                    logical_destination,
                    logical_source,
                );
                expected.push(Instruction::Ret);
                assert_eq!(
                    lower(&function)
                        .unwrap_or_else(|error| panic!("register matrix form failed: {error}"))
                        .instructions(),
                    expected,
                    "register form {width:?} {destination:?}, {source:?}"
                );

                let raw =
                    IcedInstruction::with2(immediate_codes[operation_index], destination, 1u64)
                        .expect("matrix immediate form must construct");
                let function = straight_line_function(&encode_with_ret(&raw));
                let mut expected =
                    expected_immediate_form(operation_index, width, logical_destination);
                expected.push(Instruction::Ret);
                assert_eq!(
                    lower(&function)
                        .unwrap_or_else(|error| panic!("immediate matrix form failed: {error}"))
                        .instructions(),
                    expected,
                    "immediate form {width:?} {destination:?}, 1"
                );
            }
        }
    }
}

fn operation(index: usize, width: Width) -> Instruction {
    match index {
        1 => Instruction::Add(width),
        2 => Instruction::Sub(width),
        3 => Instruction::Xor(width),
        _ => unreachable!("MOV has no arithmetic operation"),
    }
}

fn expected_register_form(
    operation_index: usize,
    width: Width,
    destination: Register,
    source: Register,
) -> Vec<Instruction> {
    if operation_index == 0 {
        return vec![
            Instruction::PushReg {
                width,
                register: source,
            },
            Instruction::PopReg {
                width,
                register: destination,
            },
        ];
    }
    vec![
        Instruction::PushReg {
            width,
            register: destination,
        },
        Instruction::PushReg {
            width,
            register: source,
        },
        operation(operation_index, width),
        Instruction::PopReg {
            width,
            register: destination,
        },
    ]
}

fn expected_immediate_form(
    operation_index: usize,
    width: Width,
    destination: Register,
) -> Vec<Instruction> {
    if operation_index == 0 {
        return vec![
            Instruction::PushImm { width, value: 1 },
            Instruction::PopReg {
                width,
                register: destination,
            },
        ];
    }
    vec![
        Instruction::PushReg {
            width,
            register: destination,
        },
        Instruction::PushImm { width, value: 1 },
        operation(operation_index, width),
        Instruction::PopReg {
            width,
            register: destination,
        },
    ]
}
