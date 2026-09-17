use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{
    instance::{BodyInstance, InstanceError},
    logical::lower_instruction,
    operand::Register,
};

fn native(bytes: &[u8]) -> Instruction {
    let raw = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE).decode();
    Instruction::decoded(Rva(0x1000), raw, bytes)
}

#[test]
fn instance_owns_opcode_table_context_and_stream() {
    let mov = native(&[0x48, 0x89, 0xc8]);
    let add = native(&[0x48, 0x01, 0xd0]);
    let bodies = [
        lower_instruction(Architecture::X64, &mov).expect("MOV"),
        lower_instruction(Architecture::X64, &add).expect("ADD"),
    ];
    for variant in 0..=u8::MAX {
        let instance = BodyInstance::generate(&bodies, VirtualAddress(0x140000000), variant)
            .expect("bounded instance");
        let stream = &instance.image()[instance.stream()];
        let &[push, pop, add, _nor, _sp, _load, _immediate, _discard] = instance.opcodes() else {
            panic!("the scalar instance generates only its declared primitives");
        };
        assert_eq!(
            stream,
            [
                push,
                instance.register_offset(Register::Rcx),
                pop,
                instance.register_offset(Register::Rax),
                push,
                instance.register_offset(Register::Rdx),
                push,
                instance.register_offset(Register::Rax),
                add,
                pop,
                instance.flags_offset(),
                pop,
                instance.register_offset(Register::Rax)
            ]
        );
        for (&opcode, &offset) in instance.opcodes().iter().zip(instance.handlers()) {
            let start = instance.table_offset() + usize::from(opcode) * 8;
            let address =
                u64::from_le_bytes(instance.image()[start..start + 8].try_into().expect("slot"));
            assert_eq!(address, 0x140000000 + offset as u64);
        }
        assert_eq!(instance.max_stack_bytes(), 16);
        assert_eq!(
            instance.image(),
            BodyInstance::generate(&bodies, VirtualAddress(0x140000000), variant)
                .expect("replay")
                .image()
        );
    }
}

#[test]
fn sub_emits_composed_primitives_and_never_a_direct_sub_handler() {
    let source = native(&[0x48, 0x29, 0xd0]);
    let body = lower_instruction(Architecture::X64, &source).expect("SUB");
    let instance =
        BodyInstance::generate(&[body], VirtualAddress(0x140000000), 0).expect("instance");
    assert_eq!(instance.max_stack_bytes(), 24);
    let code: Vec<_> = Decoder::new(
        64,
        &instance.image()[..instance.table_offset()],
        DecoderOptions::NONE,
    )
    .into_iter()
    .collect();
    assert!(!code
        .iter()
        .any(|i| i.code() == iced_x86::Code::Sub_r64_rm64));
    assert_eq!(
        code.iter()
            .filter(|i| i.code() == iced_x86::Code::Not_rm64)
            .count(),
        2
    );
    assert!(code
        .iter()
        .any(|i| i.code() == iced_x86::Code::And_rm64_r64));
}

#[test]
fn rejects_empty_oversized_and_overflowing_instances() {
    assert!(matches!(
        BodyInstance::generate(&[], VirtualAddress(0x140000000), 0),
        Err(InstanceError::BodyCount)
    ));
    let mov = native(&[0x48, 0x89, 0xc8]);
    let bodies: Vec<_> = (0..257)
        .map(|_| lower_instruction(Architecture::X64, &mov).expect("MOV"))
        .collect();
    assert!(matches!(
        BodyInstance::generate(&bodies, VirtualAddress(0x140000000), 0),
        Err(InstanceError::BodyCount)
    ));
    for variant in 0..=u8::MAX {
        let maximum = BodyInstance::generate(&bodies[..256], VirtualAddress(0x140000000), variant)
            .expect("maximum accepted count");
        assert_eq!(maximum.stream().len(), 256 * 4);
    }
    assert!(matches!(
        BodyInstance::generate(&bodies[..1], VirtualAddress(u64::MAX), 0),
        Err(InstanceError::AddressOverflow)
    ));
}
