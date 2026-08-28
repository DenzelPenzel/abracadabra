use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::{
    BasicBlock, BlockId, CompileStage, DecodeIssue, Edge, EdgeKind, EdgeTarget, Function,
    Instruction as NativeInstruction, Terminator,
};
use vmp_types::{Architecture, Rva};
use vmp_vm::{
    bytecode::{
        decode as decode_program, encode, Condition, Instruction, Register, Width, MAX_INSTRUCTIONS,
    },
    lowering::{lower, LoweringError},
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
            successors: Vec::new(),
            predecessors: Vec::new(),
        }],
        entry_block: BlockId(0),
        unwind: None,
        issues: Vec::new(),
        stage: CompileStage::Decoded,
    }
}

fn branch_to_next_function(bytes: &[u8], terminator: Terminator) -> Function {
    let entry = Rva(0x1000);
    let target = entry
        .checked_add(u32::try_from(bytes.len()).expect("small fixture"))
        .expect("small fixture");
    let mut branch_decoder =
        Decoder::with_ip(64, bytes, u64::from(entry.get()), DecoderOptions::NONE);
    let branch = branch_decoder.decode();
    let mut ret_decoder =
        Decoder::with_ip(64, &[0xc3], u64::from(target.get()), DecoderOptions::NONE);
    let successors = match terminator {
        Terminator::Jump => vec![Edge::new(EdgeKind::Jump, EdgeTarget::Block(BlockId(1)))],
        Terminator::Conditional => vec![
            Edge::new(EdgeKind::Taken, EdgeTarget::Block(BlockId(1))),
            Edge::new(EdgeKind::NotTaken, EdgeTarget::Block(BlockId(1))),
        ],
        _ => panic!("branch fixture requires direct branch terminator"),
    };
    Function {
        architecture: Architecture::X64,
        entry,
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                start: entry,
                end: target,
                instructions: vec![NativeInstruction::decoded(entry, branch, bytes)],
                terminator,
                successors,
                predecessors: vec![],
            },
            BasicBlock {
                id: BlockId(1),
                start: target,
                end: target.checked_add(1).expect("small fixture"),
                instructions: vec![NativeInstruction::decoded(
                    target,
                    ret_decoder.decode(),
                    &[0xc3],
                )],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![BlockId(0)],
            },
        ],
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    }
}

#[test]
fn lowers_a_physical_near_jmp() {
    let function = branch_to_next_function(&[0xe9, 0, 0, 0, 0], Terminator::Jump);
    assert_eq!(
        lower(&function)
            .expect("near jmp must lower")
            .instructions(),
        &[Instruction::Jmp { target: 5 }, Instruction::Ret]
    );
}

#[test]
fn lowers_a_physical_near_jcc() {
    let function = branch_to_next_function(&[0x0f, 0x84, 0, 0, 0, 0], Terminator::Conditional);
    assert_eq!(
        lower(&function).expect("near je must lower").instructions(),
        &[
            Instruction::Jcc {
                condition: Condition::E,
                target: 6,
            },
            Instruction::Ret,
        ]
    );
}

#[test]
fn lowers_mov_and_add_immediate_to_logical_stack_commands() {
    let function = straight_line_function(&[
        0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, imm64
        0x48, 0x83, 0xc0, 0xfb, // add rax, -5
        0xc3, // ret
    ]);

    let program = lower(&function).expect("curated register/immediate subset must lower");
    assert_eq!(program.entry_offset(), 0);
    assert_eq!(
        program.instructions(),
        &[
            Instruction::PushImm {
                width: Width::Qword,
                value: 0x1122_3344_5566_7788,
            },
            Instruction::PopReg {
                width: Width::Qword,
                register: Register::Rax,
            },
            Instruction::PushReg {
                width: Width::Qword,
                register: Register::Rax,
            },
            Instruction::PushImm {
                width: Width::Qword,
                value: u64::MAX - 4,
            },
            Instruction::Add(Width::Qword),
            Instruction::PopReg {
                width: Width::Qword,
                register: Register::Rax,
            },
            Instruction::Ret,
        ]
    );
}

#[test]
fn rejects_native_rsp_with_a_typed_error() {
    let function = straight_line_function(&[
        0x48, 0xbc, 1, 0, 0, 0, 0, 0, 0, 0, // mov rsp, 1
        0xc3,
    ]);

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnsupportedRegister {
            rva: Some(Rva(0x1000)),
            register: iced_x86::Register::RSP,
        })
    );
}

#[test]
fn lowers_register_and_immediate_arithmetic_at_every_width() {
    let function = straight_line_function(&[
        0xb0, 0xfe, // mov al, 0xfe
        0x04, 0x02, // add al, 2
        0x66, 0xb9, 0x34, 0x12, // mov cx, 0x1234
        0x66, 0x83, 0xe9, 0x03, // sub cx, 3
        0x41, 0xb8, 0xef, 0xcd, 0xab, 0x89, // mov r8d, 0x89abcdef
        0x45, 0x31, 0xc8, // xor r8d, r9d
        0x49, 0xbf, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // mov r15, imm64
        0x4d, 0x01, 0xf7, // add r15, r14
        0xc3,
    ]);

    let program = lower(&function).expect("curated width/register matrix must lower");
    assert_eq!(
        program.instructions(),
        &[
            Instruction::PushImm {
                width: Width::Byte,
                value: 0xfe
            },
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax
            },
            Instruction::PushReg {
                width: Width::Byte,
                register: Register::Rax
            },
            Instruction::PushImm {
                width: Width::Byte,
                value: 2
            },
            Instruction::Add(Width::Byte),
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax
            },
            Instruction::PushImm {
                width: Width::Word,
                value: 0x1234
            },
            Instruction::PopReg {
                width: Width::Word,
                register: Register::Rcx
            },
            Instruction::PushReg {
                width: Width::Word,
                register: Register::Rcx
            },
            Instruction::PushImm {
                width: Width::Word,
                value: 3
            },
            Instruction::Sub(Width::Word),
            Instruction::PopReg {
                width: Width::Word,
                register: Register::Rcx
            },
            Instruction::PushImm {
                width: Width::Dword,
                value: 0x89ab_cdef
            },
            Instruction::PopReg {
                width: Width::Dword,
                register: Register::R8
            },
            Instruction::PushReg {
                width: Width::Dword,
                register: Register::R8
            },
            Instruction::PushReg {
                width: Width::Dword,
                register: Register::R9
            },
            Instruction::Xor(Width::Dword),
            Instruction::PopReg {
                width: Width::Dword,
                register: Register::R8
            },
            Instruction::PushImm {
                width: Width::Qword,
                value: 0x0102_0304_0506_0708,
            },
            Instruction::PopReg {
                width: Width::Qword,
                register: Register::R15
            },
            Instruction::PushReg {
                width: Width::Qword,
                register: Register::R15
            },
            Instruction::PushReg {
                width: Width::Qword,
                register: Register::R14
            },
            Instruction::Add(Width::Qword),
            Instruction::PopReg {
                width: Width::Qword,
                register: Register::R15
            },
            Instruction::Ret,
        ]
    );
}

#[test]
fn rejects_wrong_architecture_and_incomplete_ir_before_lowering() {
    let mut wrong_architecture = straight_line_function(&[0xc3]);
    wrong_architecture.architecture = Architecture::X86;
    assert_eq!(
        lower(&wrong_architecture),
        Err(LoweringError::UnsupportedArchitecture {
            architecture: Architecture::X86,
        })
    );

    let issue = DecodeIssue::InvalidOpcode { rva: Rva(0x1000) };
    let mut incomplete = straight_line_function(&[0xc3]);
    incomplete.issues.push(issue);
    assert_eq!(
        lower(&incomplete),
        Err(LoweringError::IncompleteFunction { issue })
    );
}

#[test]
fn rejects_lowered_instruction_expansion_one_over_the_v1_limit() {
    let mut function = straight_line_function(&[0x48, 0x83, 0xc0, 0x01, 0xc3]);
    let decoded_add = function.blocks[0].instructions[0].clone();
    let inserted_add = NativeInstruction::inserted(*decoded_add.raw(), decoded_add.bytes());
    let ret = function.blocks[0].instructions[1].clone();
    function.blocks[0].instructions = vec![inserted_add; MAX_INSTRUCTIONS / 4 - 1];
    function.blocks[0].instructions.insert(0, decoded_add);
    function.blocks[0].instructions.push(ret);

    assert_eq!(
        lower(&function),
        Err(LoweringError::TooManyInstructions {
            count: MAX_INSTRUCTIONS + 1,
            maximum: MAX_INSTRUCTIONS,
        })
    );
}

#[test]
fn rejects_too_many_blocks_before_deep_validation() {
    let blocks = (0..=MAX_INSTRUCTIONS)
        .map(|index| BasicBlock {
            id: BlockId(u32::try_from(index).expect("v1 limit fits u32")),
            start: Rva(u32::try_from(index).expect("v1 limit fits u32")),
            end: Rva(u32::try_from(index).expect("v1 limit fits u32")),
            instructions: vec![],
            terminator: Terminator::Return,
            successors: vec![],
            predecessors: vec![],
        })
        .collect();
    let function = Function {
        architecture: Architecture::X64,
        entry: Rva(0),
        blocks,
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    };

    assert_eq!(
        lower(&function),
        Err(LoweringError::TooManyBlocks {
            count: MAX_INSTRUCTIONS + 1,
            maximum: MAX_INSTRUCTIONS,
        })
    );
}

#[test]
fn rejects_too_many_native_instructions_before_deep_validation() {
    let mut function = straight_line_function(&[0x48, 0x83, 0xc0, 0x01, 0xc3]);
    let add = &function.blocks[0].instructions[0];
    let inserted_add = NativeInstruction::inserted(*add.raw(), add.bytes());
    let ret = function.blocks[0].instructions[1].clone();
    function.blocks[0].instructions = vec![inserted_add; MAX_INSTRUCTIONS];
    function.blocks[0].instructions.push(ret);

    assert_eq!(
        lower(&function),
        Err(LoweringError::TooManyNativeInstructions {
            count: MAX_INSTRUCTIONS + 1,
            maximum: MAX_INSTRUCTIONS,
        })
    );
}

#[test]
fn rejects_cfg_relation_amplification_before_deep_validation() {
    const MAX_CFG_RELATIONS: usize = MAX_INSTRUCTIONS * 4;
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0].predecessors = vec![BlockId(0); MAX_CFG_RELATIONS + 1];

    assert_eq!(
        lower(&function),
        Err(LoweringError::TooManyCfgRelations {
            count: MAX_CFG_RELATIONS + 1,
            maximum: MAX_CFG_RELATIONS,
        })
    );
}

#[test]
fn lowers_cfg_edges_to_vm_byte_offsets() {
    let decode = |rva: u32, bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, u64::from(rva), DecoderOptions::NONE);
        let raw = decoder.decode();
        NativeInstruction::decoded(Rva(rva), raw, bytes)
    };
    let function = Function {
        architecture: Architecture::X64,
        entry: Rva(0x1000),
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
                end: Rva(0x1002),
                instructions: vec![decode(0x1000, &[0x74, 0x02])], // je 0x1004
                terminator: Terminator::Conditional,
                successors: vec![
                    Edge::new(EdgeKind::Taken, EdgeTarget::Block(BlockId(2))),
                    Edge::new(EdgeKind::NotTaken, EdgeTarget::Block(BlockId(1))),
                ],
                predecessors: vec![],
            },
            BasicBlock {
                id: BlockId(1),
                start: Rva(0x1002),
                end: Rva(0x1004),
                instructions: vec![decode(0x1002, &[0xeb, 0x02])], // jmp 0x1006
                terminator: Terminator::Jump,
                successors: vec![Edge::new(EdgeKind::Jump, EdgeTarget::Block(BlockId(3)))],
                predecessors: vec![BlockId(0)],
            },
            BasicBlock {
                id: BlockId(2),
                start: Rva(0x1004),
                end: Rva(0x1006),
                instructions: vec![decode(0x1004, &[0xb0, 0x01])], // mov al, 1
                terminator: Terminator::FallThrough,
                successors: vec![Edge::new(
                    EdgeKind::FallThrough,
                    EdgeTarget::Block(BlockId(3)),
                )],
                predecessors: vec![BlockId(0)],
            },
            BasicBlock {
                id: BlockId(3),
                start: Rva(0x1006),
                end: Rva(0x1007),
                instructions: vec![decode(0x1006, &[0xc3])],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![BlockId(1), BlockId(2)],
            },
        ],
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    };

    let program = lower(&function).expect("complete direct CFG must lower");
    assert_eq!(program.entry_offset(), 0);
    assert_eq!(
        program.instructions(),
        &[
            Instruction::Jcc {
                condition: Condition::E,
                target: 11,
            },
            Instruction::Jmp { target: 17 },
            Instruction::PushImm {
                width: Width::Byte,
                value: 1,
            },
            Instruction::PopReg {
                width: Width::Byte,
                register: Register::Rax,
            },
            Instruction::Ret,
        ]
    );
    let encoded = encode(&program).expect("lowered CFG must satisfy bytecode v1 preflight");
    assert_eq!(
        decode_program(&encoded).expect("encoded lowered CFG must decode"),
        program
    );
}

#[test]
fn rejects_duplicate_native_block_starts() {
    let mut function = straight_line_function(&[0xc3]);
    let mut duplicate = function.blocks[0].clone();
    duplicate.id = BlockId(1);
    function.blocks.push(duplicate);

    assert_eq!(
        lower(&function),
        Err(LoweringError::DuplicateBlockStart { rva: Rva(0x1000) })
    );
}

#[test]
fn lowers_all_sixteen_physical_jcc_opcodes() {
    let conditions = [
        Condition::O,
        Condition::No,
        Condition::B,
        Condition::Ae,
        Condition::E,
        Condition::Ne,
        Condition::Be,
        Condition::A,
        Condition::S,
        Condition::Ns,
        Condition::P,
        Condition::Np,
        Condition::L,
        Condition::Ge,
        Condition::Le,
        Condition::G,
    ];

    for (low_nibble, condition) in conditions.into_iter().enumerate() {
        let opcode = 0x70 | u8::try_from(low_nibble).expect("condition table index");
        let branch_bytes = [opcode, 0];
        let mut branch_decoder = Decoder::with_ip(64, &branch_bytes, 0x1000, DecoderOptions::NONE);
        let branch = branch_decoder.decode();
        let mut ret_decoder = Decoder::with_ip(64, &[0xc3], 0x1002, DecoderOptions::NONE);
        let ret = ret_decoder.decode();
        let function = Function {
            architecture: Architecture::X64,
            entry: Rva(0x1000),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    start: Rva(0x1000),
                    end: Rva(0x1002),
                    instructions: vec![NativeInstruction::decoded(
                        Rva(0x1000),
                        branch,
                        &branch_bytes,
                    )],
                    terminator: Terminator::Conditional,
                    successors: vec![
                        Edge::new(EdgeKind::Taken, EdgeTarget::Block(BlockId(1))),
                        Edge::new(EdgeKind::NotTaken, EdgeTarget::Block(BlockId(1))),
                    ],
                    predecessors: vec![],
                },
                BasicBlock {
                    id: BlockId(1),
                    start: Rva(0x1002),
                    end: Rva(0x1003),
                    instructions: vec![NativeInstruction::decoded(Rva(0x1002), ret, &[0xc3])],
                    terminator: Terminator::Return,
                    successors: vec![],
                    predecessors: vec![BlockId(0)],
                },
            ],
            entry_block: BlockId(0),
            unwind: None,
            issues: vec![],
            stage: CompileStage::Decoded,
        };

        let program = lower(&function)
            .unwrap_or_else(|error| panic!("short Jcc opcode 0x{opcode:02x} must lower: {error}"));
        assert_eq!(
            program.instructions(),
            &[
                Instruction::Jcc {
                    condition,
                    target: 6,
                },
                Instruction::Ret
            ],
            "short Jcc opcode 0x{opcode:02x}"
        );
    }
}

#[test]
fn lowers_all_sixteen_physical_near_jcc_opcodes() {
    let conditions = [
        Condition::O,
        Condition::No,
        Condition::B,
        Condition::Ae,
        Condition::E,
        Condition::Ne,
        Condition::Be,
        Condition::A,
        Condition::S,
        Condition::Ns,
        Condition::P,
        Condition::Np,
        Condition::L,
        Condition::Ge,
        Condition::Le,
        Condition::G,
    ];

    for (low_nibble, condition) in conditions.into_iter().enumerate() {
        let opcode = 0x80 | u8::try_from(low_nibble).expect("condition table index");
        let bytes = [0x0f, opcode, 0, 0, 0, 0];
        let function = branch_to_next_function(&bytes, Terminator::Conditional);
        let program = lower(&function)
            .unwrap_or_else(|error| panic!("near Jcc opcode 0x0f{opcode:02x} must lower: {error}"));
        assert_eq!(
            program.instructions(),
            &[
                Instruction::Jcc {
                    condition,
                    target: 6,
                },
                Instruction::Ret,
            ],
            "near Jcc opcode 0x0f{opcode:02x}"
        );
    }
}

#[test]
fn rejects_an_invalid_native_entry_block() {
    let mut function = straight_line_function(&[0xc3]);
    function.entry_block = BlockId(1);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidEntryBlock {
            entry_block: BlockId(1),
        })
    );
}

#[test]
fn rejects_external_cfg_edges_before_lowering() {
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0]
        .successors
        .push(Edge::new(EdgeKind::Jump, EdgeTarget::External(Rva(0x2000))));

    assert_eq!(
        lower(&function),
        Err(LoweringError::ExternalEdge {
            block: BlockId(0),
            kind: EdgeKind::Jump,
            target: Rva(0x2000),
        })
    );
}

#[test]
fn rejects_successors_that_conflict_with_the_native_terminator() {
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0]
        .successors
        .push(Edge::new(EdgeKind::Jump, EdgeTarget::Block(BlockId(0))));

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidSuccessorShape {
            block: BlockId(0),
            terminator: Terminator::Return,
        })
    );
}

#[test]
fn validates_every_local_successor_shape_before_reciprocal_edges() {
    let mut function = straight_line_function(&[0xc3]);
    let mut decoder = Decoder::with_ip(64, &[0xc3], 0x1010, DecoderOptions::NONE);
    function.blocks[0].predecessors = vec![BlockId(1)];
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1010),
        end: Rva(0x1011),
        instructions: vec![NativeInstruction::decoded(
            Rva(0x1010),
            decoder.decode(),
            &[0xc3],
        )],
        terminator: Terminator::Return,
        successors: vec![Edge::new(EdgeKind::Jump, EdgeTarget::Block(BlockId(1)))],
        predecessors: vec![],
    });

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidSuccessorShape {
            block: BlockId(1),
            terminator: Terminator::Return,
        })
    );
}

#[test]
fn rejects_an_internal_edge_to_a_missing_block() {
    let mut function = straight_line_function(&[0xb0, 0x01]);
    function.blocks[0].terminator = Terminator::FallThrough;
    function.blocks[0].successors = vec![Edge::new(
        EdgeKind::FallThrough,
        EdgeTarget::Block(BlockId(1)),
    )];

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidInternalEdge {
            block: BlockId(0),
            kind: EdgeKind::FallThrough,
            target: BlockId(1),
        })
    );
}

#[test]
fn rejects_a_taken_edge_that_disagrees_with_the_physical_branch_target() {
    let decode = |rva: u32, bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, u64::from(rva), DecoderOptions::NONE);
        NativeInstruction::decoded(Rva(rva), decoder.decode(), bytes)
    };
    let function = Function {
        architecture: Architecture::X64,
        entry: Rva(0x1000),
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
                end: Rva(0x1002),
                instructions: vec![decode(0x1000, &[0x74, 0x01])], // je 0x1003
                terminator: Terminator::Conditional,
                successors: vec![
                    Edge::new(EdgeKind::Taken, EdgeTarget::Block(BlockId(1))),
                    Edge::new(EdgeKind::NotTaken, EdgeTarget::Block(BlockId(1))),
                ],
                predecessors: vec![],
            },
            BasicBlock {
                id: BlockId(1),
                start: Rva(0x1002),
                end: Rva(0x1003),
                instructions: vec![decode(0x1002, &[0xc3])],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![BlockId(0)],
            },
            BasicBlock {
                id: BlockId(2),
                start: Rva(0x1003),
                end: Rva(0x1004),
                instructions: vec![decode(0x1003, &[0xc3])],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![],
            },
        ],
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    };

    assert_eq!(
        lower(&function),
        Err(LoweringError::EdgeRvaMismatch {
            block: BlockId(0),
            kind: EdgeKind::Taken,
            expected: Rva(0x1003),
            actual: Rva(0x1002),
        })
    );
}

#[test]
fn rejects_an_empty_native_basic_block() {
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0].instructions.clear();

    assert_eq!(
        lower(&function),
        Err(LoweringError::EmptyBlock { block: BlockId(0) })
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn rejects_a_zero_length_decoded_instruction_in_release() {
    let mut function = straight_line_function(&[0xc3]);
    let raw = *function.blocks[0].instructions[0].raw();
    function.blocks[0].instructions[0] = NativeInstruction::decoded(Rva(0x1000), raw, &[]);
    function.blocks[0].end = Rva(0x1000);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidInstructionLength {
            block: BlockId(0),
            rva: Rva(0x1000),
            expected: 1,
            actual: 0,
        })
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn rejects_a_nonzero_raw_and_stored_length_mismatch_in_release() {
    let mut function = straight_line_function(&[0xc3]);
    let raw = *function.blocks[0].instructions[0].raw();
    function.blocks[0].instructions[0] =
        NativeInstruction::decoded(Rva(0x1000), raw, &[0xc3, 0x90]);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InvalidInstructionLength {
            block: BlockId(0),
            rva: Rva(0x1000),
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn rejects_a_return_terminator_without_a_physical_ret() {
    let function = straight_line_function(&[0xb0, 0x01]);

    assert_eq!(
        lower(&function),
        Err(LoweringError::TerminatorInstructionMismatch {
            block: BlockId(0),
            terminator: Terminator::Return,
            code: iced_x86::Code::Mov_r8_imm8,
        })
    );
}

#[test]
fn rejects_an_interior_physical_control_transfer() {
    let decode = |rva: u32, bytes: &[u8]| {
        let mut decoder = Decoder::with_ip(64, bytes, u64::from(rva), DecoderOptions::NONE);
        NativeInstruction::decoded(Rva(rva), decoder.decode(), bytes)
    };
    let function = Function {
        architecture: Architecture::X64,
        entry: Rva(0x1000),
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                start: Rva(0x1000),
                end: Rva(0x1003),
                instructions: vec![decode(0x1000, &[0xeb, 0x0e]), decode(0x1002, &[0xc3])],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![],
            },
            BasicBlock {
                id: BlockId(1),
                start: Rva(0x1010),
                end: Rva(0x1013),
                instructions: vec![decode(0x1010, &[0xb0, 0x01]), decode(0x1012, &[0xc3])],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![],
            },
        ],
        entry_block: BlockId(0),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    };

    assert_eq!(
        lower(&function),
        Err(LoweringError::InteriorControlFlow {
            block: BlockId(0),
            rva: Some(Rva(0x1000)),
            code: iced_x86::Code::Jmp_rel8_64,
        })
    );
}

#[test]
fn rejects_an_interior_physical_conditional_branch() {
    let function = straight_line_function(&[0x74, 0x00, 0xc3]);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InteriorControlFlow {
            block: BlockId(0),
            rva: Some(Rva(0x1000)),
            code: iced_x86::Code::Je_rel8_64,
        })
    );
}

#[test]
fn rejects_an_interior_physical_return() {
    let function = straight_line_function(&[0xc3, 0xc3]);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InteriorControlFlow {
            block: BlockId(0),
            rva: Some(Rva(0x1000)),
            code: iced_x86::Code::Retnq,
        })
    );
}

#[test]
fn rejects_a_native_block_whose_instructions_do_not_tile_its_range() {
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0].end = Rva(0x1002);

    assert_eq!(
        lower(&function),
        Err(LoweringError::BlockEndMismatch {
            block: BlockId(0),
            declared: Rva(0x1002),
            tiled: Rva(0x1001),
        })
    );
}

#[test]
fn rejects_a_gap_between_decoded_instructions() {
    let mut function = straight_line_function(&[0xb0, 0x01, 0xc3]);
    let mut decoder = Decoder::with_ip(64, &[0xc3], 0x1003, DecoderOptions::NONE);
    function.blocks[0].instructions[1] =
        NativeInstruction::decoded(Rva(0x1003), decoder.decode(), &[0xc3]);
    function.blocks[0].end = Rva(0x1004);

    assert_eq!(
        lower(&function),
        Err(LoweringError::InstructionRvaMismatch {
            block: BlockId(0),
            expected: Rva(0x1002),
            actual: Rva(0x1003),
        })
    );
}

#[test]
fn rejects_overlapping_native_block_ranges() {
    let mut function = straight_line_function(&[0xb0, 0x01, 0xc3]);
    let ret = function.blocks[0].instructions[1].clone();
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1002),
        end: Rva(0x1003),
        instructions: vec![ret],
        terminator: Terminator::Return,
        successors: vec![],
        predecessors: vec![],
    });

    assert_eq!(
        lower(&function),
        Err(LoweringError::OverlappingBlocks {
            first: BlockId(0),
            second: BlockId(1),
        })
    );
}

#[test]
fn rejects_an_entry_block_that_disagrees_with_the_entry_rva() {
    let mut function = straight_line_function(&[0xc3]);
    let mut decoder = Decoder::with_ip(64, &[0xc3], 0x1001, DecoderOptions::NONE);
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1001),
        end: Rva(0x1002),
        instructions: vec![NativeInstruction::decoded(
            Rva(0x1001),
            decoder.decode(),
            &[0xc3],
        )],
        terminator: Terminator::Return,
        successors: vec![],
        predecessors: vec![],
    });
    function.entry_block = BlockId(1);

    assert_eq!(
        lower(&function),
        Err(LoweringError::EntryBlockMismatch {
            entry_block: BlockId(1),
            entry: Rva(0x1000),
            block_start: Rva(0x1001),
        })
    );
}

#[test]
fn rejects_a_block_id_that_disagrees_with_its_dense_index() {
    let mut function = straight_line_function(&[0xc3]);
    function.blocks[0].id = BlockId(7);

    assert_eq!(
        lower(&function),
        Err(LoweringError::BlockIdMismatch {
            index: 0,
            actual: BlockId(7),
        })
    );
}

#[test]
fn rejects_a_successor_missing_its_reciprocal_predecessor() {
    let mut function = straight_line_function(&[0xb0, 0x01, 0xc3]);
    let ret = function.blocks[0].instructions.pop().expect("ret");
    function.blocks[0].end = Rva(0x1002);
    function.blocks[0].terminator = Terminator::FallThrough;
    function.blocks[0].successors = vec![Edge::new(
        EdgeKind::FallThrough,
        EdgeTarget::Block(BlockId(1)),
    )];
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1002),
        end: Rva(0x1003),
        instructions: vec![ret],
        terminator: Terminator::Return,
        successors: vec![],
        predecessors: vec![],
    });

    assert_eq!(
        lower(&function),
        Err(LoweringError::MissingPredecessor {
            block: BlockId(1),
            predecessor: BlockId(0),
        })
    );
}

#[test]
fn rejects_a_duplicate_predecessor() {
    let mut function = straight_line_function(&[0xb0, 0x01, 0xc3]);
    let ret = function.blocks[0].instructions.pop().expect("ret");
    function.blocks[0].end = Rva(0x1002);
    function.blocks[0].terminator = Terminator::FallThrough;
    function.blocks[0].successors = vec![Edge::new(
        EdgeKind::FallThrough,
        EdgeTarget::Block(BlockId(1)),
    )];
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1002),
        end: Rva(0x1003),
        instructions: vec![ret],
        terminator: Terminator::Return,
        successors: vec![],
        predecessors: vec![BlockId(0), BlockId(0)],
    });

    assert_eq!(
        lower(&function),
        Err(LoweringError::DuplicatePredecessor {
            block: BlockId(1),
            predecessor: BlockId(0),
        })
    );
}

#[test]
fn rejects_a_predecessor_without_a_reciprocal_successor() {
    let mut function = straight_line_function(&[0xc3]);
    let mut decoder = Decoder::with_ip(64, &[0xc3], 0x1001, DecoderOptions::NONE);
    function.blocks.push(BasicBlock {
        id: BlockId(1),
        start: Rva(0x1001),
        end: Rva(0x1002),
        instructions: vec![NativeInstruction::decoded(
            Rva(0x1001),
            decoder.decode(),
            &[0xc3],
        )],
        terminator: Terminator::Return,
        successors: vec![],
        predecessors: vec![BlockId(0)],
    });

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnexpectedPredecessor {
            block: BlockId(1),
            predecessor: BlockId(0),
        })
    );
}

#[test]
fn rejects_a_physical_high_byte_register() {
    let function = straight_line_function(&[0xb4, 0x01, 0xc3]); // mov ah, 1; ret

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnsupportedRegister {
            rva: Some(Rva(0x1000)),
            register: iced_x86::Register::AH,
        })
    );
}

#[test]
fn rejects_a_physical_memory_source() {
    let function = straight_line_function(&[0x48, 0x8b, 0x03, 0xc3]); // mov rax, [rbx]

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnsupportedInstruction {
            rva: Some(Rva(0x1000)),
            code: iced_x86::Code::Mov_r64_rm64,
        })
    );
}

#[test]
fn rejects_a_physical_memory_destination() {
    let function = straight_line_function(&[0x48, 0x89, 0x03, 0xc3]); // mov [rbx], rax

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnsupportedInstruction {
            rva: Some(Rva(0x1000)),
            code: iced_x86::Code::Mov_rm64_r64,
        })
    );
}

#[test]
fn rejects_a_physical_indirect_jump() {
    let mut function = straight_line_function(&[0xff, 0xe0]); // jmp rax
    function.blocks[0].terminator = Terminator::IndirectJump;

    assert_eq!(
        lower(&function),
        Err(LoweringError::UnsupportedTerminator {
            block: BlockId(0),
            terminator: Terminator::IndirectJump,
        })
    );
}

#[test]
fn lays_out_dense_blocks_deterministically_by_rva() {
    let decode_ret = |rva: u32| {
        let mut decoder = Decoder::with_ip(64, &[0xc3], u64::from(rva), DecoderOptions::NONE);
        NativeInstruction::decoded(Rva(rva), decoder.decode(), &[0xc3])
    };
    let function = Function {
        architecture: Architecture::X64,
        entry: Rva(0x1000),
        blocks: vec![
            BasicBlock {
                id: BlockId(0),
                start: Rva(0x1001),
                end: Rva(0x1002),
                instructions: vec![decode_ret(0x1001)],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![],
            },
            BasicBlock {
                id: BlockId(1),
                start: Rva(0x1000),
                end: Rva(0x1001),
                instructions: vec![decode_ret(0x1000)],
                terminator: Terminator::Return,
                successors: vec![],
                predecessors: vec![],
            },
        ],
        entry_block: BlockId(1),
        unwind: None,
        issues: vec![],
        stage: CompileStage::Decoded,
    };

    let program = lower(&function).expect("dense blocks need not be stored in RVA order");
    assert_eq!(program.entry_offset(), 0);
    assert_eq!(
        program.instructions(),
        &[Instruction::Ret, Instruction::Ret]
    );
}
