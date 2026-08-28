#![cfg(target_arch = "x86_64")]

use core::arch::asm;

use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::{
    BasicBlock, BlockId, CompileStage, Function, Instruction as NativeInstruction, Terminator,
};
use vmp_pe::PeFile;
use vmp_types::{Architecture, Rva};
use vmp_vm::{
    bytecode::{decode, encode, Register, Width},
    host::{execute, MachineState, Termination},
    lowering::lower,
};
use vmp_x86::{decode_function, Image};

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const ARITHMETIC_DEFINED: u64 = CF | PF | AF | ZF | SF | OF;
const XOR_DEFINED: u64 = CF | PF | ZF | SF | OF;

#[derive(Debug, Clone, Copy)]
enum Operation {
    Add,
    Sub,
    Xor,
}

#[derive(Debug, Clone, Copy)]
struct NativeResult {
    rax: u64,
    rflags: u64,
}

#[derive(Debug, Clone, Copy)]
struct NativeMovResult {
    rax: u64,
    flags_before: u64,
    flags_after: u64,
}

const BRANCH_EQUAL: u64 = 0x2222_2222_2222_2222;
const BRANCH_NOT_EQUAL: u64 = 0x1111_1111_1111_1111;

#[test]
fn native_arithmetic_matches_lowered_decoded_host_v1() {
    for operation in [Operation::Add, Operation::Sub, Operation::Xor] {
        for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
            for (lhs, rhs) in edge_vectors(operation, width) {
                compare_native_with_lowered(operation, width, lhs, rhs);
            }
        }
    }
}

#[test]
fn native_mov_matches_lowered_decoded_host_v1() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        compare_native_mov_with_lowered(width, false);
        compare_native_mov_with_lowered(width, true);
    }
}

#[test]
fn native_conditional_and_join_branches_match_lowered_decoded_host_v1() {
    for (lhs, rhs) in [(0, 0), (1, 2), (u64::MAX, u64::MAX), (0, u64::MAX)] {
        let function = branching_function();
        let lowered = lower(&function).expect("curated branch function must lower");
        let encoded = encode(&lowered).expect("lowered branch program must encode");
        let decoded = decode(&encoded).expect("physical branch program must decode independently");

        let mut initial = MachineState::default();
        initial.set_register(Register::Rax, lhs);
        initial.set_register(Register::Rcx, rhs);
        let vm = execute(&decoded, initial).expect("lowered branch function must terminate");
        let native = run_native_branch(lhs, rhs);

        assert_eq!(vm.termination(), Termination::Ret);
        assert_eq!(vm.state().stack_len(), 0);
        assert_eq!(vm.state().register(Register::Rax), native.rax);
        assert_eq!(vm.state().flags_defined(), ARITHMETIC_DEFINED);
        assert_eq!(
            vm.state().flags_bits() & ARITHMETIC_DEFINED,
            native.rflags & ARITHMETIC_DEFINED,
            "flag mismatch for lhs=0x{lhs:x}, rhs=0x{rhs:x}"
        );
    }
}

fn branching_function() -> Function {
    // sub rax, rcx; je equal; mov rax, NOT_EQUAL; jmp end;
    // equal: mov rax, EQUAL; end: ret
    let text = [
        0x48, 0x29, 0xc8, 0x74, 0x0c, 0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0xeb, 0x0a, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0xc3,
    ];
    let image = minimal_pe64(&text);
    let pe = PeFile::parse(&image).expect("branch fixture must be a valid PE32+ image");
    decode_function(Image::new(&pe, &image), Rva(0x1000))
        .expect("production decoder must recover the branch CFG")
}

fn minimal_pe64(text: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 0x400];
    put_u16(&mut image, 0, 0x5a4d);
    put_u32(&mut image, 0x3c, 0x40);
    put_u32(&mut image, 0x40, 0x0000_4550);
    put_u16(&mut image, 0x44, 0x8664);
    put_u16(&mut image, 0x46, 1);
    put_u16(&mut image, 0x54, 240);
    put_u16(&mut image, 0x58, 0x20b);
    put_u32(&mut image, 0x58 + 16, 0x1000);
    put_u64(&mut image, 0x58 + 24, 0x1_4000_0000);
    put_u32(&mut image, 0x58 + 32, 0x1000);
    put_u32(&mut image, 0x58 + 36, 0x200);
    put_u32(&mut image, 0x58 + 56, 0x2000);
    put_u32(&mut image, 0x58 + 60, 0x200);
    put_u16(&mut image, 0x58 + 68, 3);
    put_u32(&mut image, 0x58 + 108, 16);
    let section = 0x148;
    image[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut image, section + 8, 0x200);
    put_u32(&mut image, section + 12, 0x1000);
    put_u32(&mut image, section + 16, 0x200);
    put_u32(&mut image, section + 20, 0x200);
    put_u32(&mut image, section + 36, 0x6000_0020);
    image[0x200..0x200 + text.len()].copy_from_slice(text);
    image
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn edge_vectors(operation: Operation, width: Width) -> [(u64, u64); 6] {
    // These boundaries are pinned independently of the host arithmetic formulas.
    let (sign, sign_max, mask) = match width {
        Width::Byte => (0x80, 0x7f, 0xff),
        Width::Word => (0x8000, 0x7fff, 0xffff),
        Width::Dword => (0x8000_0000, 0x7fff_ffff, 0xffff_ffff),
        Width::Qword => (0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff, u64::MAX),
    };
    match operation {
        Operation::Add => [
            (0, 0),
            (1, 1),
            (sign_max, 1),
            (mask, 1),
            (sign, sign),
            (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
        ],
        Operation::Sub => [
            (0, 0),
            (1, 1),
            (0, 1),
            (sign, 1),
            (sign_max, mask),
            (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
        ],
        Operation::Xor => [
            (0, 0),
            (1, 1),
            (sign, 0),
            (mask, sign),
            (sign_max, mask),
            (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
        ],
    }
}

fn compare_native_with_lowered(operation: Operation, width: Width, lhs: u64, rhs: u64) {
    let bytes = physical_bytes(operation, width);
    let function = straight_line_function(&bytes);
    let lowered = lower(&function).expect("curated arithmetic must lower");
    let encoded = encode(&lowered).expect("lowered v1 must encode");
    let decoded = decode(&encoded).expect("physical v1 must decode independently");

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, lhs);
    initial.set_register(Register::Rcx, rhs);
    let vm = execute(&decoded, initial).expect("lowered arithmetic must terminate");
    let native = run_native(operation, width, lhs, rhs);
    let defined = match operation {
        Operation::Add | Operation::Sub => ARITHMETIC_DEFINED,
        Operation::Xor => XOR_DEFINED,
    };

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(
        vm.state().register(Register::Rax),
        native.rax,
        "result mismatch for {operation:?} {width:?}, lhs=0x{lhs:x}, rhs=0x{rhs:x}"
    );
    assert_eq!(
        vm.state().flags_defined(),
        defined,
        "defined-mask mismatch for {operation:?} {width:?}"
    );
    assert_eq!(
        vm.state().flags_bits() & defined,
        native.rflags & defined,
        "flag mismatch for {operation:?} {width:?}, lhs=0x{lhs:x}, rhs=0x{rhs:x}"
    );
}

fn compare_native_mov_with_lowered(width: Width, immediate: bool) {
    let initial_rax = 0x1122_3344_5566_7788;
    let source = if immediate {
        mov_immediate(width)
    } else {
        0x8877_6655_4433_2211
    };
    let function = straight_line_function(&mov_physical_bytes(width, immediate, source));
    let lowered = lower(&function).expect("curated mov must lower");
    let encoded = encode(&lowered).expect("lowered mov v1 must encode");
    let decoded = decode(&encoded).expect("physical mov v1 must decode independently");
    let native = run_native_mov(width, immediate, initial_rax, source);

    assert_eq!(
        native.flags_before & ARITHMETIC_DEFINED,
        native.flags_after & ARITHMETIC_DEFINED,
        "native MOV changed modeled flags for {width:?}, immediate={immediate}"
    );

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, initial_rax);
    initial.set_register(Register::Rcx, source);
    initial.set_flags(native.flags_before, ARITHMETIC_DEFINED);
    let vm = execute(&decoded, initial).expect("lowered mov must terminate");

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(
        vm.state().register(Register::Rax),
        native.rax,
        "MOV result mismatch for {width:?}, immediate={immediate}"
    );
    assert_eq!(vm.state().flags_defined(), ARITHMETIC_DEFINED);
    assert_eq!(
        vm.state().flags_bits() & ARITHMETIC_DEFINED,
        native.flags_after & ARITHMETIC_DEFINED,
        "MOV flags mismatch for {width:?}, immediate={immediate}"
    );
}

fn physical_bytes(operation: Operation, width: Width) -> Vec<u8> {
    let (byte_opcode, other_opcode) = match operation {
        Operation::Add => (0x00, 0x01),
        Operation::Sub => (0x28, 0x29),
        Operation::Xor => (0x30, 0x31),
    };
    match width {
        Width::Byte => vec![byte_opcode, 0xc8, 0xc3],
        Width::Word => vec![0x66, other_opcode, 0xc8, 0xc3],
        Width::Dword => vec![other_opcode, 0xc8, 0xc3],
        Width::Qword => vec![0x48, other_opcode, 0xc8, 0xc3],
    }
}

fn mov_immediate(width: Width) -> u64 {
    match width {
        Width::Byte => 0x5a,
        Width::Word => 0xa55a,
        Width::Dword => 0xa55a_a55a,
        Width::Qword => 0xa55a_a55a_a55a_a55a,
    }
}

fn mov_physical_bytes(width: Width, immediate: bool, source: u64) -> Vec<u8> {
    if !immediate {
        return match width {
            Width::Byte => vec![0x88, 0xc8, 0xc3],
            Width::Word => vec![0x66, 0x89, 0xc8, 0xc3],
            Width::Dword => vec![0x89, 0xc8, 0xc3],
            Width::Qword => vec![0x48, 0x89, 0xc8, 0xc3],
        };
    }

    let mut bytes = match width {
        Width::Byte => vec![0xb0, source as u8],
        Width::Word => {
            let mut bytes = vec![0x66, 0xb8];
            bytes.extend_from_slice(&(source as u16).to_le_bytes());
            bytes
        }
        Width::Dword => {
            let mut bytes = vec![0xb8];
            bytes.extend_from_slice(&(source as u32).to_le_bytes());
            bytes
        }
        Width::Qword => {
            let mut bytes = vec![0x48, 0xb8];
            bytes.extend_from_slice(&source.to_le_bytes());
            bytes
        }
    };
    bytes.push(0xc3);
    bytes
}

fn straight_line_function(bytes: &[u8]) -> Function {
    let entry = Rva(0x1000);
    let mut decoder = Decoder::with_ip(64, bytes, u64::from(entry.get()), DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let raw = decoder.decode();
        let length = raw.len();
        let offset = usize::try_from(raw.ip() - u64::from(entry.get())).expect("small fixture");
        instructions.push(NativeInstruction::decoded(
            Rva(u32::try_from(raw.ip()).expect("small fixture")),
            raw,
            &bytes[offset..offset + length],
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

#[allow(
    unsafe_code,
    reason = "the x86-64 CPU oracle is isolated to this target-only test harness"
)]
fn run_native(operation: Operation, width: Width, lhs: u64, rhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: the instruction uses only declared RAX/RCX operands, records
            // RFLAGS in declared RDX, and balances its temporary stack push/pop.
            unsafe {
                asm!(
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") result,
                    in("rcx") rhs,
                    lateout("rdx") rflags,
                );
            }
        };
    }

    match (operation, width) {
        (Operation::Add, Width::Byte) => execute!("add al, cl"),
        (Operation::Add, Width::Word) => execute!("add ax, cx"),
        (Operation::Add, Width::Dword) => execute!("add eax, ecx"),
        (Operation::Add, Width::Qword) => execute!("add rax, rcx"),
        (Operation::Sub, Width::Byte) => execute!("sub al, cl"),
        (Operation::Sub, Width::Word) => execute!("sub ax, cx"),
        (Operation::Sub, Width::Dword) => execute!("sub eax, ecx"),
        (Operation::Sub, Width::Qword) => execute!("sub rax, rcx"),
        (Operation::Xor, Width::Byte) => execute!("xor al, cl"),
        (Operation::Xor, Width::Word) => execute!("xor ax, cx"),
        (Operation::Xor, Width::Dword) => execute!("xor eax, ecx"),
        (Operation::Xor, Width::Qword) => execute!("xor rax, rcx"),
    }

    NativeResult {
        rax: result,
        rflags,
    }
}

#[allow(
    unsafe_code,
    reason = "the x86-64 CPU oracle is isolated to this target-only test harness"
)]
fn run_native_branch(lhs: u64, rhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    // SAFETY: the sequence uses only declared RAX/RCX operands, records RFLAGS
    // in declared RDX, and balances its temporary stack push/pop.
    unsafe {
        asm!(
            "sub rax, rcx",
            "je 2f",
            "mov rax, 0x1111111111111111",
            "jmp 3f",
            "2:",
            "mov rax, 0x2222222222222222",
            "3:",
            "pushfq",
            "pop rdx",
            inout("rax") result,
            in("rcx") rhs,
            lateout("rdx") rflags,
        );
    }

    let expected = if lhs == rhs {
        BRANCH_EQUAL
    } else {
        BRANCH_NOT_EQUAL
    };
    assert_eq!(
        result, expected,
        "native branch oracle selected the wrong arm"
    );
    NativeResult {
        rax: result,
        rflags,
    }
}

#[allow(
    unsafe_code,
    reason = "the x86-64 CPU oracle is isolated to this target-only test harness"
)]
fn run_native_mov(width: Width, immediate: bool, initial: u64, source: u64) -> NativeMovResult {
    let mut result = initial;
    let flags_before: u64;
    let flags_after: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: the instruction uses only declared RAX/RCX operands,
            // captures RFLAGS before and after in declared scratch registers,
            // and balances both temporary stack push/pop pairs.
            unsafe {
                asm!(
                    "cmp r9, 1",
                    "pushfq",
                    "pop r8",
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") result,
                    in("rcx") source,
                    in("r9") 0u64,
                    lateout("r8") flags_before,
                    lateout("rdx") flags_after,
                );
            }
        };
    }

    match (width, immediate) {
        (Width::Byte, false) => execute!("mov al, cl"),
        (Width::Word, false) => execute!("mov ax, cx"),
        (Width::Dword, false) => execute!("mov eax, ecx"),
        (Width::Qword, false) => execute!("mov rax, rcx"),
        (Width::Byte, true) => execute!("mov al, 0x5a"),
        (Width::Word, true) => execute!("mov ax, 0xa55a"),
        (Width::Dword, true) => execute!("mov eax, 0xa55aa55a"),
        (Width::Qword, true) => execute!("mov rax, 0xa55aa55aa55aa55a"),
    }

    NativeMovResult {
        rax: result,
        flags_before,
        flags_after,
    }
}
