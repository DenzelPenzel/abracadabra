#![cfg(target_arch = "x86_64")]

use core::arch::asm;

use iced_x86::{Decoder, DecoderOptions};
use vmp_ir::{
    BasicBlock, BlockId, CompileStage, Function, Instruction as NativeInstruction, Terminator,
};
use vmp_pe::PeFile;
use vmp_types::{Architecture, Rva};
use vmp_vm::{
    bytecode::{decode, encode, Condition, Register, Width},
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
const LOGICAL_DEFINED: u64 = CF | PF | ZF | SF | OF;

#[derive(Debug, Clone, Copy)]
enum Operation {
    Add,
    Sub,
    Xor,
    And,
    Or,
}

#[derive(Debug, Clone, Copy)]
struct NativeResult {
    rax: u64,
    rflags: u64,
}

#[derive(Debug, Clone, Copy)]
struct NativeCmpResult {
    rax: u64,
    rcx: u64,
    rflags: u64,
}

#[derive(Debug, Clone, Copy)]
struct NativeMovResult {
    rax: u64,
    flags_before: u64,
    flags_after: u64,
}

const BRANCH_TAKEN: u64 = 0x2222_2222_2222_2222;
const BRANCH_NOT_TAKEN: u64 = 0x1111_1111_1111_1111;

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
fn native_and_matches_lowered_decoded_host_v1() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for (lhs, rhs) in edge_vectors(Operation::And, width) {
            compare_native_with_lowered(Operation::And, width, lhs, rhs);
        }
        for immediate in [1, -1] {
            for (lhs, _) in edge_vectors(Operation::And, width) {
                compare_native_and_immediate_with_lowered(width, immediate, lhs);
            }
        }
    }
}

#[test]
fn native_or_matches_lowered_decoded_host_v1() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for (lhs, rhs) in edge_vectors(Operation::Or, width) {
            compare_native_with_lowered(Operation::Or, width, lhs, rhs);
        }
        for immediate in [1, -1] {
            for (lhs, _) in edge_vectors(Operation::Or, width) {
                compare_native_or_immediate_with_lowered(width, immediate, lhs);
            }
        }
    }
}

#[test]
fn native_cmp_preserves_operands_and_matches_lowered_flags_v1() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for (lhs, rhs) in edge_vectors(Operation::Sub, width) {
            compare_native_cmp_with_lowered(width, None, lhs, rhs);
        }
        for immediate in [1, -1] {
            for (lhs, _) in edge_vectors(Operation::Sub, width) {
                compare_native_cmp_with_lowered(width, Some(immediate), lhs, 0x8877_6655_4433_2211);
            }
        }
    }
}

#[test]
fn native_test_preserves_operands_and_matches_lowered_flags_v1() {
    for width in [Width::Byte, Width::Word, Width::Dword, Width::Qword] {
        for (lhs, rhs) in test_vectors(width) {
            compare_native_test_with_lowered(width, None, lhs, rhs);
        }
        for immediate in [1, -1] {
            for (lhs, _) in test_vectors(width) {
                compare_native_test_with_lowered(
                    width,
                    Some(immediate),
                    lhs,
                    0x8877_6655_4433_2211,
                );
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
    for condition in all_conditions() {
        let function = branching_function(condition);
        let lowered = lower(&function).expect("curated branch function must lower");
        let encoded = encode(&lowered).expect("lowered branch program must encode");
        let decoded = decode(&encoded).expect("physical branch program must decode independently");
        let mut observed_taken = false;
        let mut observed_not_taken = false;

        for (lhs, rhs) in branch_vectors() {
            let mut initial = MachineState::default();
            initial.set_register(Register::Rax, lhs);
            initial.set_register(Register::Rcx, rhs);
            let vm = execute(&decoded, initial).expect("lowered branch function must terminate");
            let native = run_native_branch(condition, lhs, rhs);

            assert_eq!(vm.termination(), Termination::Ret);
            assert_eq!(vm.state().stack_len(), 0);
            assert_eq!(
                vm.state().register(Register::Rax),
                native.rax,
                "branch mismatch for {condition:?}, lhs=0x{lhs:x}, rhs=0x{rhs:x}"
            );
            assert_eq!(vm.state().flags_defined(), ARITHMETIC_DEFINED);
            assert_eq!(
                vm.state().flags_bits() & ARITHMETIC_DEFINED,
                native.rflags & ARITHMETIC_DEFINED,
                "flag mismatch for {condition:?}, lhs=0x{lhs:x}, rhs=0x{rhs:x}"
            );
            observed_taken |= native.rax == BRANCH_TAKEN;
            observed_not_taken |= native.rax == BRANCH_NOT_TAKEN;
        }

        assert!(observed_taken, "no taken native case for {condition:?}");
        assert!(
            observed_not_taken,
            "no not-taken native case for {condition:?}"
        );
    }
}

#[test]
fn native_test_flags_feed_all_conditional_branches_v1() {
    for condition in all_conditions() {
        let function = test_branching_function(condition);
        let lowered = lower(&function).expect("curated TEST branch function must lower");
        let encoded = encode(&lowered).expect("lowered TEST branch program must encode");
        let decoded =
            decode(&encoded).expect("physical TEST branch program must decode independently");
        let mut observed_taken = false;
        let mut observed_not_taken = false;

        for (lhs, rhs) in test_branch_vectors() {
            let mut initial = MachineState::default();
            initial.set_register(Register::Rax, lhs);
            initial.set_register(Register::Rcx, rhs);
            let vm = execute(&decoded, initial).expect("lowered TEST branch must terminate");
            let native = run_native_test_branch(condition, lhs, rhs);

            assert_eq!(vm.termination(), Termination::Ret);
            assert_eq!(vm.state().stack_len(), 0);
            assert_eq!(vm.state().register(Register::Rax), native.rax);
            assert_eq!(vm.state().flags_defined(), LOGICAL_DEFINED);
            assert_eq!(
                vm.state().flags_bits() & LOGICAL_DEFINED,
                native.rflags & LOGICAL_DEFINED,
                "TEST branch flag mismatch for {condition:?}, lhs=0x{lhs:x}, rhs=0x{rhs:x}"
            );
            observed_taken |= native.rax == BRANCH_TAKEN;
            observed_not_taken |= native.rax == BRANCH_NOT_TAKEN;
        }

        match condition {
            Condition::O | Condition::B => {
                assert!(!observed_taken, "TEST unexpectedly took {condition:?}");
                assert!(observed_not_taken, "TEST never exercised {condition:?}");
            }
            Condition::No | Condition::Ae => {
                assert!(observed_taken, "TEST never exercised {condition:?}");
                assert!(
                    !observed_not_taken,
                    "TEST unexpectedly did not take {condition:?}"
                );
            }
            _ => {
                assert!(observed_taken, "no taken TEST case for {condition:?}");
                assert!(
                    observed_not_taken,
                    "no not-taken TEST case for {condition:?}"
                );
            }
        }
    }
}

fn all_conditions() -> [Condition; 16] {
    [
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
    ]
}

fn branch_vectors() -> [(u64, u64); 8] {
    [
        (0, 0),
        (1, 0),
        (0, 1),
        (0x7fff_ffff_ffff_ffff, u64::MAX),
        (0x8000_0000_0000_0000, 1),
        (0x8000_0000_0000_0000, u64::MAX),
        (u64::MAX, 0x7fff_ffff_ffff_ffff),
        (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
    ]
}

fn test_vectors(width: Width) -> [(u64, u64); 6] {
    let (sign, mask) = match width {
        Width::Byte => (0x80, u64::from(u8::MAX)),
        Width::Word => (0x8000, u64::from(u16::MAX)),
        Width::Dword => (0x8000_0000, u64::from(u32::MAX)),
        Width::Qword => (0x8000_0000_0000_0000, u64::MAX),
    };
    [
        (0, mask),
        (mask, 0),
        (mask, mask),
        (sign | 1, mask),
        (1, 1),
        (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
    ]
}

fn test_branch_vectors() -> [(u64, u64); 6] {
    [
        (0, u64::MAX),
        (1, 1),
        (3, 3),
        (0x8000_0000_0000_0000, u64::MAX),
        (0x8000_0000_0000_0001, u64::MAX),
        (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
    ]
}

fn branching_function(condition: Condition) -> Function {
    // cmp rax, rcx; jcc taken; mov rax, NOT_TAKEN; jmp end;
    // taken: mov rax, TAKEN; end: ret
    let text = [
        0x48,
        0x39,
        0xc8,
        0x70 | condition as u8,
        0x0c,
        0x48,
        0xb8,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0xeb,
        0x0a,
        0x48,
        0xb8,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0xc3,
    ];
    let image = minimal_pe64(&text);
    let pe = PeFile::parse(&image).expect("branch fixture must be a valid PE32+ image");
    decode_function(Image::new(&pe, &image), Rva(0x1000))
        .expect("production decoder must recover the branch CFG")
}

fn test_branching_function(condition: Condition) -> Function {
    // test rax, rcx; jcc taken; mov rax, NOT_TAKEN; jmp end;
    // taken: mov rax, TAKEN; end: ret
    let text = [
        0x48,
        0x85,
        0xc8,
        0x70 | condition as u8,
        0x0c,
        0x48,
        0xb8,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0x11,
        0xeb,
        0x0a,
        0x48,
        0xb8,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0xc3,
    ];
    let image = minimal_pe64(&text);
    let pe = PeFile::parse(&image).expect("TEST branch fixture must be a valid PE32+ image");
    decode_function(Image::new(&pe, &image), Rva(0x1000))
        .expect("production decoder must recover the TEST branch CFG")
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
        Operation::And => [
            (0, 0),
            (1, 1),
            (sign, 0),
            (mask, sign),
            (sign_max, mask),
            (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
        ],
        Operation::Or => [
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
        Operation::Xor | Operation::And | Operation::Or => LOGICAL_DEFINED,
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

fn compare_native_and_immediate_with_lowered(width: Width, immediate: i8, lhs: u64) {
    let function = straight_line_function(&and_immediate_physical_bytes(width, immediate));
    let lowered = lower(&function).expect("curated immediate AND must lower");
    let encoded = encode(&lowered).expect("lowered immediate AND v1 must encode");
    let decoded = decode(&encoded).expect("physical immediate AND v1 must decode independently");

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, lhs);
    let vm = execute(&decoded, initial).expect("lowered immediate AND must terminate");
    let native = run_native_and_immediate(width, immediate, lhs);

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(vm.state().register(Register::Rax), native.rax);
    assert_eq!(vm.state().flags_defined(), LOGICAL_DEFINED);
    assert_eq!(
        vm.state().flags_bits() & LOGICAL_DEFINED,
        native.rflags & LOGICAL_DEFINED,
        "immediate AND flag mismatch for {width:?}, immediate={immediate}, lhs=0x{lhs:x}"
    );
}

fn compare_native_or_immediate_with_lowered(width: Width, immediate: i8, lhs: u64) {
    let function = straight_line_function(&or_immediate_physical_bytes(width, immediate));
    let lowered = lower(&function).expect("curated immediate OR must lower");
    let encoded = encode(&lowered).expect("lowered immediate OR v1 must encode");
    let decoded = decode(&encoded).expect("physical immediate OR v1 must decode independently");

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, lhs);
    let vm = execute(&decoded, initial).expect("lowered immediate OR must terminate");
    let native = run_native_or_immediate(width, immediate, lhs);

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(vm.state().register(Register::Rax), native.rax);
    assert_eq!(vm.state().flags_defined(), LOGICAL_DEFINED);
    assert_eq!(
        vm.state().flags_bits() & LOGICAL_DEFINED,
        native.rflags & LOGICAL_DEFINED,
        "immediate OR flag mismatch for {width:?}, immediate={immediate}, lhs=0x{lhs:x}"
    );
}

fn compare_native_cmp_with_lowered(width: Width, immediate: Option<i8>, lhs: u64, rcx: u64) {
    let bytes = cmp_physical_bytes(width, immediate);
    let image = minimal_pe64(&bytes);
    let pe = PeFile::parse(&image).expect("CMP fixture must be a valid PE32+ image");
    let function = decode_function(Image::new(&pe, &image), Rva(0x1000))
        .expect("production decoder must recover the CMP function");
    let lowered = lower(&function).expect("curated CMP must lower");
    let encoded = encode(&lowered).expect("lowered CMP v1 must encode");
    let decoded = decode(&encoded).expect("physical CMP v1 must decode independently");
    let native = run_native_cmp(width, immediate, lhs, rcx);

    assert_eq!(native.rax, lhs, "native CMP changed RAX for {width:?}");
    assert_eq!(native.rcx, rcx, "native CMP changed RCX for {width:?}");

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, lhs);
    initial.set_register(Register::Rcx, rcx);
    let vm = execute(&decoded, initial).expect("lowered CMP must terminate");

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(vm.state().register(Register::Rax), native.rax);
    assert_eq!(vm.state().register(Register::Rcx), native.rcx);
    assert_eq!(vm.state().flags_defined(), ARITHMETIC_DEFINED);
    assert_eq!(
        vm.state().flags_bits() & ARITHMETIC_DEFINED,
        native.rflags & ARITHMETIC_DEFINED,
        "CMP flag mismatch for {width:?}, immediate={immediate:?}, lhs=0x{lhs:x}"
    );
}

fn compare_native_test_with_lowered(width: Width, immediate: Option<i8>, lhs: u64, rcx: u64) {
    let bytes = test_physical_bytes(width, immediate);
    let image = minimal_pe64(&bytes);
    let pe = PeFile::parse(&image).expect("TEST fixture must be a valid PE32+ image");
    let function = decode_function(Image::new(&pe, &image), Rva(0x1000))
        .expect("production decoder must recover the TEST function");
    let lowered = lower(&function).expect("curated TEST must lower");
    let encoded = encode(&lowered).expect("lowered TEST v1 must encode");
    let decoded = decode(&encoded).expect("physical TEST v1 must decode independently");
    let native = run_native_test(width, immediate, lhs, rcx);

    assert_eq!(native.rax, lhs, "native TEST changed RAX for {width:?}");
    assert_eq!(native.rcx, rcx, "native TEST changed RCX for {width:?}");

    let mut initial = MachineState::default();
    initial.set_register(Register::Rax, lhs);
    initial.set_register(Register::Rcx, rcx);
    let vm = execute(&decoded, initial).expect("lowered TEST must terminate");

    assert_eq!(vm.termination(), Termination::Ret);
    assert_eq!(vm.state().stack_len(), 0);
    assert_eq!(vm.state().register(Register::Rax), native.rax);
    assert_eq!(vm.state().register(Register::Rcx), native.rcx);
    assert_eq!(vm.state().flags_defined(), LOGICAL_DEFINED);
    assert_eq!(
        vm.state().flags_bits() & LOGICAL_DEFINED,
        native.rflags & LOGICAL_DEFINED,
        "TEST flag mismatch for {width:?}, immediate={immediate:?}, lhs=0x{lhs:x}"
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
        Operation::And => (0x20, 0x21),
        Operation::Or => (0x08, 0x09),
    };
    match width {
        Width::Byte => vec![byte_opcode, 0xc8, 0xc3],
        Width::Word => vec![0x66, other_opcode, 0xc8, 0xc3],
        Width::Dword => vec![other_opcode, 0xc8, 0xc3],
        Width::Qword => vec![0x48, other_opcode, 0xc8, 0xc3],
    }
}

fn and_immediate_physical_bytes(width: Width, immediate: i8) -> Vec<u8> {
    let immediate = immediate as u8;
    match width {
        Width::Byte => vec![0x80, 0xe0, immediate, 0xc3],
        Width::Word => vec![0x66, 0x83, 0xe0, immediate, 0xc3],
        Width::Dword => vec![0x83, 0xe0, immediate, 0xc3],
        Width::Qword => vec![0x48, 0x83, 0xe0, immediate, 0xc3],
    }
}

fn or_immediate_physical_bytes(width: Width, immediate: i8) -> Vec<u8> {
    let immediate = immediate as u8;
    match width {
        Width::Byte => vec![0x80, 0xc8, immediate, 0xc3],
        Width::Word => vec![0x66, 0x83, 0xc8, immediate, 0xc3],
        Width::Dword => vec![0x83, 0xc8, immediate, 0xc3],
        Width::Qword => vec![0x48, 0x83, 0xc8, immediate, 0xc3],
    }
}

fn cmp_physical_bytes(width: Width, immediate: Option<i8>) -> Vec<u8> {
    if let Some(immediate) = immediate {
        let immediate = immediate as u8;
        return match width {
            Width::Byte => vec![0x80, 0xf8, immediate, 0xc3],
            Width::Word => vec![0x66, 0x83, 0xf8, immediate, 0xc3],
            Width::Dword => vec![0x83, 0xf8, immediate, 0xc3],
            Width::Qword => vec![0x48, 0x83, 0xf8, immediate, 0xc3],
        };
    }
    match width {
        Width::Byte => vec![0x38, 0xc8, 0xc3],
        Width::Word => vec![0x66, 0x39, 0xc8, 0xc3],
        Width::Dword => vec![0x39, 0xc8, 0xc3],
        Width::Qword => vec![0x48, 0x39, 0xc8, 0xc3],
    }
}

fn test_physical_bytes(width: Width, immediate: Option<i8>) -> Vec<u8> {
    if let Some(immediate) = immediate {
        let value = match immediate {
            1 => 1,
            -1 => u64::MAX,
            _ => unreachable!("unsupported TEST immediate {immediate}"),
        };
        let mut bytes = match width {
            Width::Byte => vec![0xf6, 0xc0, value as u8],
            Width::Word => {
                let mut bytes = vec![0x66, 0xf7, 0xc0];
                bytes.extend_from_slice(&(value as u16).to_le_bytes());
                bytes
            }
            Width::Dword => {
                let mut bytes = vec![0xf7, 0xc0];
                bytes.extend_from_slice(&(value as u32).to_le_bytes());
                bytes
            }
            Width::Qword => {
                let mut bytes = vec![0x48, 0xf7, 0xc0];
                bytes.extend_from_slice(&(value as u32).to_le_bytes());
                bytes
            }
        };
        bytes.push(0xc3);
        return bytes;
    }
    match width {
        Width::Byte => vec![0x84, 0xc8, 0xc3],
        Width::Word => vec![0x66, 0x85, 0xc8, 0xc3],
        Width::Dword => vec![0x85, 0xc8, 0xc3],
        Width::Qword => vec![0x48, 0x85, 0xc8, 0xc3],
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
        (Operation::And, Width::Byte) => execute!("and al, cl"),
        (Operation::And, Width::Word) => execute!("and ax, cx"),
        (Operation::And, Width::Dword) => execute!("and eax, ecx"),
        (Operation::And, Width::Qword) => execute!("and rax, rcx"),
        (Operation::Or, Width::Byte) => execute!("or al, cl"),
        (Operation::Or, Width::Word) => execute!("or ax, cx"),
        (Operation::Or, Width::Dword) => execute!("or eax, ecx"),
        (Operation::Or, Width::Qword) => execute!("or rax, rcx"),
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
fn run_native_and_immediate(width: Width, immediate: i8, lhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: AND modifies only declared RAX, records RFLAGS in declared
            // RDX, and balances its temporary stack push/pop.
            unsafe {
                asm!(
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") result,
                    lateout("rdx") rflags,
                );
            }
        };
    }

    match (width, immediate) {
        (Width::Byte, 1) => execute!("and al, 1"),
        (Width::Word, 1) => execute!("and ax, 1"),
        (Width::Dword, 1) => execute!("and eax, 1"),
        (Width::Qword, 1) => execute!("and rax, 1"),
        (Width::Byte, -1) => execute!("and al, -1"),
        (Width::Word, -1) => execute!("and ax, -1"),
        (Width::Dword, -1) => execute!("and eax, -1"),
        (Width::Qword, -1) => execute!("and rax, -1"),
        (_, immediate) => unreachable!("unsupported AND immediate {immediate}"),
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
fn run_native_or_immediate(width: Width, immediate: i8, lhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: OR modifies only declared RAX, records RFLAGS in declared
            // RDX, and balances its temporary stack push/pop.
            unsafe {
                asm!(
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") result,
                    lateout("rdx") rflags,
                );
            }
        };
    }

    match (width, immediate) {
        (Width::Byte, 1) => execute!("or al, 1"),
        (Width::Word, 1) => execute!("or ax, 1"),
        (Width::Dword, 1) => execute!("or eax, 1"),
        (Width::Qword, 1) => execute!("or rax, 1"),
        (Width::Byte, -1) => execute!("or al, -1"),
        (Width::Word, -1) => execute!("or ax, -1"),
        (Width::Dword, -1) => execute!("or eax, -1"),
        (Width::Qword, -1) => execute!("or rax, -1"),
        (_, immediate) => unreachable!("unsupported OR immediate {immediate}"),
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
fn run_native_cmp(width: Width, immediate: Option<i8>, lhs: u64, rhs: u64) -> NativeCmpResult {
    let mut rax = lhs;
    let mut rcx = rhs;
    let rflags: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: CMP does not modify its declared RAX/RCX operands, RFLAGS
            // is recorded in declared RDX, and the temporary push/pop is balanced.
            unsafe {
                asm!(
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") rax,
                    inout("rcx") rcx,
                    lateout("rdx") rflags,
                );
            }
        };
    }

    match (width, immediate) {
        (Width::Byte, None) => execute!("cmp al, cl"),
        (Width::Word, None) => execute!("cmp ax, cx"),
        (Width::Dword, None) => execute!("cmp eax, ecx"),
        (Width::Qword, None) => execute!("cmp rax, rcx"),
        (Width::Byte, Some(1)) => execute!("cmp al, 1"),
        (Width::Word, Some(1)) => execute!("cmp ax, 1"),
        (Width::Dword, Some(1)) => execute!("cmp eax, 1"),
        (Width::Qword, Some(1)) => execute!("cmp rax, 1"),
        (Width::Byte, Some(-1)) => execute!("cmp al, -1"),
        (Width::Word, Some(-1)) => execute!("cmp ax, -1"),
        (Width::Dword, Some(-1)) => execute!("cmp eax, -1"),
        (Width::Qword, Some(-1)) => execute!("cmp rax, -1"),
        (_, Some(immediate)) => unreachable!("unsupported CMP immediate {immediate}"),
    }

    NativeCmpResult { rax, rcx, rflags }
}

#[allow(
    unsafe_code,
    reason = "the x86-64 CPU oracle is isolated to this target-only test harness"
)]
fn run_native_test(width: Width, immediate: Option<i8>, lhs: u64, rhs: u64) -> NativeCmpResult {
    let mut rax = lhs;
    let mut rcx = rhs;
    let rflags: u64;

    macro_rules! execute {
        ($instruction:literal) => {
            // SAFETY: TEST does not modify its declared RAX/RCX operands, RFLAGS
            // is recorded in declared RDX, and the temporary push/pop is balanced.
            unsafe {
                asm!(
                    $instruction,
                    "pushfq",
                    "pop rdx",
                    inout("rax") rax,
                    inout("rcx") rcx,
                    lateout("rdx") rflags,
                );
            }
        };
    }

    match (width, immediate) {
        (Width::Byte, None) => execute!("test al, cl"),
        (Width::Word, None) => execute!("test ax, cx"),
        (Width::Dword, None) => execute!("test eax, ecx"),
        (Width::Qword, None) => execute!("test rax, rcx"),
        (Width::Byte, Some(1)) => execute!("test al, 1"),
        (Width::Word, Some(1)) => execute!("test ax, 1"),
        (Width::Dword, Some(1)) => execute!("test eax, 1"),
        (Width::Qword, Some(1)) => execute!("test rax, 1"),
        (Width::Byte, Some(-1)) => execute!("test al, -1"),
        (Width::Word, Some(-1)) => execute!("test ax, -1"),
        (Width::Dword, Some(-1)) => execute!("test eax, -1"),
        (Width::Qword, Some(-1)) => execute!("test rax, -1"),
        (_, Some(immediate)) => unreachable!("unsupported TEST immediate {immediate}"),
    }

    NativeCmpResult { rax, rcx, rflags }
}

#[allow(
    unsafe_code,
    reason = "the x86-64 CPU oracle is isolated to this target-only test harness"
)]
fn run_native_branch(condition: Condition, lhs: u64, rhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    macro_rules! execute {
        ($jump:literal) => {
            // SAFETY: the sequence uses only declared RAX/RCX operands, records
            // RFLAGS in declared RDX, and balances its temporary stack push/pop.
            unsafe {
                asm!(
                    "cmp rax, rcx",
                    $jump,
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
        };
    }

    match condition {
        Condition::O => execute!("jo 2f"),
        Condition::No => execute!("jno 2f"),
        Condition::B => execute!("jb 2f"),
        Condition::Ae => execute!("jae 2f"),
        Condition::E => execute!("je 2f"),
        Condition::Ne => execute!("jne 2f"),
        Condition::Be => execute!("jbe 2f"),
        Condition::A => execute!("ja 2f"),
        Condition::S => execute!("js 2f"),
        Condition::Ns => execute!("jns 2f"),
        Condition::P => execute!("jp 2f"),
        Condition::Np => execute!("jnp 2f"),
        Condition::L => execute!("jl 2f"),
        Condition::Ge => execute!("jge 2f"),
        Condition::Le => execute!("jle 2f"),
        Condition::G => execute!("jg 2f"),
    }

    assert!(
        matches!(result, BRANCH_TAKEN | BRANCH_NOT_TAKEN),
        "native branch oracle produced an unknown arm value"
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
fn run_native_test_branch(condition: Condition, lhs: u64, rhs: u64) -> NativeResult {
    let mut result = lhs;
    let rflags: u64;

    macro_rules! execute {
        ($jump:literal) => {
            // SAFETY: the sequence uses only declared RAX/RCX operands, records
            // RFLAGS in declared RDX, and balances its temporary stack push/pop.
            unsafe {
                asm!(
                    "test rax, rcx",
                    $jump,
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
        };
    }

    match condition {
        Condition::O => execute!("jo 2f"),
        Condition::No => execute!("jno 2f"),
        Condition::B => execute!("jb 2f"),
        Condition::Ae => execute!("jae 2f"),
        Condition::E => execute!("je 2f"),
        Condition::Ne => execute!("jne 2f"),
        Condition::Be => execute!("jbe 2f"),
        Condition::A => execute!("ja 2f"),
        Condition::S => execute!("js 2f"),
        Condition::Ns => execute!("jns 2f"),
        Condition::P => execute!("jp 2f"),
        Condition::Np => execute!("jnp 2f"),
        Condition::L => execute!("jl 2f"),
        Condition::Ge => execute!("jge 2f"),
        Condition::Le => execute!("jle 2f"),
        Condition::G => execute!("jg 2f"),
    }

    assert!(
        matches!(result, BRANCH_TAKEN | BRANCH_NOT_TAKEN),
        "native TEST branch oracle produced an unknown arm value"
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
