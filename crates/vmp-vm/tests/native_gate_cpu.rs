#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use iced_x86::{code_asm::*, Code, Decoder, DecoderOptions};
use vmp_ir::Instruction;
use vmp_types::{Architecture, Rva, VirtualAddress};
use vmp_vm::{instance::NativeInstance, logical::lower_instruction};

#[allow(unsafe_code)]
extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

struct Mapping(*mut u8);
const SIZE: usize = 0x10000;
impl Mapping {
    #[allow(unsafe_code)]
    fn new() -> Self {
        let anonymous = if cfg!(target_os = "macos") {
            0x1000
        } else {
            0x20
        };
        // SAFETY: Anonymous private writable mapping with no file or preexisting address
        let page = unsafe { mmap(std::ptr::null_mut(), SIZE, 3, 2 | anonymous, -1, 0) };
        assert!(!page.is_null() && page as isize != -1, "mmap");
        Self(page)
    }

    #[allow(unsafe_code)]
    fn publish(&self, bytes: &[u8]) {
        assert!(bytes.len() <= SIZE);
        // SAFETY: Fresh writable mapping of SIZE bytes, disjoint from the source buffer
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.0, bytes.len()) };
        // SAFETY: Entire owned mapping becomes RX before any invocation; x64 caches are coherent
        assert_eq!(unsafe { mprotect(self.0, SIZE, 5) }, 0, "mprotect");
    }
}
impl Drop for Mapping {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: All native calls finished and no pointer escapes this test's mapping
        assert_eq!(unsafe { munmap(self.0, SIZE) }, 0, "munmap");
    }
}

fn probe(gate: u64, address: u64, initial: &[u64; 15], flags: u64) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).expect("assembler");
    for r in [rbx, rbp, r12, r13, r14, r15] {
        a.push(r).expect("save caller");
    }
    a.sub(rsp, 24).expect("aligned metadata");
    a.mov(qword_ptr(rsp), rdi).expect("output pointer");
    a.mov(rax, gate).expect("gate pointer");
    a.mov(qword_ptr(rsp + 8), rax).expect("store gate");
    a.mov(rax, 0x5a5a5a5a5a5a5a5au64).expect("canary");
    a.sub(rsp, 512).expect("reserve canary region");
    for offset in (0..512).step_by(8) {
        a.mov(qword_ptr(rsp + offset), rax).expect("fill");
    }
    a.add(rsp, 512).expect("restore probe stack");
    a.mov(rax, qword_ptr(rsp)).expect("output");
    a.mov(qword_ptr(rax + 128), rsp).expect("pre-call RSP");
    a.mov(rax, flags).expect("flags");
    a.push(rax).expect("flags");
    a.popfq().expect("flags");
    let regs = [
        rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    for (i, r) in regs.into_iter().enumerate() {
        a.mov(r, initial[i]).expect("guest sentinel");
    }
    a.call(qword_ptr(rsp + 8)).expect("raw native gate");
    // This snapshot is outside the gate, after its complete restore/RET path
    a.pushfq().expect("observe flags");
    for r in regs {
        a.push(r).expect("observe GPR");
    }
    a.mov(rdx, qword_ptr(rsp + 128)).expect("output pointer");
    for i in 0..15 {
        a.mov(rax, qword_ptr(rsp + (14 - i) * 8)).expect("snapshot");
        a.mov(qword_ptr(rdx + i * 8), rax).expect("output");
    }
    a.mov(rax, qword_ptr(rsp + 120)).expect("saved flags");
    a.mov(qword_ptr(rdx + 120), rax).expect("output flags");
    a.lea(rax, qword_ptr(rsp + 128)).expect("post-call RSP");
    a.mov(qword_ptr(rdx + 136), rax).expect("output RSP");
    for (source, dest) in [(-280, 144), (-272, 152)] {
        a.mov(rax, qword_ptr(rsp + source))
            .expect("stack depth witness");
        a.mov(qword_ptr(rdx + dest), rax).expect("output depth");
    }
    a.lea(rsp, qword_ptr(rsp + 152))
        .expect("drop snapshot and metadata");
    for r in [r15, r14, r13, r12, rbp, rbx] {
        a.pop(r).expect("restore caller");
    }
    a.ret().expect("return");
    a.assemble(address).expect("assemble probe")
}

fn execute(variant: u8, lhs: u64, rhs: u64, mutate_pop: bool) -> [u64; 20] {
    let mut initial = std::array::from_fn(|i| 0x1122000000000000 + i as u64);
    initial[1] = lhs;
    initial[2] = rhs;
    execute_program(
        variant,
        &[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0],
        &initial,
        0x202,
        if mutate_pop {
            Mutation::Pop
        } else {
            Mutation::None
        },
        Execution::Plain,
    )
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    Pop,
    CaptureFlags,
}

#[derive(Clone, Copy)]
enum Execution {
    Native,
    Plain,
    Encrypted,
}

#[allow(unsafe_code)]
fn execute_program(
    variant: u8,
    program: &[u8],
    initial: &[u64; 15],
    flags: u64,
    mutation: Mutation,
    execution: Execution,
) -> [u64; 20] {
    let native: Vec<_> = Decoder::with_ip(64, program, 0x1000, DecoderOptions::NONE)
        .into_iter()
        .map(|raw| {
            let offset = (raw.ip() - 0x1000) as usize;
            let bytes = &program[offset..offset + raw.len()];
            Instruction::decoded(Rva(0x1000 + offset as u32), raw, bytes)
        })
        .collect();
    let bodies: Vec<_> = native
        .iter()
        .map(|i| lower_instruction(Architecture::X64, i).expect("body"))
        .collect();
    let mapping = Mapping::new();
    let base = mapping.0 as u64;
    let gate = match execution {
        Execution::Native | Execution::Plain => {
            NativeInstance::generate(&bodies, VirtualAddress(base), variant)
        }
        Execution::Encrypted => {
            NativeInstance::generate_encrypted(&bodies, VirtualAddress(base), variant)
        }
    }
    .expect("gate");
    let mut image = gate.image().to_vec();
    match mutation {
        Mutation::None => {}
        Mutation::Pop => {
            let first_pop = gate.exit_offset() + 16 * 9 + 3;
            assert_eq!(variant, 0);
            assert_eq!(image[first_pop], 0x58);
            image[first_pop] = 0x59;
        }
        Mutation::CaptureFlags => {
            // PUSH RAX preserves frame size but replaces captured flags with a benign constant
            assert_eq!(initial[0], 0x202);
            let pushf = Decoder::with_ip(
                64,
                &image[gate.entry_offset()..],
                base + gate.entry_offset() as u64,
                DecoderOptions::NONE,
            )
            .into_iter()
            .find(|i| i.code() == Code::Pushfq)
            .expect("entry PUSHF");
            image[(pushf.ip() - base) as usize] = 0x50;
        }
    }
    let entry = if !matches!(execution, Execution::Native) {
        base + gate.entry_offset() as u64
    } else {
        image = program.to_vec();
        image.push(0xc3);
        base
    };
    let outer = probe(entry, base + 0x8000, initial, flags);
    image.resize(0x8000, 0xcc);
    image.extend_from_slice(&outer);
    mapping.publish(&image);
    let mut output = [0; 20];
    // SAFETY: RX mapping contains the generated SysV outer probe at 0x8000; it preserves
    // ABI nonvolatiles, writes exactly 20 output words, and calls the owned scalar gate
    unsafe {
        let invoke: unsafe extern "C" fn(*mut u64) = std::mem::transmute(mapping.0.add(0x8000));
        invoke(output.as_mut_ptr());
    }
    output
}

#[test]
fn physical_cpu_observes_complete_gate_return() {
    for variant in 0..=u8::MAX {
        for (lhs, rhs, result, flags) in [
            (0, 0, 0, 0x246),
            (1, 2, 3, 0x206),
            (u64::MAX, 1, 0, 0x257),
            (0x7fffffffffffffff, 1, 0x8000000000000000, 0xa96),
            (0x8000000000000000, 0x8000000000000000, 0, 0xa47),
            (15, 1, 16, 0x212),
            (
                0x123456789abcdef0,
                0xfedcba9876543210,
                0x1111111111111100,
                0x207,
            ),
        ] {
            let output = execute(variant, lhs, rhs, false);
            for (i, actual) in output[..15].iter().enumerate() {
                let expected = match i {
                    0 => result,
                    1 => lhs,
                    2 => rhs,
                    _ => 0x1122000000000000 + i as u64,
                };
                assert_eq!(*actual, expected, "variant={variant}, GPR={i}");
            }
            assert_eq!(output[15] & 0x8d5, flags & 0x8d5);
            assert_eq!(output[15] & 0x600, 0x200, "IF/DF");
            assert_eq!(output[16], output[17], "outer RSP");
            assert_eq!(
                output[18], 0x5a5a5a5a5a5a5a5a,
                "beyond complete stack budget"
            );
            assert_ne!(output[19], 0x5a5a5a5a5a5a5a5a, "deepest PUSHF executed");
        }
    }
    assert_ne!(
        execute(0, 1, 2, true)[0],
        3,
        "wrong native POP must be detected"
    );
}

fn compare_native(variant: u8, program: &[u8], initial: &[u64; 15], flags: u64) -> [u64; 20] {
    let expected = execute_program(
        variant,
        program,
        initial,
        flags,
        Mutation::None,
        Execution::Native,
    );
    let actual = execute_program(
        variant,
        program,
        initial,
        flags,
        Mutation::None,
        Execution::Plain,
    );
    let encrypted = execute_program(
        variant,
        program,
        initial,
        flags,
        Mutation::None,
        Execution::Encrypted,
    );
    assert_eq!(&encrypted[..15], &expected[..15], "encrypted GPRs");
    assert_eq!(
        encrypted[15] & 0xed5,
        expected[15] & 0xed5,
        "encrypted flags"
    );
    assert_eq!(encrypted[16], encrypted[17], "encrypted RSP");
    assert_eq!(
        encrypted[18], 0x5a5a5a5a5a5a5a5a,
        "encrypted stack boundary"
    );
    assert_eq!(
        &actual[..15],
        &expected[..15],
        "GPRs, variant={variant}, bytes={program:x?}"
    );
    assert_eq!(
        actual[15] & 0xed5,
        expected[15] & 0xed5,
        "flags, variant={variant}"
    );
    for output in [actual, expected] {
        assert_eq!(output[16], output[17], "outer RSP");
        assert_eq!(output[18], 0x5a5a5a5a5a5a5a5a, "stack boundary");
    }
    actual
}

#[test]
fn mov_only_preserves_incoming_flags() {
    let initial = std::array::from_fn(|i| if i == 0 { 0x202 } else { u64::MAX - i as u64 });
    let mov = [0x48, 0x89, 0xc8];
    for variant in 0..=u8::MAX {
        for bits in [0, 1, 4, 0x10, 0x40, 0x80, 0x800, 0x8d5] {
            let flags = 0x202 | bits;
            let output = compare_native(variant, &mov, &initial, flags);
            assert_eq!(output[15] & 0x8d5, bits, "entry flags");
        }
    }
    let corrupt = execute_program(
        0,
        &mov,
        &initial,
        0xad7,
        Mutation::CaptureFlags,
        Execution::Plain,
    );
    assert_ne!(
        corrupt[15] & 0x8d5,
        0x8d5,
        "wrong entry capture must be detected"
    );
}

#[test]
fn all_register_pairs_match_native_including_aliases() {
    let regs = [
        rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    let initial = std::array::from_fn(|i| match i % 3 {
        0 => u64::MAX - i as u64,
        1 => 0x7fffffffffffffff - i as u64,
        _ => i as u64 + 1,
    });
    for destination in regs {
        for source in regs {
            for add in [false, true] {
                let mut a = CodeAssembler::new(64).expect("assembler");
                if add {
                    a.add(destination, source).expect("ADD");
                } else {
                    a.mov(destination, source).expect("MOV");
                }
                let bytes = a.assemble(0x1000).expect("native instruction");
                for variant in 0..16 {
                    compare_native(variant, &bytes, &initial, 0xad7);
                }
            }
        }
    }
}

#[test]
fn maximum_body_compositions_match_native() {
    let initial = std::array::from_fn(|i| u64::MAX - i as u64);
    for template in [
        &[0x48, 0x89, 0xc8][..],
        &[0x48, 0x01, 0xd0][..],
        &[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0][..],
    ] {
        let instruction_count = Decoder::new(64, template, DecoderOptions::NONE)
            .into_iter()
            .count();
        let program = template.repeat(256 / instruction_count);
        assert_eq!(
            Decoder::new(64, &program, DecoderOptions::NONE)
                .into_iter()
                .count(),
            256
        );
        for variant in 0..=u8::MAX {
            compare_native(variant, &program, &initial, 0xad7);
        }
    }
}
