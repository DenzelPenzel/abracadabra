//! Decoder and CFG tests over hand-built images.
//!
//! Every byte of code here is written by the test, so a failure names one
//! decision rather than one binary. The corpus tests cover the opposite side:
//! whether the same decisions hold on code a real compiler emitted.

use vmp_ir::{DecodeIssue, EdgeKind, EdgeTarget, OperandRef, TargetKind, Terminator};
use vmp_pe::PeFile;
use vmp_types::Rva;
use vmp_x86::{decode_function, decode_function_with, DecodeOptions, Image, X86Error};

const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const RELOC_RVA: u32 = 0x3000;
const IMAGE_BASE: u64 = 0x1_4000_0000;

/// A minimal PE32+ with `.text`, `.rdata` and `.reloc`, all one page each.
struct Builder {
    text: Vec<u8>,
    rdata: Vec<u8>,
    fixups: Vec<(u32, u16)>,
}

/// `IMAGE_REL_BASED_DIR64`.
const REL_DIR64: u16 = 10;

impl Builder {
    fn new(text: &[u8]) -> Builder {
        Builder {
            text: text.to_vec(),
            rdata: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn rdata(mut self, bytes: &[u8]) -> Builder {
        self.rdata = bytes.to_vec();
        self
    }

    /// Adds a base relocation at an RVA inside `.text`.
    fn fixup(mut self, rva: u32, kind: u16) -> Builder {
        self.fixups.push((rva, kind));
        self
    }

    fn build(self) -> Vec<u8> {
        let mut data = vec![0u8; 0xa00];
        put16(&mut data, 0, 0x5a4d); // MZ
        put32(&mut data, 0x3c, 0x40); // e_lfanew
        put32(&mut data, 0x40, 0x0000_4550); // PE\0\0

        put16(&mut data, 0x44, 0x8664); // Machine: AMD64
        put16(&mut data, 0x46, 3); // NumberOfSections
        put16(&mut data, 0x54, 240); // SizeOfOptionalHeader

        put16(&mut data, 0x58, 0x20b); // PE32+
        put32(&mut data, 0x58 + 16, TEXT_RVA); // AddressOfEntryPoint
        put64(&mut data, 0x58 + 24, IMAGE_BASE);
        put32(&mut data, 0x58 + 32, 0x1000); // SectionAlignment
        put32(&mut data, 0x58 + 36, 0x200); // FileAlignment
        put32(&mut data, 0x58 + 56, 0x4000); // SizeOfImage
        put32(&mut data, 0x58 + 60, 0x400); // SizeOfHeaders
        put16(&mut data, 0x58 + 68, 3); // Subsystem: console
        put32(&mut data, 0x58 + 108, 16); // NumberOfRvaAndSizes

        section(&mut data, 0, b".text", TEXT_RVA, 0x400, 0x6000_0020);
        section(&mut data, 1, b".rdata", RDATA_RVA, 0x600, 0x4000_0040);
        section(&mut data, 2, b".reloc", RELOC_RVA, 0x800, 0x4200_0040);

        data[0x400..0x400 + self.text.len()].copy_from_slice(&self.text);
        data[0x600..0x600 + self.rdata.len()].copy_from_slice(&self.rdata);

        if !self.fixups.is_empty() {
            let block = relocation_block(&self.fixups);
            data[0x800..0x800 + block.len()].copy_from_slice(&block);
            // Directory 5: base relocations
            let entry = 0x58 + 112 + 5 * 8;
            put32(&mut data, entry, RELOC_RVA);
            put32(&mut data, entry + 4, block.len() as u32);
        }
        data
    }
}

/// One relocation block covering page `TEXT_RVA`.
fn relocation_block(fixups: &[(u32, u16)]) -> Vec<u8> {
    let mut entries: Vec<u16> = fixups
        .iter()
        .map(|(rva, kind)| (kind << 12) | ((rva - TEXT_RVA) as u16))
        .collect();
    // Blocks are padded to a multiple of four bytes with ABSOLUTE entries
    if entries.len() % 2 == 1 {
        entries.push(0);
    }
    let size = 8 + entries.len() * 2;
    let mut block = Vec::with_capacity(size);
    block.extend_from_slice(&TEXT_RVA.to_le_bytes());
    block.extend_from_slice(&(size as u32).to_le_bytes());
    for entry in entries {
        block.extend_from_slice(&entry.to_le_bytes());
    }
    block
}

fn section(data: &mut [u8], index: usize, name: &[u8], rva: u32, raw: u32, characteristics: u32) {
    let base = 0x148 + index * 40;
    data[base..base + name.len()].copy_from_slice(name);
    put32(data, base + 8, 0x200); // VirtualSize
    put32(data, base + 12, rva);
    put32(data, base + 16, 0x200); // SizeOfRawData
    put32(data, base + 20, raw);
    put32(data, base + 36, characteristics);
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Decodes from `TEXT_RVA` and runs `check` against the result.
fn decoded(image: Vec<u8>, check: impl FnOnce(&vmp_ir::Function, &Image<'_>)) {
    let pe = PeFile::parse(&image).expect("synthetic image must parse");
    let view = Image::new(&pe, &image);
    let function = decode_function(view, Rva(TEXT_RVA)).expect("must decode");
    check(&function, &view);
}

#[test]
fn a_conditional_branch_produces_a_diamond() {
    // 0x1000: cmp ecx, 1        83 f9 01
    // 0x1003: jne +6            75 06   -> 0x100b
    // 0x1005: mov eax, 1        b8 01 00 00 00
    // 0x100a: ret               c3
    // 0x100b: xor eax, eax      31 c0
    // 0x100d: ret               c3
    let text = [
        0x83, 0xf9, 0x01, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        assert_eq!(function.blocks.len(), 3);
        assert_eq!(function.instruction_count(), 6);

        let entry = function.block(function.entry_block).expect("entry block");
        assert_eq!(entry.terminator, Terminator::Conditional);
        assert_eq!(entry.successors.len(), 2);
        assert_eq!(entry.successors[0].kind, EdgeKind::Taken);
        assert_eq!(entry.successors[1].kind, EdgeKind::NotTaken);

        // Both arms return, and each knows the entry precedes it
        for edge in &entry.successors {
            let EdgeTarget::Block(id) = edge.target else {
                panic!("both arms are inside the function");
            };
            let arm = function.block(id).expect("arm");
            assert_eq!(arm.terminator, Terminator::Return);
            assert_eq!(arm.predecessors, vec![entry.id]);
        }
    });
}

#[test]
fn a_backward_branch_closes_a_loop() {
    // 0x1000: xor eax, eax      31 c0
    // 0x1002: inc eax           ff c0
    // 0x1004: cmp eax, 10       83 f8 0a
    // 0x1007: jne -7            75 f9   -> 0x1002
    // 0x1009: ret               c3
    let text = [0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x0a, 0x75, 0xf9, 0xc3];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        assert_eq!(function.blocks.len(), 3);

        let head = function
            .block_containing(Rva(TEXT_RVA + 2))
            .and_then(|id| function.block(id))
            .expect("the loop body starts at a leader");
        assert_eq!(head.start, Rva(TEXT_RVA + 2));
        // Reached from the entry block and from its own back edge
        assert_eq!(head.predecessors.len(), 2);
        assert!(head.predecessors.contains(&head.id), "back edge is missing");
    });
}

#[test]
fn an_indirect_jump_is_fail_closed() {
    // 0x1000: jmp rax           ff e0
    let text = [0xff, 0xe0];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(!function.is_complete());
        assert_eq!(
            function.issues,
            vec![DecodeIssue::IndirectJump { rva: Rva(TEXT_RVA) }]
        );
        let entry = function.block(function.entry_block).expect("entry block");
        assert_eq!(entry.terminator, Terminator::IndirectJump);
        assert!(entry.successors.is_empty());
    });
}

#[test]
fn an_indirect_call_does_not_end_the_block() {
    // 0x1000: call rax          ff d0
    // 0x1002: ret               c3
    let text = [0xff, 0xd0, 0xc3];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        assert_eq!(function.blocks.len(), 1, "a call never splits a block");
        assert_eq!(function.instruction_count(), 2);
        let entry = function.block(function.entry_block).expect("entry block");
        assert_eq!(entry.terminator, Terminator::Return);
    });
}

#[test]
fn a_direct_call_is_recorded_but_not_followed() {
    // 0x1000: call +0x10        e8 10 00 00 00   -> 0x1015
    // 0x1005: ret               c3
    let text = [0xe8, 0x10, 0x00, 0x00, 0x00, 0xc3];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        assert_eq!(
            function.instruction_count(),
            2,
            "the callee must not be decoded into this function"
        );

        let call = function.instructions().next().expect("the call");
        assert_eq!(call.branch_target(), Some(Rva(0x1015)));
        // A call is not a control-flow edge of the caller's graph
        assert!(function.external_targets().is_empty());
    });
}

#[test]
fn zero_padding_is_not_decoded_as_code() {
    // 0x1000: jmp +2            eb 02   -> 0x1004, skipping two zero bytes
    // 0x1002: 00 00             the `add [rax], al` reading of padding
    // 0x1004: ret               c3
    let text = [0xeb, 0x02, 0x00, 0x00, 0xc3];
    decoded(Builder::new(&text).build(), |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        for instruction in function.instructions() {
            assert_ne!(
                instruction.bytes(),
                [0x00, 0x00],
                "padding must not become an instruction"
            );
        }
    });
}

#[test]
fn a_rip_relative_operand_resolves_to_its_section() {
    // 0x1000: mov eax, [rip+0xffa]   8b 05 fa 0f 00 00   -> 0x2000
    // 0x1006: ret                    c3
    let text = [0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00, 0xc3];
    decoded(Builder::new(&text).rdata(&[1, 2, 3, 4]).build(), |f, _| {
        let load = f.instructions().next().expect("the load");
        let reference = load.refs().first().expect("one reference");
        match reference {
            OperandRef::RipRelative {
                target,
                target_kind,
                field,
            } => {
                assert_eq!(*target, Rva(RDATA_RVA));
                assert_eq!(*target_kind, TargetKind::Data);
                assert_eq!(field.offset, 2, "the displacement follows the ModRM byte");
                assert_eq!(field.size, 4);
            }
            other => panic!("expected a RIP-relative reference, got {other:?}"),
        }
    });
}

#[test]
fn a_relocated_immediate_becomes_an_absolute_reference() {
    // 0x1000: movabs rax, 0x140002000   48 b8 00 20 00 40 01 00 00 00
    // 0x100a: ret                       c3
    // The 64-bit immediate at 0x1002 carries a DIR64 base relocation
    let text = [
        0x48, 0xb8, 0x00, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ];
    let image = Builder::new(&text).fixup(TEXT_RVA + 2, REL_DIR64).build();
    decoded(image, |function, _| {
        assert!(function.is_complete(), "issues: {:?}", function.issues);
        let load = function.instructions().next().expect("the load");
        let reference = load
            .refs()
            .iter()
            .find(|reference| matches!(reference, OperandRef::Absolute { .. }))
            .expect("the relocated immediate must be bound");

        match reference {
            OperandRef::Absolute {
                va,
                target,
                width,
                target_kind,
                field,
            } => {
                assert_eq!(va.get(), IMAGE_BASE + u64::from(RDATA_RVA));
                assert_eq!(*target, Some(Rva(RDATA_RVA)));
                assert_eq!(*width, vmp_ir::AbsoluteWidth::Bits64);
                assert_eq!(*target_kind, TargetKind::Data);
                assert_eq!(field.offset, 2);
                assert_eq!(field.size, 8);
            }
            other => panic!("expected an absolute reference, got {other:?}"),
        }
    });
}

#[test]
fn a_relocation_that_misses_every_field_is_reported() {
    // The same `movabs`, but the relocation claims the opcode byte rather than
    // the immediate, which can only mean the decode disagrees with the linker
    let text = [
        0x48, 0xb8, 0x00, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ];
    let image = Builder::new(&text).fixup(TEXT_RVA + 1, REL_DIR64).build();
    decoded(image, |function, _| {
        assert_eq!(
            function.issues,
            vec![DecodeIssue::FixupOutsideField {
                rva: Rva(TEXT_RVA),
                fixup: Rva(TEXT_RVA + 1),
            }]
        );
    });
}

#[test]
fn a_branch_into_a_non_executable_section_is_reported() {
    // 0x1000: jne +0xffa        0f 85 fa 0f 00 00   -> 0x2000, inside .rdata
    // 0x1006: ret               c3
    let text = [0x0f, 0x85, 0xfa, 0x0f, 0x00, 0x00, 0xc3];
    decoded(Builder::new(&text).build(), |function, _| {
        assert_eq!(
            function.issues,
            vec![DecodeIssue::TargetNotExecutable {
                rva: Rva(TEXT_RVA),
                target: Rva(RDATA_RVA),
            }]
        );
        // The edge survives as external so the graph stays honest
        assert_eq!(function.external_targets(), vec![Rva(RDATA_RVA)]);
    });
}

#[test]
fn an_entry_outside_executable_memory_is_rejected() {
    let image = Builder::new(&[0xc3]).build();
    let pe = PeFile::parse(&image).expect("must parse");
    let view = Image::new(&pe, &image);

    assert_eq!(
        decode_function(view, Rva(RDATA_RVA)).err(),
        Some(X86Error::EntryNotExecutable {
            rva: Rva(RDATA_RVA)
        })
    );
    assert_eq!(
        decode_function(view, Rva(0x9000)).err(),
        Some(X86Error::EntryUnmapped { rva: Rva(0x9000) })
    );
}

#[test]
fn the_budget_bounds_a_pathological_input() {
    // A one-byte infinite loop: `jmp -2`. Decoding converges immediately, so
    // exercise the budget with a long straight run of `nop` instead
    let text = vec![0x90u8; 0x200];
    let image = Builder::new(&text).build();
    let pe = PeFile::parse(&image).expect("must parse");
    let view = Image::new(&pe, &image);

    let function = decode_function_with(view, Rva(TEXT_RVA), DecodeOptions { budget: 10 })
        .expect("a truncated decode is still a function");
    assert_eq!(function.instruction_count(), 10);
    assert_eq!(
        function.issues,
        vec![DecodeIssue::BudgetExceeded { limit: 10 }]
    );
}

#[test]
fn decoding_from_every_offset_of_arbitrary_bytes_never_panics() {
    // A deterministic pseudo-random page: the point is that no byte sequence,
    // at any entry, may panic or hang
    let mut text = vec![0u8; 0x200];
    let mut state = 0x1234_5678u32;
    for byte in text.iter_mut() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 16) as u8;
    }
    let image = Builder::new(&text).build();
    let pe = PeFile::parse(&image).expect("must parse");
    let view = Image::new(&pe, &image);

    for offset in 0..0x200u32 {
        let entry = Rva(TEXT_RVA + offset);
        match decode_function_with(view, entry, DecodeOptions { budget: 4096 }) {
            Ok(function) => {
                for block in &function.blocks {
                    assert!(!block.instructions.is_empty());
                }
            }
            Err(error) => match error {
                X86Error::NothingDecoded { .. } => {}
                other => panic!("unexpected error at {entry}: {other}"),
            },
        }
    }
}
