//! Windows OS oracle for the standalone generated frame

use super::build_runtime_image;
use crate::emit::{emit_interpreter, RuntimeBlob};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, Register};
use std::ffi::c_void;
use std::ptr::{null, null_mut, NonNull};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, RtlAddFunctionTable, RtlDeleteFunctionTable, RtlLookupFunctionEntry,
    RtlVirtualUnwind, CONTEXT, CONTEXT_ALL_AMD64, IMAGE_RUNTIME_FUNCTION_ENTRY, UNW_FLAG_NHANDLER,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

struct MappedImage {
    base: NonNull<c_void>,
    table_offset: u32,
    registered: bool,
}

impl MappedImage {
    #[allow(unsafe_code)]
    fn new(blob: &RuntimeBlob) -> Self {
        let image = build_runtime_image(blob).expect("runtime image must serialize");
        // SAFETY: The allocation is private, and the owner releases it on every later failure
        let base = unsafe {
            VirtualAlloc(
                null(),
                image.bytes.len(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let mut mapping = Self {
            base: NonNull::new(base).expect("VirtualAlloc must allocate the proof image"),
            table_offset: image.function_table_offset,
            registered: false,
        };
        // SAFETY: The fresh RW allocation holds the entire image and does not overlap its source
        unsafe {
            std::ptr::copy_nonoverlapping(
                image.bytes.as_ptr(),
                mapping.base.as_ptr().cast(),
                image.bytes.len(),
            );
        }
        let mut old_protection = 0;
        // SAFETY: The owner keeps the allocation live throughout protection and cache synchronization
        unsafe {
            assert_ne!(
                VirtualProtect(
                    base,
                    image.bytes.len(),
                    PAGE_EXECUTE_READ,
                    &mut old_protection
                ),
                0,
                "VirtualProtect must publish RX bytes"
            );
            assert_ne!(
                FlushInstructionCache(GetCurrentProcess(), base, image.bytes.len()),
                0,
                "FlushInstructionCache must synchronize the image"
            );
        }
        // SAFETY: Both table entries and their referenced code/xdata stay in this owned mapping
        mapping.registered = unsafe { RtlAddFunctionTable(mapping.table(), 2, mapping.address(0)) };
        assert!(
            mapping.registered,
            "RtlAddFunctionTable must register the image"
        );
        mapping
    }

    fn table(&self) -> *const IMAGE_RUNTIME_FUNCTION_ENTRY {
        self.address(self.table_offset) as *const IMAGE_RUNTIME_FUNCTION_ENTRY
    }

    fn address(&self, offset: u32) -> u64 {
        self.base.as_ptr() as u64 + u64::from(offset)
    }

    #[allow(unsafe_code)]
    fn lookup(&self, offset: u32, index: u32) -> *mut IMAGE_RUNTIME_FUNCTION_ENTRY {
        let mut image_base = 0;
        // SAFETY: Lookup only queries the live mapping and writes a local output value
        let entry =
            unsafe { RtlLookupFunctionEntry(self.address(offset), &mut image_base, null_mut()) };
        assert!(
            !entry.is_null(),
            "generated code at offset {offset:#x} has no registered RUNTIME_FUNCTION"
        );
        assert_eq!(
            image_base,
            self.address(0),
            "lookup must return this image's base"
        );
        assert_eq!(
            entry as u64,
            self.address(self.table_offset + index * 12),
            "lookup must return the persistent table entry"
        );
        entry
    }
}

impl Drop for MappedImage {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: No probe is executing, and this exact table is still backed by live storage
            let removed = unsafe { RtlDeleteFunctionTable(self.table()) };
            assert!(
                removed,
                "unregister must succeed before freeing its storage"
            );
            self.registered = false;
        }
        // SAFETY: No code is executing and the table no longer references this allocation
        let released = unsafe { VirtualFree(self.base.as_ptr(), 0, MEM_RELEASE) };
        assert_ne!(released, 0, "VirtualFree must release the proof image");
    }
}

const NONVOLATILES: [Register; 8] = [
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const CALLER_VALUES: [u64; 8] = [
    0x1133, 0x2255, 0x3377, 0x4499, 0x55bb, 0x66dd, 0x77ee, 0x88ff,
];
const CALLER_RIP: u64 = 0x0000_1234_5678_9abc;

// Physical stack words from the saved flags upward, independent of UNWIND_CODE generation
const SAVED_WORDS: [u64; 17] = [
    0x202, 0x88ff, 0x77ee, 0x66dd, 0x55bb, 0xb0b0, 0xa0a0, 0x9090, 0x8080, 0x4499, 0x3377, 0x2255,
    0x1133, 0xd0d0, 0xc0c0, 0xa1a1, CALLER_RIP,
];
const PROLOGUE: [u8; 27] = [
    0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41,
    0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x9c, 0x49, 0x89, 0xe7,
];
const PROLOGUE_STATES: [(u32, usize); 18] = [
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
    (4, 4),
    (5, 5),
    (6, 6),
    (7, 7),
    (9, 8),
    (11, 9),
    (13, 10),
    (15, 11),
    (17, 12),
    (19, 13),
    (21, 14),
    (23, 15),
    (24, 16),
    (27, 16),
];

fn set_nonvolatile(context: &mut CONTEXT, register: Register, value: u64) {
    match register {
        Register::RBX => context.Rbx = value,
        Register::RBP => context.Rbp = value,
        Register::RSI => context.Rsi = value,
        Register::RDI => context.Rdi = value,
        Register::R12 => context.R12 = value,
        Register::R13 => context.R13 = value,
        Register::R14 => context.R14 = value,
        Register::R15 => context.R15 = value,
        _ => panic!("not a fixture nonvolatile"),
    }
}

#[repr(align(16))]
struct Frame([u64; 96]);

impl Frame {
    fn new() -> Self {
        let mut frame = Self([0xdead_dead_dead_dead; 96]);
        frame.0[49..66].copy_from_slice(&SAVED_WORDS);
        frame
    }

    fn slot(&self, index: usize) -> u64 {
        &self.0[index] as *const u64 as u64
    }

    fn context(&self, mapping: &MappedImage, offset: u32, body: bool) -> CONTEXT {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64,
            Rip: mapping.address(offset),
            Rsp: self.slot(65),
            ..Default::default()
        };
        for (register, value) in NONVOLATILES.into_iter().zip(CALLER_VALUES) {
            set_nonvolatile(&mut context, register, if body { 0xbad0 } else { value });
        }
        if body {
            context.R15 = self.slot(49);
            context.Rsp = self.slot(32);
        }
        context
    }

    #[allow(unsafe_code)]
    fn check(&self, mapping: &MappedImage, offset: u32, mut context: CONTEXT) {
        let entry = mapping.lookup(offset, 1);
        let mut handler_data = null_mut();
        let mut establisher = 0;
        // SAFETY: The trusted image and synthetic stack remain live; all modeled reads are inside
        // the frame, and the returned RIP is compared as data rather than resumed
        let handler = unsafe {
            RtlVirtualUnwind(
                UNW_FLAG_NHANDLER,
                mapping.address(0),
                context.Rip,
                entry,
                &mut context,
                &mut handler_data,
                &mut establisher,
                null_mut(),
            )
        };
        assert!(handler.is_none(), "no language handler at {offset:#x}");
        assert_eq!(context.Rip, CALLER_RIP, "caller RIP at {offset:#x}");
        assert_eq!(context.Rsp, self.slot(66), "caller RSP at {offset:#x}");
        assert_eq!(
            [
                context.Rbx,
                context.Rbp,
                context.Rsi,
                context.Rdi,
                context.R12,
                context.R13,
                context.R14,
                context.R15
            ],
            CALLER_VALUES,
            "caller nonvolatiles at {offset:#x}"
        );
    }
}

fn production_instructions(blob: &RuntimeBlob) -> Vec<Instruction> {
    let start = blob.production_entry_offset();
    assert_eq!(
        &blob.bytes()[start as usize..start as usize + PROLOGUE.len()],
        &PROLOGUE
    );
    Decoder::with_ip(
        64,
        &blob.bytes()[start as usize..],
        u64::from(start),
        DecoderOptions::NONE,
    )
    .into_iter()
    .collect()
}

fn epilogue_index(instructions: &[Instruction]) -> usize {
    instructions
        .iter()
        .position(|instruction| {
            instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_register() == Register::RSP
                && instruction.memory_base() == Register::R15
        })
        .expect("production epilogue must start with LEA RSP,[R15+8]")
}

#[test]
fn lookup_covers_adapter_dispatcher_and_handlers() {
    let blob = emit_interpreter().expect("interpreter must assemble");
    let mapping = MappedImage::new(&blob);
    for (index, function) in blob.unwind_plan.functions.iter().enumerate() {
        for offset in function.range.start()..function.range.end() {
            mapping.lookup(offset, index as u32);
        }
    }
}

#[test]
fn virtual_unwind_restores_caller_at_every_partial_prologue_boundary() {
    let blob = emit_interpreter().expect("interpreter must assemble");
    let mapping = MappedImage::new(&blob);
    production_instructions(&blob);
    let frame = Frame::new();
    for (relative, pushes) in PROLOGUE_STATES {
        let offset = blob.production_entry_offset() + relative;
        let mut context = frame.context(&mapping, offset, false);
        context.Rsp = frame.slot(65 - pushes);
        if relative == 27 {
            context.R15 = frame.slot(49);
        }
        frame.check(&mapping, offset, context);
    }
}

#[test]
fn virtual_unwind_restores_caller_through_dispatcher_and_handlers() {
    let blob = emit_interpreter().expect("interpreter must assemble");
    let mapping = MappedImage::new(&blob);
    let instructions = production_instructions(&blob);
    let frame = Frame::new();
    let epilogue = epilogue_index(&instructions);
    for instruction in &instructions[17..epilogue] {
        let offset = instruction.ip() as u32;
        // Exercise pre-allocation, aligned operand-stack, and transient-push stack positions
        for stack_slot in [49, 33, 32, 31] {
            let mut context = frame.context(&mapping, offset, true);
            context.Rsp = frame.slot(stack_slot);
            frame.check(&mapping, offset, context);
        }
    }
}

#[test]
fn virtual_unwind_restores_caller_at_every_epilogue_boundary() {
    let blob = emit_interpreter().expect("interpreter must assemble");
    let mapping = MappedImage::new(&blob);
    let instructions = production_instructions(&blob);
    let epilogue = &instructions[epilogue_index(&instructions)..];
    let pops = [
        Register::R15,
        Register::R14,
        Register::R13,
        Register::R12,
        Register::R11,
        Register::R10,
        Register::R9,
        Register::R8,
        Register::RDI,
        Register::RSI,
        Register::RBP,
        Register::RBX,
        Register::RDX,
        Register::RCX,
        Register::RAX,
    ];
    assert_eq!(epilogue.len(), 17);
    assert_eq!(epilogue[0].memory_displacement64(), 8);
    assert_eq!(epilogue[16].mnemonic(), Mnemonic::Ret);
    let frame = Frame::new();
    let mut context = frame.context(&mapping, epilogue[0].ip() as u32, true);
    frame.check(&mapping, epilogue[0].ip() as u32, context);
    context.Rsp = frame.slot(50);
    for (index, register) in pops.into_iter().enumerate() {
        let instruction = &epilogue[index + 1];
        assert_eq!(instruction.mnemonic(), Mnemonic::Pop);
        assert_eq!(instruction.op0_register(), register);
        context.Rip = mapping.address(instruction.ip() as u32);
        frame.check(&mapping, instruction.ip() as u32, context);
        if NONVOLATILES.contains(&register) {
            set_nonvolatile(&mut context, register, SAVED_WORDS[index + 1]);
        }
        context.Rsp = frame.slot(51 + index);
    }
    context.Rip = mapping.address(epilogue[16].ip() as u32);
    frame.check(&mapping, epilogue[16].ip() as u32, context);
}
