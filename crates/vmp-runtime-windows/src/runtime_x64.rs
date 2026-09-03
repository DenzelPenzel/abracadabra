//! The unsafe surface is intentionally confined to the two naked x64 entry
//! points. The public wrapper accepts bounded Rust slices.
#![allow(unsafe_code)]

use core::arch::naked_asm;
use thiserror::Error;

/// Maximum v1 instruction-stream size: 1 MiB container minus its 16-byte header.
pub const MAX_RUNTIME_CODE_SIZE: usize = 1024 * 1024 - 16;

const MAX_RUNTIME_STEPS: u32 = 1_000_000;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeTrap {
    #[error("runtime bytecode size {size} exceeds {maximum}")]
    BytecodeTooLarge { size: usize, maximum: usize },
    #[error("truncated runtime bytecode")]
    TruncatedBytecode,
    #[error("unsupported runtime opcode")]
    UnsupportedOpcode,
    #[error("invalid runtime operand")]
    InvalidOperand,
    #[error("runtime VM stack underflow")]
    StackUnderflow,
    #[error("runtime VM stack overflow")]
    StackOverflow,
    #[error("runtime VM stack is not empty at return")]
    NonEmptyStack,
    #[error("runtime RFLAGS restoration mismatch")]
    FlagRestoreMismatch,
    #[error("runtime VM step limit reached")]
    StepLimit,
}

/// Guest state observable after the raw runtime returns to native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeExecution {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rflags: u64,
}

#[repr(C)]
struct GateOutput {
    status: u64,
    rax: u64,
    runtime_rflags: u64,
    observed_rflags: u64,
    rcx: u64,
    rdx: u64,
}

/// Execute the first register-only runtime slice through a raw Win64 gate.
///
/// The accepted bytecode subset is `PushReg` for RCX/RDX, qword `Add`,
/// `PopReg` to RAX, and `Ret`. All bytecode fetches and operand-stack accesses
/// are bounded and fail closed with [`RuntimeTrap`].
pub fn execute_raw_gate(code: &[u8], lhs: u64, rhs: u64) -> Result<RuntimeExecution, RuntimeTrap> {
    if code.len() > MAX_RUNTIME_CODE_SIZE {
        return Err(RuntimeTrap::BytecodeTooLarge {
            size: code.len(),
            maximum: MAX_RUNTIME_CODE_SIZE,
        });
    }

    let mut output = GateOutput {
        status: u64::MAX,
        rax: 0,
        runtime_rflags: 0,
        observed_rflags: 0,
        rcx: 0,
        rdx: 0,
    };
    let code_end = code.as_ptr().wrapping_add(code.len());

    // SAFETY: `raw_gate` receives valid bounds from `code`, a valid status
    // pointer, and restores the Win64 nonvolatile registers before returning.
    unsafe {
        raw_gate(
            code.as_ptr(),
            code_end,
            lhs,
            rhs,
            core::ptr::addr_of_mut!(output),
        )
    };

    match output.status {
        0 if output.runtime_rflags == output.observed_rflags => Ok(RuntimeExecution {
            rax: output.rax,
            rcx: output.rcx,
            rdx: output.rdx,
            rflags: output.observed_rflags,
        }),
        0 => Err(RuntimeTrap::FlagRestoreMismatch),
        1 => Err(RuntimeTrap::TruncatedBytecode),
        2 => Err(RuntimeTrap::UnsupportedOpcode),
        3 => Err(RuntimeTrap::InvalidOperand),
        4 => Err(RuntimeTrap::StackUnderflow),
        5 => Err(RuntimeTrap::StackOverflow),
        6 => Err(RuntimeTrap::NonEmptyStack),
        7 => Err(RuntimeTrap::StepLimit),
        _ => Err(RuntimeTrap::InvalidOperand),
    }
}

/// Test gate using the Win64 calling convention on every x86-64 host.
///
/// It converts normal Win64 arguments into the legacy-compatible entry frame:
/// bytecode pointer, bytecode end, then an outcome pointer. RCX and RDX are
/// loaded with guest values before control reaches the raw runtime entry.
#[unsafe(naked)]
unsafe extern "win64" fn raw_gate(
    _code: *const u8,
    _code_end: *const u8,
    _lhs: u64,
    _rhs: u64,
    _output: *mut GateOutput,
) -> u64 {
    naked_asm!(
        "push qword ptr [rsp + 40]",
        "push rdx",
        "push rcx",
        "mov rcx, r8",
        "mov rdx, r9",
        "call {runtime_entry}",
        "lea rsp, [rsp + 24]",
        // Observe the flags that reached the native continuation without
        // changing any guest register or flag.
        "push r10",
        "mov r10, qword ptr [rsp + 48]",
        "mov qword ptr [r10 + 32], rcx",
        "mov qword ptr [r10 + 40], rdx",
        "push rax",
        "pushfq",
        "pop rax",
        "mov qword ptr [r10 + 24], rax",
        "pop rax",
        "pop r10",
        "ret",
        runtime_entry = sym runtime_entry,
    )
}

/// Minimal native x64 VM processor entry.
///
/// Entry stack, above the return address: bytecode begin, bytecode end, status
/// pointer. The processor captures all modeled GPRs and RFLAGS before using any
/// of them as runtime scratch registers.
#[unsafe(naked)]
unsafe extern "C" fn runtime_entry() {
    naked_asm!(
        "pushfq",
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // R15 is the immutable saved-context base. Metadata follows the saved
        // register frame at offsets 136, 144, and 152.
        "mov r15, rsp",
        "mov r13, qword ptr [r15 + 136]",
        "mov r12, qword ptr [r15 + 144]",
        // Reserve a bounded operand stack and keep its empty top in R11.
        "sub rsp, 128",
        "and rsp, -16",
        "mov r14, rsp",
        "mov r11, rsp",
        "lea rbx, [rsp + 128]",
        "mov ebp, {max_steps}",
        // Fetch one opcode, failing closed at the bytecode boundary.
        "2:",
        "test ebp, ebp",
        "jz 27f",
        "dec ebp",
        "cmp r13, r12",
        "jae 20f",
        "movzx eax, byte ptr [r13]",
        "inc r13",
        "cmp al, 0x01",
        "je 10f",
        "cmp al, 0x11",
        "je 3f",
        "cmp al, 0x12",
        "je 5f",
        "cmp al, 0x20",
        "je 7f",
        "jmp 21f",
        // PUSH_REG qword, currently bounded to RCX and RDX for the first
        // vertical proof slice.
        "3:",
        "mov rax, r12",
        "sub rax, r13",
        "cmp rax, 2",
        "jb 20f",
        "cmp byte ptr [r13], 8",
        "jne 22f",
        "movzx eax, byte ptr [r13 + 1]",
        "add r13, 2",
        "lea r10, [r14 + 8]",
        "cmp r10, rbx",
        "ja 24f",
        "cmp al, 1",
        "je 4f",
        "cmp al, 2",
        "jne 22f",
        "mov rax, qword ptr [r15 + 96]",
        "jmp 30f",
        "4:",
        "mov rax, qword ptr [r15 + 104]",
        "30:",
        "mov qword ptr [r14], rax",
        "mov r14, r10",
        "jmp 2b",
        // POP_REG qword, bounded to RAX for this slice.
        "5:",
        "mov rax, r12",
        "sub rax, r13",
        "cmp rax, 2",
        "jb 20f",
        "cmp byte ptr [r13], 8",
        "jne 22f",
        "cmp byte ptr [r13 + 1], 0",
        "jne 22f",
        "add r13, 2",
        "cmp r14, r11",
        "je 23f",
        "sub r14, 8",
        "mov rax, qword ptr [r14]",
        "mov qword ptr [r15 + 112], rax",
        "jmp 2b",
        // ADD qword: rhs and lhs are popped, result and native ADD flags are
        // written back to the saved guest context.
        "7:",
        "cmp r13, r12",
        "jae 20f",
        "cmp byte ptr [r13], 8",
        "jne 22f",
        "inc r13",
        "mov rax, r14",
        "sub rax, r11",
        "cmp rax, 16",
        "jb 23f",
        "sub r14, 8",
        "mov rax, qword ptr [r14]",
        "sub r14, 8",
        "add qword ptr [r14], rax",
        "pushfq",
        "pop rax",
        "mov qword ptr [r15 + 120], rax",
        "add r14, 8",
        "jmp 2b",
        // RET requires an empty VM operand stack.
        "10:",
        "cmp r14, r11",
        "jne 25f",
        "xor eax, eax",
        "jmp 26f",
        "20:",
        "mov eax, 1",
        "jmp 26f",
        "21:",
        "mov eax, 2",
        "jmp 26f",
        "22:",
        "mov eax, 3",
        "jmp 26f",
        "23:",
        "mov eax, 4",
        "jmp 26f",
        "24:",
        "mov eax, 5",
        "jmp 26f",
        "25:",
        "mov eax, 6",
        "jmp 26f",
        "27:",
        "mov eax, 7",
        // Publish status before restoring every captured register and RFLAGS.
        "26:",
        "mov r10, qword ptr [r15 + 152]",
        "mov qword ptr [r10], rax",
        "mov rax, qword ptr [r15 + 112]",
        "mov qword ptr [r10 + 8], rax",
        "mov rax, qword ptr [r15 + 120]",
        "mov qword ptr [r10 + 16], rax",
        "mov rsp, r15",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "popfq",
        "ret",
        max_steps = const MAX_RUNTIME_STEPS,
    )
}
