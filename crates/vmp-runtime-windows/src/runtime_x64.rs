//! The unsafe surface is intentionally confined to mapping the emitted
//! interpreter and calling its Win64 entry point. The public wrapper accepts
//! bounded Rust slices.
#![allow(unsafe_code)]

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;
use vmp_vm::bytecode::{decode, DecodeError, MAX_CONTAINER_SIZE, V1_HEADER_SIZE};

use crate::emit::{emit_interpreter, status, EmitError};

/// Maximum v1 instruction-stream size: 1 MiB container minus its 16-byte header.
pub const MAX_RUNTIME_CODE_SIZE: usize = MAX_CONTAINER_SIZE - V1_HEADER_SIZE;

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

/// Failure to prepare the runtime, to validate bytecode, or inside the runtime.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error(transparent)]
    Emit(#[from] EmitError),
    #[error("{step} the {size}-byte interpreter failed")]
    Mapping { step: MappingStep, size: usize },
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Trap(#[from] RuntimeTrap),
}

/// Operating-system step that failed while publishing the interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MappingStep {
    /// Reserving and committing the pages.
    Reserve,
    /// Making the filled pages executable.
    Protect,
    /// Making the instruction cache coherent with the written bytes.
    Flush,
}

impl fmt::Display for MappingStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reserve => "reserving pages for",
            Self::Protect => "making the pages executable for",
            Self::Flush => "flushing the instruction cache for",
        })
    }
}

/// Guest state observable after the runtime returns to native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeExecution {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestState {
    rflags: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[repr(C)]
struct GateInput {
    code_base: *const u8,
    entry_pc: *const u8,
    code_end: *const u8,
    state: GuestState,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateOutput {
    status: u64,
    runtime_rflags: u64,
    observed_rflags: u64,
    rsp_before: u64,
    rsp_after: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

impl GateOutput {
    fn empty() -> Self {
        Self {
            status: u64::MAX,
            runtime_rflags: 0,
            observed_rflags: 0,
            rsp_before: 0,
            rsp_after: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }
}

/// Win64 entry point of the emitted interpreter.
///
/// It loads a complete guest context from the input record and observes the
/// state that the separate production entry restores.
type GateFn = unsafe extern "win64" fn(input: *const GateInput, output: *mut GateOutput) -> u64;

/// Validate a v1 container before executing its entry point through the gate.
///
/// The accepted bytecode subset is `PushReg` for RCX/RDX, qword `Add`,
/// `PopReg` to RAX, and `Ret`. All bytecode fetches and operand-stack accesses
/// are bounded and fail closed with [`RuntimeTrap`].
pub fn execute_validated_gate(
    container: &[u8],
    lhs: u64,
    rhs: u64,
) -> Result<RuntimeExecution, RuntimeError> {
    let program = decode(container)?;
    let code = &container[V1_HEADER_SIZE..];
    run_gate(
        mapped_gate()?,
        code,
        program.entry_offset() as usize,
        lhs,
        rhs,
    )
}

#[cfg(test)]
pub(crate) fn execute_raw_gate(
    code: &[u8],
    lhs: u64,
    rhs: u64,
) -> Result<RuntimeExecution, RuntimeError> {
    if code.len() > MAX_RUNTIME_CODE_SIZE {
        return Err(RuntimeTrap::BytecodeTooLarge {
            size: code.len(),
            maximum: MAX_RUNTIME_CODE_SIZE,
        }
        .into());
    }
    run_gate(mapped_gate()?, code, 0, lhs, rhs)
}

fn run_gate(
    gate: GateFn,
    code: &[u8],
    entry_offset: usize,
    lhs: u64,
    rhs: u64,
) -> Result<RuntimeExecution, RuntimeError> {
    let initial = GuestState {
        rflags: 0x202,
        rax: 0xfeed_face_cafe_beef,
        rcx: lhs,
        rdx: rhs,
        rbx: 0x0303_0303_0303_0303,
        rbp: 0x0404_0404_0404_0404,
        rsi: 0x0505_0505_0505_0505,
        rdi: 0x0606_0606_0606_0606,
        r8: 0x0808_0808_0808_0808,
        r9: 0x0909_0909_0909_0909,
        r10: 0x1010_1010_1010_1010,
        r11: 0x1111_1111_1111_1111,
        r12: 0x1212_1212_1212_1212,
        r13: 0x1313_1313_1313_1313,
        r14: 0x1414_1414_1414_1414,
        r15: 0x1515_1515_1515_1515,
    };
    let output = run_gate_observed(gate, code, entry_offset, initial)?;

    match output.status {
        status::OK if output.runtime_rflags == output.observed_rflags => Ok(RuntimeExecution {
            rax: output.rax,
            rcx: output.rcx,
            rdx: output.rdx,
            rflags: output.observed_rflags,
        }),
        status::OK => Err(RuntimeTrap::FlagRestoreMismatch.into()),
        status::TRUNCATED_BYTECODE => Err(RuntimeTrap::TruncatedBytecode.into()),
        status::UNSUPPORTED_OPCODE => Err(RuntimeTrap::UnsupportedOpcode.into()),
        status::INVALID_OPERAND => Err(RuntimeTrap::InvalidOperand.into()),
        status::STACK_UNDERFLOW => Err(RuntimeTrap::StackUnderflow.into()),
        status::STACK_OVERFLOW => Err(RuntimeTrap::StackOverflow.into()),
        status::NON_EMPTY_STACK => Err(RuntimeTrap::NonEmptyStack.into()),
        status::STEP_LIMIT => Err(RuntimeTrap::StepLimit.into()),
        _ => Err(RuntimeTrap::InvalidOperand.into()),
    }
}

fn run_gate_observed(
    gate: GateFn,
    code: &[u8],
    entry_offset: usize,
    initial: GuestState,
) -> Result<GateOutput, RuntimeError> {
    let entry = code
        .get(entry_offset..)
        .ok_or(RuntimeTrap::InvalidOperand)?;
    run_gate_observed_bounds(
        gate,
        code.as_ptr(),
        entry.as_ptr(),
        code.as_ptr().wrapping_add(code.len()),
        initial,
    )
}

fn run_gate_observed_bounds(
    gate: GateFn,
    code_base: *const u8,
    entry_pc: *const u8,
    code_end: *const u8,
    initial: GuestState,
) -> Result<GateOutput, RuntimeError> {
    let mut output = GateOutput::empty();
    let input = GateInput {
        code_base,
        entry_pc,
        code_end,
        state: initial,
    };

    // SAFETY: `gate` points at the read-execute mapping of the emitted
    // interpreter, whose entry point is the Win64 signature `GateFn` describes.
    // Both records remain valid for the call, their code pointers describe one
    // live slice, and the adapter restores its caller's nonvolatile registers.
    unsafe { gate(core::ptr::addr_of!(input), core::ptr::addr_of_mut!(output)) };
    Ok(output)
}

/// Address of the interpreter's entry point in an executable mapping.
///
/// Zero means "not mapped yet"; the emitted entry point can never be zero.
static GATE: AtomicUsize = AtomicUsize::new(0);

/// Return the entry point of the shared interpreter.
///
/// On first use, the interpreter is emitted, mapped, and cached for the life of
/// the process. Concurrent first calls may create extra valid mappings that are
/// not reused.
fn mapped_gate() -> Result<GateFn, RuntimeError> {
    let cached = GATE.load(Ordering::Acquire);
    let entry = if cached == 0 {
        let blob = emit_interpreter()?;
        let entry = map_executable(blob.bytes())? + blob.test_entry_offset() as usize;
        GATE.store(entry, Ordering::Release);
        entry
    } else {
        cached
    };

    // SAFETY: `entry` is the entry point of a read-execute mapping of the
    // emitted interpreter.
    Ok(unsafe { gate_at(entry) })
}

/// Reinterpret a mapped interpreter entry point as its Win64 signature.
///
/// # Safety
///
/// `entry` must be the entry point of a live read-execute mapping of the bytes
/// [`emit_interpreter`] produced.
unsafe fn gate_at(entry: usize) -> GateFn {
    core::mem::transmute::<usize, GateFn>(entry)
}

/// Copy `bytes` into a fresh read-execute mapping and return its base address.
///
/// The mapping is filled while it is read-write and flipped to read-execute
/// before it is returned, so the process never holds writable executable
/// memory at a point where the runtime could be entered.
#[cfg(unix)]
fn map_executable(bytes: &[u8]) -> Result<usize, RuntimeError> {
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    const MAP_PRIVATE: i32 = 0x0002;
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x0020;

    extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
        fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut u8, len: usize) -> i32;
    }

    let size = bytes.len();
    if bytes.is_empty() {
        return Err(RuntimeError::Mapping {
            step: MappingStep::Reserve,
            size,
        });
    }

    // SAFETY: a null hint asks the kernel to choose the address, the length is
    // non-zero, and an anonymous private mapping needs no file descriptor.
    let page = unsafe {
        mmap(
            core::ptr::null_mut(),
            bytes.len(),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page.is_null() || page as isize == -1 {
        return Err(RuntimeError::Mapping {
            step: MappingStep::Reserve,
            size,
        });
    }

    // SAFETY: the mapping is at least `size` long, writable, freshly allocated
    // by the kernel, and cannot overlap `bytes`.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), page, size) };

    // SAFETY: `page` and the length are the mapping this function just created.
    if unsafe { mprotect(page, size, PROT_READ | PROT_EXEC) } != 0 {
        // SAFETY: the same mapping, which nothing else can hold yet.
        unsafe { munmap(page, size) };
        return Err(RuntimeError::Mapping {
            step: MappingStep::Protect,
            size,
        });
    }

    // No instruction-cache flush is needed on this path. The module only ever
    // compiles for x86-64, where the instruction cache is kept coherent with
    // writes in hardware and the `mprotect` transition serialises. Windows
    // documents an explicit requirement instead, which the other
    // implementation honours.
    Ok(page as usize)
}

#[cfg(windows)]
fn map_executable(bytes: &[u8]) -> Result<usize, RuntimeError> {
    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const MEM_RELEASE: u32 = 0x0000_8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(
            address: *mut u8,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut u8;
        fn VirtualProtect(
            address: *mut u8,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        fn VirtualFree(address: *mut u8, size: usize, free_type: u32) -> i32;
        fn GetCurrentProcess() -> *mut u8;
        fn FlushInstructionCache(process: *mut u8, base: *const u8, size: usize) -> i32;
    }

    let size = bytes.len();
    if bytes.is_empty() {
        return Err(RuntimeError::Mapping {
            step: MappingStep::Reserve,
            size,
        });
    }

    // SAFETY: a null base lets the allocator choose the address, and the size
    // is non-zero.
    let page = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if page.is_null() {
        return Err(RuntimeError::Mapping {
            step: MappingStep::Reserve,
            size,
        });
    }

    // SAFETY: the allocation is at least `size` long, writable, freshly
    // committed, and cannot overlap `bytes`.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), page, size) };

    let mut previous = 0u32;
    // SAFETY: `page` and the length are the allocation this function just made,
    // and `previous` is a valid output slot.
    let changed = unsafe {
        VirtualProtect(
            page,
            size,
            PAGE_EXECUTE_READ,
            core::ptr::addr_of_mut!(previous),
        )
    };
    if changed == 0 {
        // SAFETY: `page` is the base address of this allocation, nothing else
        // can hold it yet, and MEM_RELEASE requires a zero size.
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };
        return Err(RuntimeError::Mapping {
            step: MappingStep::Protect,
            size,
        });
    }

    // Windows requires the instruction cache to be made coherent with freshly
    // written code before it is executed, and documents that requirement on
    // `VirtualProtect` itself. Until this succeeds the mapping is not returned,
    // so no caller can reach the generated code through a stale cache.
    //
    // SAFETY: the pseudo-handle `GetCurrentProcess` returns needs no release,
    // and `page` with the same length is the region just made executable.
    let flushed = unsafe { FlushInstructionCache(GetCurrentProcess(), page, size) };
    if flushed == 0 {
        // SAFETY: as above; the region is still owned solely by this call.
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };
        return Err(RuntimeError::Mapping {
            step: MappingStep::Flush,
            size,
        });
    }
    Ok(page as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmp_vm::bytecode::{encode, Instruction, Program, Register, Width};

    fn sentinel_state() -> GuestState {
        GuestState {
            rflags: 0x202,
            rax: 0x0101_0101_0101_0101,
            rcx: 0xffff_ffff_ffff_fffe,
            rdx: 5,
            rbx: 0x0303_0303_0303_0303,
            rbp: 0x0404_0404_0404_0404,
            rsi: 0x0505_0505_0505_0505,
            rdi: 0x0606_0606_0606_0606,
            r8: 0x0808_0808_0808_0808,
            r9: 0x0909_0909_0909_0909,
            r10: 0x1010_1010_1010_1010,
            r11: 0x1111_1111_1111_1111,
            r12: 0x1212_1212_1212_1212,
            r13: 0x1313_1313_1313_1313,
            r14: 0x1414_1414_1414_1414,
            r15: 0x1515_1515_1515_1515,
        }
    }

    fn observed_state(output: GateOutput) -> GuestState {
        GuestState {
            rflags: output.observed_rflags,
            rax: output.rax,
            rcx: output.rcx,
            rdx: output.rdx,
            rbx: output.rbx,
            rbp: output.rbp,
            rsi: output.rsi,
            rdi: output.rdi,
            r8: output.r8,
            r9: output.r9,
            r10: output.r10,
            r11: output.r11,
            r12: output.r12,
            r13: output.r13,
            r14: output.r14,
            r15: output.r15,
        }
    }

    /// Two independent mappings of one blob must behave identically.
    ///
    /// This is the execution-level position-independence proof: the emitter
    /// test shows the bytes do not depend on the assembly address, and this
    /// shows the mapped bytes do not depend on the address they run at.
    #[test]
    fn the_same_interpreter_bytes_run_identically_at_two_mappings() {
        let container = encode(&Program::new(
            0,
            vec![
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rcx,
                },
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rdx,
                },
                Instruction::Add(Width::Qword),
                Instruction::PopReg {
                    width: Width::Qword,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        ))
        .expect("fixture must encode");
        let code = &container[V1_HEADER_SIZE..];

        let blob = emit_interpreter().expect("the interpreter must assemble");
        let first = map_executable(blob.bytes()).expect("the first mapping must succeed");
        let second = map_executable(blob.bytes()).expect("the second mapping must succeed");
        assert_ne!(first, second, "the two mappings must not share an address");

        // SAFETY: both addresses are live read-execute mappings of the bytes
        // `emit_interpreter` produced, so both hold the gate at its entry
        // offset.
        let (first_gate, second_gate) = unsafe {
            (
                gate_at(first + blob.test_entry_offset() as usize),
                gate_at(second + blob.test_entry_offset() as usize),
            )
        };

        for (lhs, rhs) in [(0u64, 0u64), (1, 2), (u64::MAX, 1), (0x0f, 1)] {
            let from_first =
                run_gate(first_gate, code, 0, lhs, rhs).expect("the first mapping must execute");
            let from_second =
                run_gate(second_gate, code, 0, lhs, rhs).expect("the second mapping must execute");

            assert_eq!(from_first, from_second);
            assert_eq!(from_first.rax, lhs.wrapping_add(rhs));
        }
    }

    #[test]
    fn production_entry_restores_the_complete_guest_context() {
        let container = encode(&Program::new(
            0,
            vec![
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rcx,
                },
                Instruction::PushReg {
                    width: Width::Qword,
                    register: Register::Rdx,
                },
                Instruction::Add(Width::Qword),
                Instruction::PopReg {
                    width: Width::Qword,
                    register: Register::Rax,
                },
                Instruction::Ret,
            ],
        ))
        .expect("fixture must encode");
        let code = &container[V1_HEADER_SIZE..];
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let mapping = map_executable(blob.bytes()).expect("the mapping must succeed");
        // SAFETY: the mapping contains the emitted test adapter at this offset.
        let gate = unsafe { gate_at(mapping + blob.test_entry_offset() as usize) };
        let initial = sentinel_state();

        let observed = run_gate_observed(gate, code, 0, initial)
            .expect("the production entry must return through the test adapter");

        assert_eq!(observed.status, status::OK);
        assert_eq!(observed.rax, initial.rcx.wrapping_add(initial.rdx));
        assert_eq!(observed.rcx, initial.rcx);
        assert_eq!(observed.rdx, initial.rdx);
        assert_eq!(observed.rbx, initial.rbx);
        assert_eq!(observed.rbp, initial.rbp);
        assert_eq!(observed.rsi, initial.rsi);
        assert_eq!(observed.rdi, initial.rdi);
        assert_eq!(observed.r8, initial.r8);
        assert_eq!(observed.r9, initial.r9);
        assert_eq!(observed.r10, initial.r10);
        assert_eq!(observed.r11, initial.r11);
        assert_eq!(observed.r12, initial.r12);
        assert_eq!(observed.r13, initial.r13);
        assert_eq!(observed.r14, initial.r14);
        assert_eq!(observed.r15, initial.r15);
        assert_eq!(observed.runtime_rflags, observed.observed_rflags);
        assert_eq!(observed.rsp_before, observed.rsp_after);
        assert_eq!(observed.rsp_before & 0xf, 0);
    }

    #[test]
    fn production_entry_restores_guest_context_on_a_trap() {
        let code = [0xff];
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let mapping = map_executable(blob.bytes()).expect("the mapping must succeed");
        // SAFETY: the mapping contains the emitted test adapter at this offset.
        let gate = unsafe { gate_at(mapping + blob.test_entry_offset() as usize) };
        let initial = sentinel_state();

        let observed = run_gate_observed(gate, &code, 0, initial)
            .expect("the production trap path must return through the adapter");

        assert_eq!(observed.status, status::UNSUPPORTED_OPCODE);
        assert_eq!(observed_state(observed), initial);
        assert_eq!(observed.runtime_rflags, initial.rflags);
        assert_eq!(observed.rsp_before, observed.rsp_after);
    }

    #[test]
    fn production_entry_receives_code_base_and_entry_pc_separately() {
        let code = [0xff, 0x01];
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let mapping = map_executable(blob.bytes()).expect("the mapping must succeed");
        // SAFETY: the mapping contains the emitted test adapter at this offset.
        let gate = unsafe { gate_at(mapping + blob.test_entry_offset() as usize) };

        let observed = run_gate_observed(gate, &code, 1, sentinel_state())
            .expect("the production entry must start at the supplied PC");

        assert_eq!(observed.status, status::OK);
    }

    #[test]
    fn production_entry_rejects_malformed_code_bounds_before_fetch() {
        let code = [0xff, 0x01];
        let start = code.as_ptr();
        let end = start.wrapping_add(code.len());
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let mapping = map_executable(blob.bytes()).expect("the mapping must succeed");
        // SAFETY: the mapping contains the emitted test adapter at this offset.
        let gate = unsafe { gate_at(mapping + blob.test_entry_offset() as usize) };

        for (base, entry, code_end, expected) in [
            (start.wrapping_add(1), start, end, status::INVALID_OPERAND),
            (
                start.wrapping_add(1),
                start.wrapping_add(1),
                start,
                status::INVALID_OPERAND,
            ),
            (start, end, end, status::TRUNCATED_BYTECODE),
            (start, end.wrapping_add(1), end, status::INVALID_OPERAND),
        ] {
            let observed = run_gate_observed_bounds(gate, base, entry, code_end, sentinel_state())
                .expect("malformed bounds must return through the adapter");

            assert_eq!(observed.status, expected);
        }
    }
}
