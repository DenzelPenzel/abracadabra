//! Real processor exceptions on an ordinary Win64 thread stack, not the blob's test adapter

use super::*;

use iced_x86::code_asm::*;
use std::mem::offset_of;

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vmp_vm::bytecode::{
    decode, encode, Instruction as VmInstruction, Program, Register as VmRegister, Width,
};
use windows_sys::Win32::Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_NOACCESS};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

const TF: u32 = 1 << 8;
const DF: u32 = 1 << 10;
const AC: u32 = 1 << 18;
const CONTINUE_EXECUTION: i32 = -1;
const CONTINUE_SEARCH: i32 = 0;
const CHILD_ENV: &str = "VMP_REAL_EXCEPTION_CHILD";
const MAX_STEPS: usize = 1024;
static SERIAL: Mutex<()> = Mutex::new(());
static ACTIVE: AtomicPtr<ProbeState> = AtomicPtr::new(null_mut());
static OWNER_THREAD: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Default)]
struct Outcome {
    caller_rsp: u64,
    caller_rip: u64,
    nonvolatiles: [u64; 8],
    result: u64,
    status: u64,
    flags: u64,
    returned_rsp: u64,
    completed: u64,
    returned_flags: u64,
    guest_flags: u64,
}

#[repr(C)]
struct ProbeInput {
    code: u64,
    code_end: u64,
    entry: u64,
    flags: u64,
    outcome: *mut Outcome,
}

struct ProbeState {
    base: u64,
    start: u64,
    end: u64,
    fetch: u64,
    code: u64,
    ac: bool,
    outcome: *mut Outcome,
    failures: u32,
    first_bad_rip: u64,
    steps: usize,
    av_count: usize,
    continuation_count: usize,
    seen: [u64; MAX_STEPS],
    exception_flags: u32,
    saved_guest_flags: u64,
}

// This allocation has no runtime function table: the VEH never walks the assembly wrapper
struct Allocation(NonNull<c_void>);

impl Allocation {
    #[allow(unsafe_code)]
    fn new(bytes: &[u8], protection: u32) -> Self {
        assert!(!bytes.is_empty());
        // SAFETY: This private allocation is initialized while RW, then owned until after execution
        unsafe {
            let allocation = Self(
                NonNull::new(VirtualAlloc(
                    null(),
                    bytes.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                ))
                .expect("allocate exception fixture"),
            );
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                allocation.0.as_ptr().cast(),
                bytes.len(),
            );
            allocation.protect(bytes.len(), protection);
            assert_ne!(
                FlushInstructionCache(GetCurrentProcess(), allocation.0.as_ptr(), bytes.len()),
                0
            );
            allocation
        }
    }

    #[allow(unsafe_code)]
    fn protect(&self, len: usize, protection: u32) {
        let mut old = 0;
        // SAFETY: The range is inside this live allocation and is not executing during transition
        assert_ne!(
            unsafe { VirtualProtect(self.0.as_ptr(), len, protection, &mut old) },
            0
        );
    }

    fn address(&self) -> u64 {
        self.0.as_ptr() as u64
    }
}

impl Drop for Allocation {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: The handler and generated invocation have ended before releasing this owner
        assert_ne!(unsafe { VirtualFree(self.0.as_ptr(), 0, MEM_RELEASE) }, 0);
    }
}

struct Handler(NonNull<c_void>);

impl Handler {
    #[allow(unsafe_code)]
    fn install(state: &mut ProbeState) -> Self {
        // SAFETY: The boxed state and all pointees outlive the handler guard under SERIAL
        let handler = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };
        let guard = Self(NonNull::new(handler).expect("install vectored exception handler"));
        ACTIVE.store(state, Ordering::SeqCst);
        // SAFETY: Querying our thread ID requires no pointers and publishes no mutable state
        OWNER_THREAD.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);
        guard
    }
}

impl Drop for Handler {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        OWNER_THREAD.store(0, Ordering::SeqCst);
        ACTIVE.store(null_mut(), Ordering::SeqCst);
        // SAFETY: This is our live registration, removed before state or executable owners drop
        assert_ne!(
            unsafe { RemoveVectoredExceptionHandler(self.0.as_ptr()) },
            0
        );
    }
}

fn nonvolatiles(context: &CONTEXT) -> [u64; 8] {
    [
        context.Rbx,
        context.Rbp,
        context.Rsi,
        context.Rdi,
        context.R12,
        context.R13,
        context.R14,
        context.R15,
    ]
}

fn fail(state: &mut ProbeState, bit: u32, rip: u64) {
    if state.failures == 0 {
        state.first_bad_rip = rip;
    }
    state.failures |= bit;
}

// Failure recovery uses only the independently recorded generated caller, never a Rust frame
fn recover(context: &mut CONTEXT, outcome: &Outcome) {
    context.Rip = outcome.caller_rip;
    context.Rsp = outcome.caller_rsp;
    context.Rbx = CALLER_VALUES[0];
    context.Rbp = CALLER_VALUES[1];
    context.Rsi = CALLER_VALUES[2];
    context.Rdi = CALLER_VALUES[3];
    context.R12 = CALLER_VALUES[4];
    context.R13 = CALLER_VALUES[5];
    context.R14 = CALLER_VALUES[6];
    context.R15 = CALLER_VALUES[7];
    context.EFlags &= !(TF | AC | DF);
}

#[allow(unsafe_code)]
unsafe extern "system" fn exception_handler(pointers: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: Reject other threads before even reading the private state's address
    if unsafe { GetCurrentThreadId() } != OWNER_THREAD.load(Ordering::SeqCst) {
        return CONTINUE_SEARCH;
    }
    let state = ACTIVE.load(Ordering::SeqCst);
    // SAFETY: ACTIVE is owned by the serialized invocation; other threads do not dereference it
    unsafe {
        if state.is_null() || pointers.is_null() {
            return CONTINUE_SEARCH;
        }
        let state = &mut *state;
        let pointers = &*pointers;
        if pointers.ContextRecord.is_null() || pointers.ExceptionRecord.is_null() {
            return CONTINUE_SEARCH;
        }
        let context = &mut *pointers.ContextRecord;
        let exception = &*pointers.ExceptionRecord;
        let outcome = &*state.outcome;
        let single_step = exception.ExceptionCode == EXCEPTION_SINGLE_STEP;
        let access_violation = exception.ExceptionCode == EXCEPTION_ACCESS_VIOLATION;

        if state.steps == 0 {
            state.exception_flags = context.EFlags;
        }
        if !single_step && !access_violation {
            return CONTINUE_SEARCH;
        }
        if context.Rip == outcome.caller_rip && single_step && !state.ac {
            state.continuation_count += 1;
            if context.Rsp != outcome.caller_rsp || nonvolatiles(context) != CALLER_VALUES {
                fail(state, 1, context.Rip);
            }
            context.EFlags &= !(TF | AC | DF);
            return CONTINUE_EXECUTION;
        }
        if context.Rip < state.start || context.Rip >= state.end {
            return CONTINUE_SEARCH;
        }
        let rip = context.Rip;
        if exception.ExceptionAddress as u64 != rip {
            fail(state, 2, rip);
        }
        if state.ac {
            state.av_count += 1;
            state.exception_flags = context.EFlags;
            if !access_violation
                || rip != state.fetch
                || context.EFlags & AC != 0
                || exception.NumberParameters != 2
                || exception.ExceptionInformation[0] != 0
                || exception.ExceptionInformation[1] as u64 != state.code
                || context.R13 != state.code
            {
                fail(state, 4, rip);
            }
            // The first fetch has the complete 128-byte snapshot below the independent caller
            if rip == state.fetch && context.R15 == outcome.caller_rsp - 136 {
                state.saved_guest_flags = std::ptr::read(context.R15 as *const u64);
                if state.saved_guest_flags & u64::from(AC) == 0 {
                    fail(state, 128, rip);
                }
            } else {
                fail(state, 128, rip);
            }
        // Windows delivers #DB with TF cleared in CONTEXT; the code and observed RIP prove stepping
        } else if !single_step {
            fail(state, 8, rip);
        }
        if let Some(slot) = state.seen.get_mut(state.steps) {
            *slot = rip;
            state.steps += 1;
        } else {
            fail(state, 16, rip);
            recover(context, outcome);
            return CONTINUE_EXECUTION;
        }
        let mut copy = *context;
        let mut base = 0;
        let entry = RtlLookupFunctionEntry(rip, &mut base, null_mut());
        if entry.is_null() || base != state.base {
            fail(state, 32, rip);
            recover(context, outcome);
            return CONTINUE_EXECUTION;
        }
        let mut handler_data = null_mut();
        let mut establisher = 0;
        let language_handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,
            base,
            rip,
            entry,
            &mut copy,
            &mut handler_data,
            &mut establisher,
            null_mut(),
        );

        if language_handler.is_some()
            || copy.Rip != outcome.caller_rip
            || copy.Rsp != outcome.caller_rsp
            || nonvolatiles(&copy) != CALLER_VALUES
        {
            fail(state, 64, rip);
        }
        if state.ac {
            if state.failures == 0 {
                // Only assembly frames are skipped; no Rust local or destructor is bypassed
                copy.EFlags &= !(TF | AC | DF);
                *context = copy;
            } else {
                recover(context, outcome);
            }
        } else {
            // Keep observing actual execution, including transient stack pushes and canonical RET
            context.EFlags |= TF;
        }
        CONTINUE_EXECUTION
    }
}

fn wrapper() -> Vec<u8> {
    let mut asm = CodeAssembler::new(64).expect("Win64 assembler");
    let mut continuation = asm.create_label();
    let regs = [rbx, rbp, rsi, rdi, r12, r13, r14, r15];
    for reg in regs {
        asm.push(reg).expect("save host nonvolatile");
    }
    // Eight pushes plus 56 bytes leave the normal Win64 caller stack 16-byte aligned
    asm.sub(rsp, 56).expect("reserve production metadata");
    asm.mov(r10, rcx).expect("retain input");
    asm.mov(r11, qword_ptr(r10 + offset_of!(ProbeInput, outcome) as i32))
        .expect("outcome");
    asm.mov(qword_ptr(rsp + 40), r11).expect("retain outcome");
    asm.mov(rax, qword_ptr(r10 + offset_of!(ProbeInput, entry) as i32))
        .expect("entry");
    asm.mov(qword_ptr(rsp + 48), rax).expect("retain entry");
    asm.mov(rax, qword_ptr(r10 + offset_of!(ProbeInput, code) as i32))
        .expect("code");
    asm.mov(qword_ptr(rsp), rax).expect("code base");
    asm.mov(qword_ptr(rsp + 8), rax).expect("entry PC");
    asm.mov(
        rax,
        qword_ptr(r10 + offset_of!(ProbeInput, code_end) as i32),
    )
    .expect("code end");
    asm.mov(qword_ptr(rsp + 16), rax).expect("code end slot");
    asm.mov(qword_ptr(rsp + 24), -1i32)
        .expect("unpublished status");
    asm.mov(qword_ptr(rsp + 32), 0i32)
        .expect("runtime flags slot");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, caller_rsp) as i32), rsp)
        .expect("independent caller RSP");
    asm.lea(rax, ptr(continuation))
        .expect("independent continuation");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, caller_rip) as i32), rax)
        .expect("independent caller RIP");
    for (reg, value) in regs.into_iter().zip(CALLER_VALUES) {
        asm.mov(reg, value).expect("seed nonvolatile");
    }
    asm.mov(rcx, 19u64).expect("lhs");
    asm.mov(rdx, 23u64).expect("rhs");
    asm.push(qword_ptr(r10 + offset_of!(ProbeInput, flags) as i32))
        .expect("test flags");
    asm.popfq().expect("activate TF or AC");
    asm.call(qword_ptr(rsp + 48))
        .expect("immediately enter production");
    asm.set_label(&mut continuation).expect("continuation");
    asm.pushfq().expect("physical return flags");
    asm.pop(r10).expect("retain return flags");
    asm.push(r10).expect("temporary safe flags");
    asm.and(qword_ptr(rsp), !((TF | AC | DF) as i32))
        .expect("clear dangerous live flags before Rust");
    asm.popfq().expect("safe live flags");
    asm.mov(r11, qword_ptr(rsp + 40))
        .expect("reload independent outcome");
    asm.mov(
        qword_ptr(r11 + offset_of!(Outcome, returned_flags) as i32),
        r10,
    )
    .expect("record physical return flags");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, result) as i32), rax)
        .expect("physical result");
    for (index, reg) in regs.into_iter().enumerate() {
        asm.mov(
            qword_ptr(r11 + (offset_of!(Outcome, nonvolatiles) + index * 8) as i32),
            reg,
        )
        .expect("physical restored nonvolatile");
    }
    asm.mov(
        qword_ptr(r11 + offset_of!(Outcome, returned_rsp) as i32),
        rsp,
    )
    .expect("physical returned RSP");
    asm.mov(rax, qword_ptr(rsp + 24)).expect("published status");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, status) as i32), rax)
        .expect("record status");
    asm.mov(rax, qword_ptr(rsp + 32))
        .expect("published guest flags");
    asm.mov(
        qword_ptr(r11 + offset_of!(Outcome, guest_flags) as i32),
        rax,
    )
    .expect("record guest flags");
    asm.pushfq().expect("safe continuation flags");
    asm.pop(rax).expect("capture flags");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, flags) as i32), rax)
        .expect("record flags");
    asm.mov(qword_ptr(r11 + offset_of!(Outcome, completed) as i32), 1i32)
        .expect("completion");
    asm.add(rsp, 56).expect("release metadata");
    for reg in regs.into_iter().rev() {
        asm.pop(reg).expect("restore host nonvolatile");
    }
    asm.ret().expect("return to Rust with safe flags");
    asm.assemble(0)
        .expect("assemble independent exception wrapper")
}

fn validated_add() -> Vec<u8> {
    let container = encode(&Program::new(
        0,
        vec![
            VmInstruction::PushReg {
                width: Width::Qword,
                register: VmRegister::Rcx,
            },
            VmInstruction::PushReg {
                width: Width::Qword,
                register: VmRegister::Rdx,
            },
            VmInstruction::Add(Width::Qword),
            VmInstruction::PopReg {
                width: Width::Qword,
                register: VmRegister::Rax,
            },
            VmInstruction::Ret,
        ],
    ))
    .expect("encode ADD fixture");
    decode(&container).expect("validate complete ADD container before execution");
    assert_eq!(
        &container[16..],
        &[0x11, 8, 1, 0x11, 8, 2, 0x20, 8, 0x12, 8, 0, 1]
    );
    container[16..].to_vec()
}

#[allow(unsafe_code)]
fn run_probe(ac: bool, normal: bool) {
    let _serial = SERIAL.lock().expect("serialize VEH owner");
    let blob = emit_interpreter().expect("emit production runtime");
    let mapping = MappedImage::new(&blob);
    // Missing registration fails safely before any dangerous flags or exception is enabled
    mapping.lookup(blob.production_entry_offset(), 1);
    let instructions = production_instructions(&blob);
    let fetch = instructions
        .iter()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Movzx
                && instruction.op0_register() == Register::EAX
                && instruction.memory_base() == Register::R13
                && instruction.memory_displacement64() == 0
        })
        .expect("unchanged MOVZX EAX,byte ptr [R13] opcode fetch");
    assert_eq!(
        &blob.bytes()[fetch.ip() as usize..fetch.next_ip() as usize],
        &[0x41, 0x0f, 0xb6, 0x45, 0]
    );
    let code_bytes = validated_add();
    let code = Allocation::new(&code_bytes, PAGE_READWRITE);
    // SAFETY: The bytes are still readable here, before the test deliberately revokes access
    assert_eq!(
        unsafe { std::slice::from_raw_parts(code.0.as_ptr().cast::<u8>(), code_bytes.len()) },
        code_bytes
    );
    if ac && !normal {
        code.protect(code_bytes.len(), PAGE_NOACCESS);
        let mut information = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQuery observes the address without dereferencing its inaccessible bytes
        assert_ne!(
            unsafe {
                VirtualQuery(
                    code.0.as_ptr(),
                    &mut information,
                    std::mem::size_of_val(&information),
                )
            },
            0
        );
        assert_eq!(information.Protect, PAGE_NOACCESS);
    }
    let wrapper = Allocation::new(&wrapper(), PAGE_EXECUTE_READ);
    let mut outcome = Box::<Outcome>::default();
    let outcome_pointer = &mut *outcome as *mut Outcome;
    let mut state = Box::new(ProbeState {
        base: mapping.address(0),
        start: mapping.address(blob.production_entry_offset()),
        end: mapping.address(blob.unwind_plan.functions[1].range.end()),
        fetch: mapping.address(fetch.ip() as u32),
        code: code.address(),
        ac,
        outcome: outcome_pointer,
        failures: 0,
        first_bad_rip: 0,
        steps: 0,
        av_count: 0,
        continuation_count: 0,
        seen: [0; MAX_STEPS],
        exception_flags: 0,
        saved_guest_flags: 0,
    });
    let input = ProbeInput {
        code: code.address(),
        code_end: code.address() + code_bytes.len() as u64,
        entry: state.start,
        flags: u64::from(0x202 | if ac { AC } else { TF }),
        outcome: outcome_pointer,
    };
    let handler = Handler::install(&mut state);

    // SAFETY: This emitted Win64 wrapper preserves the host ABI and returns with TF/AC/DF clear
    // The VEH and every referenced allocation remain live, and only generated frames are skipped
    unsafe {
        let invoke: unsafe extern "win64" fn(*const ProbeInput) =
            std::mem::transmute(wrapper.address());
        invoke(&input);
    }
    drop(handler);
    assert_eq!(
        state.failures,
        0,
        "VEH failure bits, first image offset {:#x}, first saved flags {:#x}",
        state.first_bad_rip.wrapping_sub(state.base),
        state.exception_flags
    );
    assert_eq!(outcome.completed, 1);
    assert_eq!(
        outcome.caller_rsp & 15,
        0,
        "ordinary aligned Win64 caller stack"
    );
    assert_eq!(outcome.returned_rsp, outcome.caller_rsp);
    assert_eq!(
        outcome.nonvolatiles, CALLER_VALUES,
        "physical wrapper continuation state"
    );
    assert_eq!(
        outcome.flags & u64::from(TF | AC | DF),
        0,
        "safe Rust ABI return"
    );
    if normal {
        assert_eq!(state.steps, 0);
        assert_eq!(state.av_count, 0);
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.result, 42);
        assert_ne!(outcome.guest_flags & u64::from(AC), 0);
        assert_ne!(outcome.returned_flags & u64::from(AC), 0);
    } else if ac {
        assert_eq!(state.av_count, 1);
        assert_eq!(state.steps, 1);
        assert_eq!(state.exception_flags & AC, 0);
        assert_ne!(state.saved_guest_flags & u64::from(AC), 0);
        assert_eq!(
            outcome.status,
            u64::MAX,
            "fault recovery must not masquerade as normal RET"
        );
    } else {
        assert_eq!(state.av_count, 0);
        assert_eq!(
            state.continuation_count, 1,
            "real RET reached wrapper continuation"
        );
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.result, 42);
        let observed = &state.seen[..state.steps];
        // Require every partial prologue and canonical epilogue boundary, not just one #DB
        for (relative, _) in PROLOGUE_STATES {
            assert!(
                observed.contains(&mapping.address(blob.production_entry_offset() + relative)),
                "missing prologue step {relative}"
            );
        }
        for instruction in &instructions[epilogue_index(&instructions)..] {
            assert!(
                observed.contains(&mapping.address(instruction.ip() as u32)),
                "missing epilogue step {instruction}"
            );
        }
        let add = instructions
            .iter()
            .position(|instruction| {
                instruction.mnemonic() == Mnemonic::Add
                    && instruction.memory_base() == Register::R14
                    && instruction.op1_register() == Register::RAX
            })
            .expect("physical ADD handler");
        assert_eq!(instructions[add + 1].mnemonic(), Mnemonic::Pushfq);
        assert_eq!(instructions[add + 2].mnemonic(), Mnemonic::Pop);
        for instruction in &instructions[add..=add + 3] {
            assert!(
                observed.contains(&mapping.address(instruction.ip() as u32)),
                "missing ADD/transient flags step {instruction}"
            );
        }
    }
    eprintln!(
        "real exception proof: ac={ac}, steps={}, av={}, continuation={}, first saved flags={:#x}",
        state.steps, state.av_count, state.continuation_count, state.exception_flags
    );
}

fn isolated(name: &str, ac: bool, normal: bool) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        run_probe(ac, normal);
        return;
    }
    let exact = format!("unwind::windows_tests::exceptions::{name}");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated real exception probe");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("poll exception child") {
            let output = child
                .wait_with_output()
                .expect("collect exception child output");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{stdout}{stderr}");
            assert!(status.success(), "real exception child failed: {status}");
            assert!(
                stdout.contains("1 passed; 0 failed"),
                "child must run exactly one test"
            );
            assert!(
                stderr.contains("real exception proof:"),
                "child must reach proof assertions"
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out exception child");
            child.wait().expect("reap exception child");
            panic!("real exception child exceeded 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn active_tf_steps_real_production_frame_through_add_and_ret() {
    isolated(
        "active_tf_steps_real_production_frame_through_add_and_ret",
        false,
        false,
    );
}

#[test]
fn active_ac_access_violation_unwinds_real_opcode_fetch() {
    isolated(
        "active_ac_access_violation_unwinds_real_opcode_fetch",
        true,
        false,
    );
}

#[test]
fn active_ac_normal_add_preserves_guest_and_physical_return_flags() {
    isolated(
        "active_ac_normal_add_preserves_guest_and_physical_return_flags",
        true,
        true,
    );
}
