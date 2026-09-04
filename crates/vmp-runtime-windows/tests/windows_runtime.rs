#![cfg(all(windows, target_arch = "x86_64"))]
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::process::Command;
use std::ptr;

use vmp_runtime_windows::{
    emit_interpreter, RuntimeBlob, MAX_PRODUCTION_ENTRY_STACK_USAGE,
    MAX_PROTECTED_FUNCTION_STACK_USAGE,
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_MASK: u32 = 0x10 | 0x20 | 0x40 | 0x80;
const PROCESS_DEP_POLICY: u32 = 0;
const DEP_ENABLE: u32 = 1;
const DF: u64 = 1 << 10;
const IF: u64 = 1 << 9;
const TF: u64 = 1 << 8;
const AC: u64 = 1 << 18;
const ADD_DEFINED_FLAGS: u64 = 0x8d5;
const RET_PRESERVED_FLAGS: u64 = ADD_DEFINED_FLAGS | DF | IF | TF | AC;
const STACK_FILL: u8 = 0xa5;
const STACK_CANARY: u64 = 0xa5a5_a5a5_a5a5_a5a5;
const PRODUCTION_ENTRY_OUTER_FRAME_BYTES: usize = 48;
const STACK_LOW_WATERMARK_OFFSET: usize = 8;
const LOW_CANDIDATES: [usize; 3] = [0x1000_0000, 0x2000_0000, 0x3000_0000];
const HIGH_CANDIDATES: [usize; 3] = [0x1_0000_0000, 0x2_0000_0000, 0x4_0000_0000];

#[repr(C, align(32))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct CpuState {
    gpr: [u64; 15],
    rflags: u64,
    ymm6_15: [[u8; 32]; 10],
    mxcsr: u32,
    x87_control: u16,
    reserved: u16,
    valid_xstate: u32,
    padding: [u8; 20],
}

impl CpuState {
    fn sentinel(direction_flag: bool) -> Self {
        let mut ymm6_15 = [[0_u8; 32]; 10];
        for (register, bytes) in ymm6_15.iter_mut().enumerate() {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = ((register * 37 + index * 11 + 1) & 0xff) as u8;
            }
        }

        Self {
            gpr: [
                0x0101_0101_0101_0101,
                1,
                2,
                0x0303_0303_0303_0303,
                0x0404_0404_0404_0404,
                0x0505_0505_0505_0505,
                0x0606_0606_0606_0606,
                0x0808_0808_0808_0808,
                0x0909_0909_0909_0909,
                0x1010_1010_1010_1010,
                0x1111_1111_1111_1111,
                0x1212_1212_1212_1212,
                0x1313_1313_1313_1313,
                0x1414_1414_1414_1414,
                0x1515_1515_1515_1515,
            ],
            rflags: IF | ADD_DEFINED_FLAGS | if direction_flag { DF } else { 0 },
            ymm6_15,
            // All exception masks stay set; only control bits vary from reset state
            mxcsr: 0x5f80,
            // All x87 exceptions stay masked while the rounding mode is non-default
            x87_control: 0x077f,
            reserved: 0,
            valid_xstate: u32::from(std::is_x86_feature_detected!("avx")),
            padding: [0; 20],
        }
    }

    fn host_sentinel() -> Self {
        let mut state = Self::sentinel(false);
        for value in &mut state.gpr {
            *value = !*value;
        }
        for register in &mut state.ymm6_15 {
            for byte in register {
                *byte = !*byte;
            }
        }
        state.mxcsr = 0x3f80;
        state.x87_control = 0x0b7f;
        state
    }
}

#[repr(C, align(32))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HarnessOutput {
    state: CpuState,
    entry_rsp: u64,
    continuation_rsp: u64,
    status: u64,
    runtime_rflags: u64,
    abi_rflags: u64,
    canary_before: u64,
    canary_after: u64,
    low_watermark_after: u64,
    continuation_reached: u32,
    padding: [u8; 28],
}

impl Default for HarnessOutput {
    fn default() -> Self {
        Self {
            state: CpuState::sentinel(false),
            entry_rsp: 0,
            continuation_rsp: 0,
            status: u64::MAX,
            runtime_rflags: u64::MAX,
            abi_rflags: 0,
            canary_before: 0,
            canary_after: 0,
            low_watermark_after: STACK_CANARY,
            continuation_reached: 0,
            padding: [0; 28],
        }
    }
}

#[repr(C)]
struct HarnessArgs {
    production_entry: *const u8,
    code_base: *const u8,
    entry_pc: *const u8,
    code_end: *const u8,
    seed: *const CpuState,
    output: *mut HarnessOutput,
    writable_stack_page: *mut u8,
    page_size: usize,
    host_seed: *const CpuState,
}

#[repr(C, align(16))]
#[derive(Debug, Default)]
struct AbiOutput {
    gpr: [u64; 8],
    xmm6_15: [[u8; 16]; 10],
    mxcsr: u32,
    x87_control: u16,
    padding0: [u8; 2],
    rsp_before: u64,
    rsp_after: u64,
    probe_result: u32,
    padding1: [u8; 4],
}

#[repr(C)]
#[derive(Default)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: *mut c_void,
    maximum_application_address: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

#[repr(C)]
#[derive(Default)]
struct DepPolicy {
    flags: u32,
    permanent: u8,
    padding: [u8; 3],
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
    fn VirtualProtect(
        address: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    fn VirtualQuery(
        address: *const c_void,
        information: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessMitigationPolicy(
        process: *mut c_void,
        policy: u32,
        buffer: *mut c_void,
        length: usize,
    ) -> i32;
    fn GetSystemInfo(system_info: *mut SystemInfo);
}

extern "C" {
    fn vmp_runtime_production_probe(args: *const HarnessArgs) -> u32;
    fn vmp_runtime_probe_abi(args: *const HarnessArgs, output: *mut AbiOutput) -> u32;
    static vmp_runtime_fastfail_begin: u8;
    static vmp_runtime_fastfail_end: u8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    Low,
    High,
}

struct Mapping {
    base: *mut u8,
}

impl Mapping {
    fn executable(blob: &RuntimeBlob, class: AddressClass) -> Self {
        let candidates = match class {
            AddressClass::Low => LOW_CANDIDATES,
            AddressClass::High => HIGH_CANDIDATES,
        };
        let mut base: *mut u8 = ptr::null_mut();
        for candidate in candidates {
            // SAFETY: each candidate is allocation-granularity aligned and the
            // returned region remains uniquely owned by this value
            let mapped = unsafe {
                VirtualAlloc(
                    candidate as *mut c_void,
                    blob.bytes().len(),
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
            if !mapped.is_null() {
                assert_eq!(mapped as usize, candidate);
                base = mapped.cast();
                break;
            }
        }
        assert!(
            !base.is_null(),
            "no requested {class:?} address was available"
        );
        match class {
            AddressClass::Low => assert!((base as usize) < 0x1_0000_0000),
            AddressClass::High => assert!((base as usize) >= 0x1_0000_0000),
        }
        assert_eq!(page_protection(base), PAGE_READWRITE);

        // SAFETY: the allocation is writable and at least blob.bytes().len()
        // bytes long, and the slices do not overlap
        unsafe {
            ptr::copy_nonoverlapping(blob.bytes().as_ptr(), base, blob.bytes().len());
        }
        let mut old_protect = 0;
        // SAFETY: the region is live and uniquely owned by this value
        assert_ne!(
            unsafe {
                VirtualProtect(
                    base.cast(),
                    blob.bytes().len(),
                    PAGE_EXECUTE_READ,
                    &mut old_protect,
                )
            },
            0
        );
        // SAFETY: the process handle is pseudo-handle valid for this call and
        // the mapped range is live
        assert_ne!(
            unsafe { FlushInstructionCache(GetCurrentProcess(), base.cast(), blob.bytes().len(),) },
            0
        );
        assert_eq!(page_protection(base), PAGE_EXECUTE_READ);

        Self { base }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: base denotes this value's complete VirtualAlloc allocation
        let released = unsafe { VirtualFree(self.base.cast(), 0, MEM_RELEASE) };
        assert_ne!(released, 0);
    }
}

struct ProbeStack {
    allocation: *mut u8,
    writable_page: *mut u8,
    page_size: usize,
}

impl ProbeStack {
    fn new() -> Self {
        let page_size = system_page_size();
        // SAFETY: null requests an arbitrary fresh allocation
        let allocation = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                page_size * 2,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        }
        .cast::<u8>();
        assert!(!allocation.is_null());
        let mut old_protect = 0;
        // SAFETY: the first page is a live page in this allocation
        assert_ne!(
            unsafe {
                VirtualProtect(
                    allocation.cast(),
                    page_size,
                    PAGE_NOACCESS,
                    &mut old_protect,
                )
            },
            0
        );
        // SAFETY: the second page follows the first within the allocation
        let writable_page = unsafe { allocation.add(page_size) };
        assert_eq!(page_protection(writable_page), PAGE_READWRITE);
        // SAFETY: 280 bytes fit in one writable system page
        unsafe { ptr::write_bytes(writable_page, STACK_FILL, 280) };

        Self {
            allocation,
            writable_page,
            page_size,
        }
    }
}

impl Drop for ProbeStack {
    fn drop(&mut self) {
        // SAFETY: allocation denotes this value's complete VirtualAlloc region
        let released = unsafe { VirtualFree(self.allocation.cast(), 0, MEM_RELEASE) };
        assert_ne!(released, 0);
    }
}

fn system_page_size() -> usize {
    let mut information = SystemInfo::default();
    // SAFETY: the pointer references a writable record of the required layout
    unsafe { GetSystemInfo(&mut information) };
    usize::try_from(information.page_size).expect("the system page size must fit usize")
}

fn page_protection(address: *const u8) -> u32 {
    let mut information = MemoryBasicInformation::default();
    // SAFETY: information is writable and address is queried without dereference
    let written = unsafe {
        VirtualQuery(
            address.cast(),
            &mut information,
            size_of::<MemoryBasicInformation>(),
        )
    };
    assert_eq!(written, size_of::<MemoryBasicInformation>());
    information.protect
}

fn assert_dep_enabled() {
    let mut policy = DepPolicy::default();
    // SAFETY: the pseudo-handle and writable policy record satisfy the API
    let succeeded = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            PROCESS_DEP_POLICY,
            ptr::addr_of_mut!(policy).cast(),
            size_of::<DepPolicy>(),
        )
    };
    assert_ne!(succeeded, 0);
    assert_ne!(policy.flags & DEP_ENABLE, 0, "DEP must be enabled");
}

fn run_probe(blob: &RuntimeBlob, mapping: &Mapping, code: &[u8], seed: &CpuState) -> HarnessOutput {
    assert_eq!(page_protection(code.as_ptr()) & PAGE_EXECUTE_MASK, 0);
    let stack = ProbeStack::new();
    let mut output = HarnessOutput::default();
    let args = HarnessArgs {
        // SAFETY: the checked blob offset is within the live executable mapping
        production_entry: unsafe { mapping.base.add(blob.production_entry_offset() as usize) },
        code_base: code.as_ptr(),
        entry_pc: code.as_ptr(),
        code_end: code.as_ptr().wrapping_add(code.len()),
        seed,
        output: &mut output,
        writable_stack_page: stack.writable_page,
        page_size: stack.page_size,
        host_seed: seed,
    };

    // SAFETY: the linked MASM routine consumes the exact repr(C) layouts above,
    // and every pointed-to allocation remains live for the complete call
    let result = unsafe { vmp_runtime_production_probe(&args) };
    assert_eq!(result, 0);
    let entry_rsp = usize::try_from(output.entry_rsp).expect("entry RSP must fit usize");
    let low_watermark = (stack.writable_page as usize)
        .checked_add(STACK_LOW_WATERMARK_OFFSET)
        .expect("the low-watermark address must fit usize");
    assert_eq!(
        entry_rsp.checked_sub(low_watermark),
        Some(MAX_PRODUCTION_ENTRY_STACK_USAGE)
    );
    let protected_entry_rsp = entry_rsp
        .checked_add(PRODUCTION_ENTRY_OUTER_FRAME_BYTES)
        .expect("the protected-function entry RSP must fit usize");
    assert_eq!(
        protected_entry_rsp.checked_sub(low_watermark),
        Some(MAX_PROTECTED_FUNCTION_STACK_USAGE)
    );
    output
}

fn assert_fastfail_subcode_encoding() {
    let begin = ptr::addr_of!(vmp_runtime_fastfail_begin);
    let end = ptr::addr_of!(vmp_runtime_fastfail_end);
    // SAFETY: the two labels delimit one contiguous instruction sequence
    let length = unsafe { end.offset_from(begin) };
    assert_eq!(length, 7);
    let length = usize::try_from(length).expect("the fast-fail sequence length must fit usize");
    // SAFETY: the linked labels delimit exactly `length` readable bytes
    let bytes = unsafe { std::slice::from_raw_parts(begin, length) };
    assert_eq!(bytes, [0xb9, 7, 0, 0, 0, 0xcd, 0x29]);
}

fn assert_control_state(seed: &CpuState, output: &HarnessOutput) {
    assert_eq!(output.runtime_rflags & DF, seed.rflags & DF);
    assert_eq!(output.state.rflags & DF, 0);
    assert_eq!(output.state.rflags & IF, seed.rflags & IF);
    assert_eq!(output.state.rflags & TF, 0);
    assert_eq!(output.state.rflags & AC, 0);
    assert_eq!(output.runtime_rflags & !DF, output.state.rflags & !DF);
    assert_eq!(output.abi_rflags & DF, 0);
    assert_eq!(output.abi_rflags & IF, seed.rflags & IF);
    assert_eq!(output.abi_rflags & TF, 0);
    assert_eq!(output.abi_rflags & AC, 0);
    assert_eq!(output.state.mxcsr & 0xffc0, seed.mxcsr & 0xffc0);
    assert_eq!(output.state.x87_control, seed.x87_control);
    assert_eq!(output.state.valid_xstate, seed.valid_xstate);
    for (observed, expected) in output.state.ymm6_15.iter().zip(&seed.ymm6_15) {
        let compared = if seed.valid_xstate == 0 { 16 } else { 32 };
        assert_eq!(&observed[..compared], &expected[..compared]);
    }
}

#[test]
fn masm_layout_matches_the_rust_records() {
    assert_eq!(size_of::<CpuState>(), 480);
    assert_eq!(offset_of!(CpuState, rflags), 120);
    assert_eq!(offset_of!(CpuState, ymm6_15), 128);
    assert_eq!(offset_of!(CpuState, mxcsr), 448);
    assert_eq!(offset_of!(CpuState, x87_control), 452);
    assert_eq!(offset_of!(CpuState, valid_xstate), 456);
    assert_eq!(size_of::<HarnessOutput>(), 576);
    assert_eq!(offset_of!(HarnessOutput, entry_rsp), 480);
    assert_eq!(offset_of!(HarnessOutput, continuation_reached), 544);
    assert_eq!(size_of::<HarnessArgs>(), 72);
    assert_eq!(size_of::<AbiOutput>(), 256);
    assert_eq!(offset_of!(AbiOutput, rsp_before), 232);
    assert_eq!(offset_of!(AbiOutput, probe_result), 248);
}

#[test]
fn production_probe_restores_its_win64_callers_nonvolatile_state() {
    let blob = emit_interpreter().expect("the runtime must assemble");
    let mapping = Mapping::executable(&blob, AddressClass::High);
    let code = [0x01];
    let stack = ProbeStack::new();
    let guest_seed = CpuState::sentinel(true);
    let host_seed = CpuState::host_sentinel();
    let mut output = HarnessOutput::default();
    let mut abi = AbiOutput::default();
    let args = HarnessArgs {
        // SAFETY: the checked blob offset is within the live executable mapping
        production_entry: unsafe { mapping.base.add(blob.production_entry_offset() as usize) },
        code_base: code.as_ptr(),
        entry_pc: code.as_ptr(),
        code_end: code.as_ptr().wrapping_add(code.len()),
        seed: &guest_seed,
        output: &mut output,
        writable_stack_page: stack.writable_page,
        page_size: stack.page_size,
        host_seed: &host_seed,
    };

    // SAFETY: both MASM records have the exact repr(C) layouts asserted above
    let result = unsafe { vmp_runtime_probe_abi(&args, &mut abi) };

    assert_eq!(result, 0);
    assert_eq!(abi.probe_result, 0);
    assert_eq!(abi.rsp_after, abi.rsp_before);
    assert_eq!(
        abi.gpr,
        [
            host_seed.gpr[3],
            host_seed.gpr[4],
            host_seed.gpr[5],
            host_seed.gpr[6],
            host_seed.gpr[11],
            host_seed.gpr[12],
            host_seed.gpr[13],
            host_seed.gpr[14],
        ]
    );
    for (observed, expected) in abi.xmm6_15.iter().zip(&host_seed.ymm6_15) {
        assert_eq!(observed, &expected[..16]);
    }
    assert_eq!(abi.mxcsr, host_seed.mxcsr);
    assert_eq!(abi.x87_control, host_seed.x87_control);
    assert_eq!(output.continuation_reached, 1);
}

#[test]
fn production_entry_preserves_state_at_low_and_high_addresses() {
    assert_dep_enabled();
    let blob = emit_interpreter().expect("the runtime must assemble");
    let code = [0x01];

    for direction_flag in [false, true] {
        let seed = CpuState::sentinel(direction_flag);
        let low = Mapping::executable(&blob, AddressClass::Low);
        let high = Mapping::executable(&blob, AddressClass::High);
        let low_output = run_probe(&blob, &low, &code, &seed);
        let high_output = run_probe(&blob, &high, &code, &seed);

        for output in [&low_output, &high_output] {
            assert_eq!(output.state.gpr, seed.gpr);
            assert_eq!(output.status, 0);
            assert_eq!(
                output.runtime_rflags & RET_PRESERVED_FLAGS,
                seed.rflags & RET_PRESERVED_FLAGS
            );
            assert_eq!(output.entry_rsp & 0xf, 8);
            assert_eq!(output.continuation_rsp, output.entry_rsp + 8);
            assert_eq!(output.continuation_reached, 1);
            assert_control_state(&seed, output);
        }
        assert_eq!(low_output.state, high_output.state);
    }
}

#[test]
fn production_add_preserves_control_state_and_stack_budget() {
    let blob = emit_interpreter().expect("the runtime must assemble");
    let mapping = Mapping::executable(&blob, AddressClass::High);
    let code = [0x11, 8, 1, 0x11, 8, 2, 0x20, 8, 0x12, 8, 0, 0x01];
    let seed = CpuState::sentinel(true);
    let output = run_probe(&blob, &mapping, &code, &seed);
    let mut expected_gpr = seed.gpr;
    expected_gpr[0] = 3;

    assert_eq!(output.state.gpr, expected_gpr);
    assert_eq!(output.state.rflags & ADD_DEFINED_FLAGS, 0x4);
    assert_eq!(output.canary_before, STACK_CANARY);
    assert_eq!(output.canary_after, STACK_CANARY);
    assert_ne!(output.low_watermark_after, STACK_CANARY);
    assert_eq!(MAX_PRODUCTION_ENTRY_STACK_USAGE, 272);
    assert_eq!(MAX_PROTECTED_FUNCTION_STACK_USAGE, 320);
    assert_control_state(&seed, &output);
}

#[test]
fn production_trap_does_not_resume_native_continuation() {
    const CHILD: &str = "VMP_RUNTIME_FASTFAIL_CHILD";
    assert_fastfail_subcode_encoding();
    if std::env::var_os(CHILD).is_some() {
        let blob = emit_interpreter().expect("the runtime must assemble");
        let mapping = Mapping::executable(&blob, AddressClass::High);
        let code = [0xff];
        let seed = CpuState::sentinel(false);
        let _ = run_probe(&blob, &mapping, &code, &seed);
        panic!("a production runtime trap returned to native continuation");
    }

    let status = Command::new(std::env::current_exe().expect("the test executable must exist"))
        .arg("--exact")
        .arg("production_trap_does_not_resume_native_continuation")
        .arg("--nocapture")
        .env(CHILD, "1")
        .status()
        .expect("the fail-fast child must start");

    assert_eq!(status.code(), Some(0xc000_0409_u32 as i32));
}
