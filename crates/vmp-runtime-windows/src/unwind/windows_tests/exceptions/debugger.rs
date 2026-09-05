//! Temporary parent-side observation; never edits child code or exception contexts

use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

#[allow(unsafe_code)]
pub(super) fn observe(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut initial_breakpoint = true;
    loop {
        if Instant::now() >= deadline {
            child.kill().expect("kill debug timeout");
            panic!("debug observation exceeded 25 seconds");
        }
        let mut event = DEBUG_EVENT::default();
        // SAFETY: Events and contexts are local outputs; handles identify our stopped child only
        unsafe {
            if WaitForDebugEvent(&mut event, 100) == 0 {
                continue;
            }
            let mut disposition = DBG_CONTINUE;
            match event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let exception = event.u.Exception;
                    let record = exception.ExceptionRecord;
                    let mut module = [0u16; 1024];
                    let length = windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW(
                        child.as_raw_handle(),
                        record.ExceptionAddress,
                        module.as_mut_ptr(),
                        module.len() as u32,
                    );
                    eprintln!(
                        "DEBUG module={}",
                        String::from_utf16_lossy(&module[..length as usize])
                    );
                    let thread = OpenThread(THREAD_GET_CONTEXT, 0, event.dwThreadId);
                    assert!(!thread.is_null(), "open stopped exception thread");
                    let mut context = CONTEXT {
                        ContextFlags: CONTEXT_ALL_AMD64,
                        ..Default::default()
                    };
                    let got = GetThreadContext(thread, &mut context);
                    CloseHandle(thread);
                    assert_ne!(got, 0, "read stopped context");
                    eprintln!("DEBUG exception first={} code={:#x} address={:#x} tid={} RIP={:#x} RSP={:#x} EFLAGS={:#x} RAX={:#x} RCX={:#x} RDX={:#x} RBX={:#x} RBP={:#x} RSI={:#x} RDI={:#x} R8={:#x} R9={:#x} R10={:#x} R11={:#x} R12={:#x} R13={:#x} R14={:#x} R15={:#x} parameters={:?}", exception.dwFirstChance, record.ExceptionCode, record.ExceptionAddress as usize, event.dwThreadId, context.Rip, context.Rsp, context.EFlags, context.Rax, context.Rcx, context.Rdx, context.Rbx, context.Rbp, context.Rsi, context.Rdi, context.R8, context.R9, context.R10, context.R11, context.R12, context.R13, context.R14, context.R15, &record.ExceptionInformation[..record.NumberParameters.min(15) as usize]);
                    let mut bytes = [0u8; 64];
                    let mut read = 0;
                    let got = ReadProcessMemory(
                        child.as_raw_handle(),
                        context.Rip as *const c_void,
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        &mut read,
                    );
                    eprintln!("DEBUG memory ok={got} bytes={:02x?}", &bytes[..read]);
                    for instruction in
                        Decoder::with_ip(64, &bytes[..read], context.Rip, DecoderOptions::NONE)
                            .into_iter()
                            .take(8)
                    {
                        eprintln!("DEBUG instruction {:#x}: {}", instruction.ip(), instruction);
                    }
                    disposition = DBG_EXCEPTION_NOT_HANDLED;
                    if initial_breakpoint
                        && record.ExceptionCode == EXCEPTION_BREAKPOINT
                        && exception.dwFirstChance != 0
                    {
                        initial_breakpoint = false;
                        disposition = DBG_CONTINUE;
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let dll = event.u.LoadDll;
                    eprintln!("DEBUG DLL base={:#x}", dll.lpBaseOfDll as usize);
                    if !dll.hFile.is_null() {
                        CloseHandle(dll.hFile);
                    }
                }
                CREATE_PROCESS_DEBUG_EVENT => {
                    let process = event.u.CreateProcessInfo;
                    eprintln!("DEBUG EXE base={:#x}", process.lpBaseOfImage as usize);
                    if !process.hFile.is_null() {
                        CloseHandle(process.hFile);
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    eprintln!("DEBUG exit={:#x}", event.u.ExitProcess.dwExitCode);
                    assert_ne!(
                        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition),
                        0
                    );
                    break;
                }
                _ => {}
            }
            assert_ne!(
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition),
                0
            );
        }
    }
}
