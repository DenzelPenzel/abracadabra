/* Native Windows exception-dispatch proof, isolated by the Python parent */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DWORD owner_thread;
static unsigned char *fault_pc, *handler_pc;
static unsigned char handler_byte;
static DWORD64 expected_rip, observed_frame, observed_native_rsp;
static unsigned fault_seen, handler_seen;
static DWORD frame_bias;
static int entry_fault;
static int gate_fault;

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s (win32=%lu)\n", message, GetLastError());
        fflush(stderr);
        ExitProcess(20);
    }
}

static LONG CALLBACK observe(EXCEPTION_POINTERS *exception)
{
    CONTEXT *context;
    DWORD old;
    if (GetCurrentThreadId() != owner_thread)
        return EXCEPTION_CONTINUE_SEARCH;
    context = exception->ContextRecord;
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
        exception->ExceptionRecord->ExceptionAddress == fault_pc) {
        NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
        require(fault_seen == 0, "fault must be delivered once");
        observed_frame = context->Rsp + frame_bias;
        require(observed_frame >= (DWORD64)tib->StackLimit &&
                observed_frame + 256 < (DWORD64)tib->StackBase, "native thread stack frame");
        if (!entry_fault && !gate_fault)
            require(*(DWORD64 *)(observed_frame + 192) == expected_rip, "live shadow RIP");
        observed_native_rsp = gate_fault ? 0 : *(DWORD64 *)(observed_frame + 200);
        if (!entry_fault && !gate_fault)
            require(observed_native_rsp > observed_frame + 248 &&
                observed_native_rsp < (DWORD64)tib->StackBase, "live native RSP");
        fault_seen++;
        printf("FAULT: pc=%p frame=%llx native_rsp=%llx\n", fault_pc,
               (unsigned long long)observed_frame, (unsigned long long)observed_native_rsp);
        fflush(stdout);
        /* Do not handle the fault: Windows must perform normal SEH search */
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
        exception->ExceptionRecord->ExceptionAddress == handler_pc) {
        DISPATCHER_CONTEXT *dispatch = (DISPATCHER_CONTEXT *)context->R9;
        require(fault_seen == 1 && handler_seen == 0, "handler follows original fault once");
        require(context->Rdx == observed_frame, "OS supplied actual establisher frame");
        require(dispatch->ContextRecord->Rsp == observed_frame + 248, "OS supplied dispatcher cursor");
        handler_seen++;
        printf("HANDLER: pc=%p frame=%llx cursor=%llx\n", handler_pc,
               (unsigned long long)context->Rdx,
               (unsigned long long)dispatch->ContextRecord->Rsp);
        fflush(stdout);
        /* Restore the original instruction before resuming at its first byte */
        require(VirtualProtect(handler_pc, 1, PAGE_READWRITE, &old) != 0, "handler writable");
        *handler_pc = handler_byte;
        require(VirtualProtect(handler_pc, 1, old, &old) != 0, "handler executable");
        require(FlushInstructionCache(GetCurrentProcess(), handler_pc, 1) != 0, "handler cache");
        context->Rip = (DWORD64)handler_pc;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (entry_fault && fault_seen && handler_seen &&
        exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        DWORD64 handler_base = 0, fault_base = 0;
        PRUNTIME_FUNCTION handler_range = RtlLookupFunctionEntry((DWORD64)handler_pc, &handler_base, NULL);
        PRUNTIME_FUNCTION fault_range = RtlLookupFunctionEntry(context->Rip, &fault_base, NULL);
        require(handler_range != NULL && fault_range != NULL && handler_base == fault_base &&
                handler_range->BeginAddress == fault_range->BeginAddress &&
                handler_range->EndAddress == fault_range->EndAddress, "AV belongs to original handler");
        require(exception->ExceptionRecord->NumberParameters >= 2 &&
                exception->ExceptionRecord->ExceptionInformation[0] == 1 &&
                exception->ExceptionRecord->ExceptionInformation[1] == observed_native_rsp - 8,
                "handler writes through native-RSP shadow");
        printf("HANDLER_AV: pc=%p operation=%llu address=%llx\n",
               exception->ExceptionRecord->ExceptionAddress,
               (unsigned long long)exception->ExceptionRecord->ExceptionInformation[0],
               (unsigned long long)exception->ExceptionRecord->ExceptionInformation[1]);
        fflush(stdout);
        /* Stop the isolated diagnostic child before recursive exception dispatch */
        ExitProcess(21);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int catch_fault(EXCEPTION_POINTERS *exception)
{
    require(exception->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
            exception->ExceptionRecord->ExceptionAddress == fault_pc, "outer catcher sees original fault");
    require(fault_seen == 1 && handler_seen == (gate_fault ? 0u : 1u),
            "expected handler path before outer catcher");
    return EXCEPTION_EXECUTE_HANDLER;
}

/* MSVC emits the outer SEH metadata; no synthetic stack or manual handler call */
__declspec(noinline) static void invoke(DWORD64 entry, uint64_t lhs, uint64_t rhs, int normal)
{
    typedef uint64_t (*probe_fn)(uint64_t, uint64_t);
    volatile int caught = 0;
    __try {
        uint64_t result = ((probe_fn)entry)(lhs, rhs);
        require(normal, "faulting processor unexpectedly returned");
        require(result == lhs + rhs, "native result");
    } __except (catch_fault(GetExceptionInformation())) {
        caught = 1;
    }
    require(normal ? !caught : caught, "outer native continuation");
}

int main(int argc, char **argv)
{
    DWORD64 base, entry;
    SIZE_T size;
    DWORD pdata, count, unwind_rva, old;
    uint64_t lhs, rhs;
    int normal, negative, loader;
    void *reservation = NULL;
    void *image, *observer;
    FILE *file = NULL;
    PRUNTIME_FUNCTION table;
    require(argc == 14 || argc == 15 || argc == 16, "arguments");
    loader = argc == 16;
    require(!loader || strcmp(argv[15], "pe") == 0, "loader mode");
    frame_bias = argc >= 15 ? (DWORD)strtoul(argv[14], NULL, 10) : 0;
    require(frame_bias == 0 || frame_bias == 8, "frame bias");
    base = _strtoui64(argv[2], NULL, 10);
    size = (SIZE_T)_strtoui64(argv[3], NULL, 10);
    entry = _strtoui64(argv[4], NULL, 10);
    pdata = (DWORD)strtoul(argv[5], NULL, 10);
    count = (DWORD)strtoul(argv[6], NULL, 10);
    fault_pc = (unsigned char *)_strtoui64(argv[7], NULL, 10);
    handler_pc = (unsigned char *)_strtoui64(argv[8], NULL, 10);
    expected_rip = _strtoui64(argv[9], NULL, 10);
    unwind_rva = (DWORD)strtoul(argv[10], NULL, 10);
    lhs = _strtoui64(argv[11], NULL, 10);
    rhs = _strtoui64(argv[12], NULL, 10);
    normal = strcmp(argv[13], "normal") == 0;
    negative = strcmp(argv[13], "no-handler") == 0;
    entry_fault = strcmp(argv[13], "entry-fault") == 0;
    gate_fault = strcmp(argv[13], "gate-fault") == 0;
    require(normal || negative || entry_fault || gate_fault || strcmp(argv[13], "fault") == 0, "mode");
    require(size && pdata < size && (SIZE_T)count * 12 <= size - pdata &&
            unwind_rva < size && entry >= base && entry - base < size &&
            (DWORD64)fault_pc >= base && (DWORD64)fault_pc - base + 2 <= size &&
            (DWORD64)handler_pc >= base && (DWORD64)handler_pc - base < size, "image ranges");
    if (loader) {
        DWORD64 loaded_base = 0, delta;
        PRUNTIME_FUNCTION found;
        reservation = VirtualAlloc((void *)base, size, MEM_RESERVE, PAGE_NOACCESS);
        image = (void *)LoadLibraryA(argv[1]);
        require(image != NULL && (DWORD64)image != base, "loader must rebase the DLL");
        delta = (DWORD64)image - base;
        base = (DWORD64)image;
        entry += delta;
        fault_pc = (unsigned char *)((DWORD64)fault_pc + delta);
        handler_pc = (unsigned char *)((DWORD64)handler_pc + delta);
        expected_rip += delta;
        found = RtlLookupFunctionEntry((DWORD64)fault_pc, &loaded_base, NULL);
        require(found != NULL && loaded_base == base && found->UnwindData == unwind_rva,
                "loader registered persisted exception directory");
        require(VirtualProtect(image, size, PAGE_READWRITE, &old) != 0, "loaded image writable");
    } else {
    image = VirtualAlloc((void *)base, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    require(image == (void *)base, "exact image allocation");
    require(fopen_s(&file, argv[1], "rb") == 0 && file != NULL, "image open");
    require(fread(image, 1, size, file) == size && fgetc(file) == EOF, "image length");
    require(fclose(file) == 0, "image close");
    }
    if (!normal) {
        fault_pc[0] = 0x0f;
        fault_pc[1] = 0x0b;
        handler_byte = *handler_pc;
        *handler_pc = 0xcc;
        if (negative) {
            require(((unsigned char *)image)[unwind_rva] == 9, "EHANDLER header");
            ((unsigned char *)image)[unwind_rva] = 1;
        }
    }
    require(VirtualProtect(image, size, PAGE_EXECUTE_READ, &old) != 0, "image executable");
    require(FlushInstructionCache(GetCurrentProcess(), image, size) != 0, "image cache");
    table = (PRUNTIME_FUNCTION)(base + pdata);
    if (!loader)
        require(RtlAddFunctionTable(table, count, base) != 0, "register table");
    owner_thread = GetCurrentThreadId();
    observer = AddVectoredExceptionHandler(1, observe);
    require(observer != NULL, "install observer");
    invoke(entry, lhs, rhs, normal);
    require(RemoveVectoredExceptionHandler(observer) != 0, "remove observer");
    if (loader) {
        require(FreeLibrary((HMODULE)image) != 0, "unload image");
        if (reservation != NULL)
            require(VirtualFree(reservation, 0, MEM_RELEASE) != 0, "release reservation");
    } else {
        require(RtlDeleteFunctionTable(table) != 0, "delete table");
        require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release image");
    }
    puts(normal ? "PASS: native normal return" : "PASS: native exception dispatch");
    return 0;
}
