"""Windows metadata unwind over C++-produced snapshots, not exception dispatch.

The processor ran in Unicorn. Windows supplies EstablisherFrame, stack cursors,
handler lookup and subsequent unwind transitions. Only the returned handler is
called natively; neither the protected function nor a real exception is run here.
"""
import ctypes as c
import json
import os
from pathlib import Path
import struct

import pefile
from snapshot import STACK, STACK_SIZE, REGS, UNWIND, snapshots, verified_image


def main():
    assert os.name == 'nt' and c.sizeof(c.c_void_p) == 8, 'requires native Windows x64'
    kernel = c.WinDLL('kernel32', use_last_error=True)
    ntdll = c.WinDLL('ntdll')
    ptr, u32, u64 = c.c_void_p, c.c_uint32, c.c_uint64
    def bind(dll, name, result, args):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = result, args
        return fn
    alloc = bind(kernel, 'VirtualAlloc', ptr, [ptr, c.c_size_t, u32, u32])
    free = bind(kernel, 'VirtualFree', c.c_int, [ptr, c.c_size_t, u32])
    protect = bind(kernel, 'VirtualProtect', c.c_int, [ptr, c.c_size_t, u32, c.POINTER(u32)])
    flush = bind(kernel, 'FlushInstructionCache', c.c_int, [ptr, ptr, c.c_size_t])
    process = bind(kernel, 'GetCurrentProcess', ptr, [])
    add = bind(ntdll, 'RtlAddFunctionTable', c.c_ubyte, [ptr, u32, u64])
    delete = bind(ntdll, 'RtlDeleteFunctionTable', c.c_ubyte, [ptr])
    lookup = bind(ntdll, 'RtlLookupFunctionEntry', ptr, [u64, c.POINTER(u64), ptr])
    unwind = bind(ntdll, 'RtlVirtualUnwind', ptr,
                  [u32, u64, u64, ptr, ptr, c.POINTER(ptr), c.POINTER(u64), ptr])
    readq = lambda address: c.c_uint64.from_address(address).value
    writeq = lambda address, value: setattr(c.c_uint64.from_address(address), 'value', value)
    rows = []
    for variant, lhs, rhs, checkpoint, data, uc in snapshots():
        pe = pefile.PE(data=data)
        base, size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
        pc, frame = uc.reg_read(REGS['rip']), uc.reg_read(REGS['rsp'])
        entries = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION]
        owners = [e for e in entries if e.BeginAddress <= pc - base < e.EndAddress]
        assert len(owners) == 1
        owner = owners[0]
        assert pe.get_data(owner.UnwindData, 16) == UNWIND
        expected_handler = base + struct.unpack('<I', pe.get_data(owner.UnwindData + 16, 4))[0]
        mapped = registered = False
        stack = None
        table = base + pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress
        try:
            address = alloc(base, size, 0x3000, 4)
            assert address == base, ('exact image mapping required', c.get_last_error())
            mapped = True
            stack = alloc(STACK, STACK_SIZE, 0x3000, 4)
            assert stack == STACK, ('exact snapshot stack mapping required', c.get_last_error())
            image = verified_image(pe, uc)
            c.memmove(base, image, len(image))
            stack_bytes = bytes(uc.mem_read(STACK, STACK_SIZE))
            c.memmove(STACK, stack_bytes, len(stack_bytes))
            old = u32()
            assert protect(base, size, 0x20, c.byref(old))
            assert flush(process(), base, size)
            assert add(table, len(entries), base)
            registered = True
            image_base = u64()
            function = lookup(pc, c.byref(image_base), None)
            assert function and image_base.value == base
            assert c.string_at(function, 12) == struct.pack('<III', owner.BeginAddress, owner.EndAddress, owner.UnwindData)
            # Native x64 CONTEXT has 16-byte alignment and GPRs starting at 0x78
            storage = c.create_string_buffer(1232 + 15)
            context = (c.addressof(storage) + 15) & ~15
            c.c_uint32.from_address(context + 0x30).value = 0x10000b
            c.c_uint32.from_address(context + 0x44).value = uc.reg_read(REGS['eflags'])
            order = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                     'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip')
            for index, name in enumerate(order):
                writeq(context + 0x78 + 8 * index, uc.reg_read(REGS[name]))
            native_rip, native_rsp = readq(frame + 192), readq(frame + 200)
            handler_data, establisher = ptr(), u64()
            handler = unwind(1, base, pc, function, context, c.byref(handler_data), c.byref(establisher), None)
            cursor = readq(context + 0x98)
            print(json.dumps({'variant': variant, 'checkpoint': checkpoint, 'pc': hex(pc),
                              'frame': hex(frame), 'establisher': hex(establisher.value),
                              'cursor': hex(cursor), 'handler': hex(handler or 0)}), flush=True)
            assert handler == expected_handler and establisher.value == frame
            assert cursor == frame + 248
            for offset, slot in ((0xa0, 208), (0xa8, 216), (0xb0, 224), (0x90, 232)):
                assert readq(context + offset) == readq(frame + slot)
            # The dispatcher structure points at the OS-mutated context unchanged
            dispatch = c.create_string_buffer(80)
            writeq(c.addressof(dispatch) + 0x28, context)
            callback = c.WINFUNCTYPE(c.c_int32, ptr, ptr, ptr, ptr)(handler)
            assert callback(None, establisher.value, context, c.addressof(dispatch)) == 1
            expected_stack = bytearray(stack_bytes)
            struct.pack_into('<Q', expected_stack, native_rsp - 8 - STACK, native_rip)
            empty = [e.BeginAddress for e in entries if e.EndAddress == e.BeginAddress + 1
                     and pe.get_data(e.BeginAddress, 1) == b'\xc3'
                     and pe.get_data(e.UnwindData, 4) == bytes.fromhex('01000000')]
            assert len(empty) == 1
            for slot in range(frame + 240, native_rsp - 8, 8):
                struct.pack_into('<Q', expected_stack, slot - STACK, base + empty[0])
            assert c.string_at(STACK, STACK_SIZE) == expected_stack
            assert readq(context + 0x98) == cursor
            steps = 0
            while readq(context + 0xf8) != native_rip:
                current = readq(context + 0xf8)
                assert current == base + empty[0] and steps < 256
                function = lookup(current, c.byref(image_base), None)
                assert function and image_base.value == base
                returned = unwind(0, base, current, function, context,
                                  c.byref(handler_data), c.byref(establisher), None)
                assert not returned
                steps += 1
            assert readq(context + 0x98) == native_rsp
            rows.append({'variant': variant, 'lhs': lhs, 'rhs': rhs, 'checkpoint': checkpoint,
                         'frame': frame, 'os_cursor': cursor, 'native_rip': native_rip,
                         'native_rsp': native_rsp, 'unwind_steps': steps})
            assert delete(table)
            registered = False
            assert not lookup(pc, c.byref(image_base), None), 'removed table must no longer resolve'
        finally:
            if registered:
                assert delete(table)
            if stack:
                assert free(stack, 0, 0x8000)
            if mapped:
                assert free(base, 0, 0x8000)
    assert len(rows) == 30
    Path('cpp-windows-unwind-results.json').write_text(json.dumps({
        'scope': 'Windows metadata unwind and native callback over emulator snapshots; NOT exception dispatch',
        'cases': rows}, indent=2) + '\n')
    print('PASS: 30 Windows metadata/handler walks; 30 removed-table lookup negatives', flush=True)


if __name__ == '__main__':
    main()
