"""Compare Windows entry unwind at every live Rust entry instruction boundary."""
import ctypes as c
import json
import os
from pathlib import Path
import struct
import subprocess

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from snapshot import REGS, STACK, STACK_SIZE, SP, STOP
from rust_leaf import BASE, PLACEMENT

ORDER = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip')
NONVOL = ('rbx', 'rbp', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15')


def states(row, image):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, len(image))
    uc.mem_write(BASE, bytes(image))
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(STOP, 4096)
    expected = {}
    for index, name in enumerate(ORDER):
        value = 0x1122000000000000 + index * 0x101
        uc.reg_write(REGS[name], value)
        expected[name] = value
    uc.reg_write(REGS['rsp'], SP)
    uc.reg_write(REGS['eflags'], 0x202)
    uc.mem_write(SP, struct.pack('<Q', STOP))
    rows = []
    start, end = BASE + PLACEMENT + row['entry'], BASE + PLACEMENT + row['empty']
    def capture(machine, pc, size, _):
        if start <= pc < end:
            rows.append(([machine.reg_read(REGS[name]) for name in ORDER],
                         bytes(machine.mem_read(SP - 4096, 4104))))
    uc.hook_add(UC_HOOK_CODE, capture)
    uc.emu_start(start, STOP, count=100000)
    assert uc.reg_read(REGS['rip']) == STOP
    assert rows and rows[0][0][-1] == start
    return rows, expected


def windows(image, snapshots, expected):
    kernel, nt = c.WinDLL('kernel32'), c.WinDLL('ntdll')
    ptr, u64, u32 = c.c_void_p, c.c_uint64, c.c_uint32
    alloc = kernel.VirtualAlloc
    alloc.restype, alloc.argtypes = ptr, [ptr, c.c_size_t, u32, u32]
    free = kernel.VirtualFree
    free.restype, free.argtypes = c.c_int, [ptr, c.c_size_t, u32]
    unwind = nt.RtlVirtualUnwind
    unwind.restype, unwind.argtypes = ptr, [u32, u64, u64, ptr, ptr, ptr, ptr, ptr]
    mapped = stack = None
    results = []
    try:
        mapped = alloc(BASE, len(image), 0x3000, 4)
        assert mapped == BASE
        stack = alloc(STACK, STACK_SIZE, 0x3000, 4)
        assert stack == STACK
        c.memmove(BASE, bytes(image), len(image))
        for regs, memory in snapshots:
            pc = regs[-1]
            for negative in (False, True):
                if negative and regs[4] == SP:
                    continue
                c.memmove(SP - 4096, memory, len(memory))
                prefix = bytes(image[0x8100:0x8104]) if not negative else bytes([1, 0, 0, 0])
                c.memmove(BASE + 0x8100, prefix, 4)
                storage = c.create_string_buffer(1248)
                context = (c.addressof(storage) + 15) & ~15
                for index, value in enumerate(regs):
                    c.c_uint64.from_address(context + 0x78 + index * 8).value = value
                handler_data, frame = ptr(), u64()
                handler = unwind(1, BASE, pc, BASE + 0x8000, context,
                                 c.byref(handler_data), c.byref(frame), None)
                actual = {name: c.c_uint64.from_address(context + 0x78 + index * 8).value
                          for index, name in enumerate(ORDER)}
                correct = (actual['rip'] == STOP and actual['rsp'] == SP + 8
                           and all(actual[name] == expected[name] for name in NONVOL))
                assert not handler and correct != negative, (hex(pc), negative, actual)
                results.append(dict(pc=pc, negative=negative, correct=correct))
    finally:
        if stack:
            assert free(stack, 0, 0x8000)
        if mapped:
            assert free(mapped, 0, 0x8000)
    return results


def main():
    output = subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-vm', '--example', 'leaf_unwind'], text=True)
    instances = [json.loads(line) for line in output.splitlines()]
    assert [row['variant'] for row in instances] == [0, 1, 127, 255]
    reports = []
    for row in instances:
        image = bytearray(65536)
        code = bytes(row['image'])
        image[PLACEMENT:PLACEMENT + len(code)] = code
        struct.pack_into('<III', image, 0x8000, PLACEMENT + row['entry'], PLACEMENT + row['empty'], 0x8100)
        image[0x8100:0x8128] = bytes(row['entry_codes'])
        snapshots, expected = states(row, image)
        cases = windows(image, snapshots, expected) if os.name == 'nt' else []
        reports.append(dict(variant=row['variant'], boundaries=len(snapshots), cases=cases))
    out = Path('target/rust-entry-unwind')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'results.json').write_text(json.dumps(reports, indent=2) + '\n')
    print('PASS:', sum(r['boundaries'] for r in reports), 'live entry boundaries;',
          sum(len(r['cases']) for r in reports), 'Windows unwind/negative comparisons')


if __name__ == '__main__':
    main()
