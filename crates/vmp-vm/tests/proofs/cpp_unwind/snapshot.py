"""Bounded C++ artifact replay; snapshots are not native Windows execution."""
from pathlib import Path
import hashlib
import json
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import x86_const as x

ROOT = Path(__file__).resolve().parent
STACK, STACK_SIZE, SP, STOP = 0x60000000, 0x200000, 0x60100008, 0x70000000
NAMES = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'eflags')
REGS = {name: getattr(x, 'UC_X86_REG_' + name.upper()) for name in (*NAMES, 'rip')}
UNWIND = bytes.fromhex('0900060005011a000450036002700130')


def artifacts():
    manifest = json.loads((ROOT / 'fixtures/manifest.json').read_text())
    required = {'unwind_add_probe.exe', 'unwind_classic_add_protected.exe',
                'unwind_advanced_add_protected.exe'}
    assert set(manifest) == required
    result = {}
    for name in sorted(required):
        data = (ROOT / 'fixtures' / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest[name], name
        result[name] = data
    original = pefile.PE(data=result['unwind_add_probe.exe'])
    assert len(original.DIRECTORY_ENTRY_EXCEPTION) == 1
    assert len(original.DIRECTORY_ENTRY_EXPORT.symbols) == 1
    entry = original.DIRECTORY_ENTRY_EXCEPTION[0].struct
    assert original.DIRECTORY_ENTRY_EXPORT.symbols[0].address == entry.BeginAddress
    assert entry.EndAddress == entry.BeginAddress + 17
    assert original.get_data(entry.BeginAddress, 17) == bytes.fromhex('534883ec204889c84801d04883c4205bc3')
    assert original.get_data(entry.UnwindData, 8) == bytes.fromhex('0105020005320130')
    return result, original.OPTIONAL_HEADER.ImageBase + entry.BeginAddress


def replay(data, lhs, rhs, count=100000):
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
    uc.mem_write(base, pe.get_memory_mapped_image())
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(SP - 4096, b'\xa5' * 4096)
    uc.mem_map(STOP, 4096)
    for i, name in enumerate(NAMES):
        if name != 'eflags':
            uc.reg_write(REGS[name], 0x1122000000000000 + i * 0x101)
    for name, value in (('rcx', lhs), ('rdx', rhs), ('rsp', SP), ('eflags', 0x202)):
        uc.reg_write(REGS[name], value)
    uc.mem_write(SP, struct.pack('<Q', STOP))
    instructions, events = [], []
    def code(machine, pc, size, _):
        instructions.append((pc, size))
    def write(machine, access, address, size, value, _):
        rsp = machine.reg_read(REGS['rsp'])
        if size == 8 and address - rsp in (192, 200, 208, 216, 224, 232):
            events.append((address - rsp, value, len(instructions)))
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    assert len(pe.DIRECTORY_ENTRY_EXPORT.symbols) == 1
    uc.emu_start(base + pe.DIRECTORY_ENTRY_EXPORT.symbols[0].address, STOP,
                 count=count, timeout=10000000)
    assert len(instructions) == count or uc.reg_read(REGS['rip']) == STOP
    return uc, events


def snapshots():
    files, entry = artifacts()
    expected = [(192, entry), (200, SP), (208, 0x1122000000000606),
                (216, 0x1122000000000404), (224, 0x1122000000000505),
                (232, 0x1122000000000101), (200, SP - 8), (192, entry + 1),
                (200, SP - 40), (192, entry + 5), (200, SP - 8), (200, SP)]
    for variant in ('classic', 'advanced'):
        data = files[f'unwind_{variant}_add_protected.exe']
        for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
            native, _ = replay(files['unwind_add_probe.exe'], lhs, rhs)
            protected, events = replay(data, lhs, rhs)
            assert [(offset, value) for offset, value, _ in events] == expected
            assert protected.reg_read(REGS['rip']) == STOP
            for name in NAMES:
                mask = 0x8d5 if name == 'eflags' else 0xffffffffffffffff
                assert native.reg_read(REGS[name]) & mask == protected.reg_read(REGS[name]) & mask
            for checkpoint in (5, 7, 9, 10, 11):
                uc, partial = replay(data, lhs, rhs, events[checkpoint][2])
                assert partial == events[:checkpoint + 1]
                yield variant, lhs, rhs, checkpoint, data, uc


if __name__ == '__main__':
    count = sum(1 for _ in snapshots())
    assert count == 30
    print('PASS: 30 C++ producer snapshots; 6 native/protected comparisons')
