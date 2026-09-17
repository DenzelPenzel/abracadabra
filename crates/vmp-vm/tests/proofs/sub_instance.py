"""Execute composed SUB and inspect every C++-pinned primitive boundary.

The reference trace is captured from C++ source, while result/flags come from
executing the original x64 instructions. This is emulator evidence, not Windows.
"""
import json
from pathlib import Path
import struct
import subprocess
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x
from body_instance import ROOT, BASE, CONTEXT, STACK

if not __debug__:
    raise RuntimeError('proof requires assertions')

MASK = (1 << 64) - 1
ROWS = ['push reg 8 1', 'pop reg 8 0'] + (Path(__file__).parent.parent / 'fixtures/cpp_sub_qword.txt').read_text().splitlines()
CASES = [(0, 0), (1, 2), (0, 1), (MASK, 1), (1 << 63, 1),
         ((1 << 63) - 1, MASK), (16, 1), (0x123456789abcdef0, 0xfedcba9876543210)]


def original(lhs, rhs):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, 4096)
    uc.mem_map(STACK, 4096)
    uc.mem_write(BASE, bytes.fromhex('4889c84829d0'))
    for r, v in [(x.UC_X86_REG_RSP, STACK), (x.UC_X86_REG_RCX, lhs),
                 (x.UC_X86_REG_RDX, rhs), (x.UC_X86_REG_EFLAGS, 0x202)]:
        uc.reg_write(r, v)
    uc.emu_start(BASE, BASE + 6, count=3)
    assert uc.reg_read(x.UC_X86_REG_RIP) == BASE + 6
    return uc.reg_read(x.UC_X86_REG_RAX), uc.reg_read(x.UC_X86_REG_EFLAGS)


def qword_decode(ciphertext, key):
    value = ~(((ciphertext ^ key) - 1) & MASK) & MASK
    return (((value >> 17) | (value << 47)) + 1) & MASK


def fields(artifact):
    commands = []
    depth = 0
    for row in ROWS:
        op, operand, width, raw = row.split()
        value = int(raw)
        args = []
        before = depth
        if (op, operand) == ('push', 'reg'):
            depth += 8
            if value == 4:
                handler = 4
            else:
                handler = 0
                args = [artifact['flags'] if value == 16 else 128 if value == 17
                        else artifact['registers'][value]]
        elif (op, operand) == ('pop', 'reg'):
            depth -= 8
            if value == 255:
                handler = 7
            else:
                handler = 1
                args = [artifact['flags'] if value == 16 else 128 if value == 17
                        else artifact['registers'][value]]
        elif (op, operand) == ('push', 'mem'):
            handler = 5
        elif (op, operand) == ('push', 'imm'):
            handler = 6
            depth += 8
            args = list(struct.pack('<Q', value))
        else:
            assert op in ('add', 'nor') and operand == 'none'
            handler = 2 if op == 'add' else 3
        commands.append((handler, before, args))
        assert 0 <= depth <= 24
    assert depth == 0 and max(c[1] for c in commands) == 24
    return commands


def execute(artifact, lhs, rhs, mutation=None):
    result, flags = original(lhs, rhs)
    commands = fields(artifact)
    image = bytes(artifact['image'])
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, 65536)
    uc.mem_write(BASE, image)
    uc.mem_map(0x60000000, 0x20000)
    uc.mem_write(CONTEXT - 16, b'\xa5' * 168)
    uc.mem_write(STACK - 40, b'\x5a' * 72)
    regs = [0x1122000000000000 + i for i in range(15)]
    regs[1:3] = [lhs, rhs]
    for offset, value in zip(artifact['registers'], regs):
        uc.mem_write(CONTEXT + offset, struct.pack('<Q', value))
    uc.mem_write(CONTEXT + artifact['flags'], struct.pack('<Q', 0x202))
    for r, v in [(x.UC_X86_REG_RSP, CONTEXT), (x.UC_X86_REG_RBP, STACK),
                 (x.UC_X86_REG_RSI, BASE + artifact['stream'][0]),
                 (x.UC_X86_REG_R10, BASE + artifact['table']),
                 (x.UC_X86_REG_R11, BASE + artifact['stream'][1]),
                 (x.UC_X86_REG_RDI, artifact.get('key') or 0),
                 (x.UC_X86_REG_EFLAGS, 0x202)]:
        uc.reg_write(r, v)
    assert len(artifact['opcodes']) == len(artifact['handlers']) == 8
    key = artifact.get('key')
    cursor = artifact['stream'][0]
    transitions = []
    for handler, _, args in commands:
        operands = [(1, artifact['opcodes'][handler])]
        operands += [(8, int.from_bytes(bytes(args), 'little'))] if handler == 6 else [(1, v) for v in args]
        for index, (width, expected) in enumerate(operands):
            actual = int.from_bytes(image[cursor:cursor + width], 'little')
            if key is not None:
                before = key
                def ror(value, count):
                    return ((value >> count) | (value << (8 - count))) & 255
                if width == 8:
                    actual = qword_decode(actual, key)
                else:
                    value = actual ^ (key & 255)
                    actual = (ror(~((value - 1) & 255) & 255, 1) + 1) & 255 if index else ror(~ror(value, 4) & 255, 7) ^ 0x1b
                key ^= actual
                transitions.append((BASE + cursor, width, actual, before, key))
            assert actual == expected, 'physical field differs from C++ primitive'
            cursor += width
    assert cursor == artifact['stream'][1]
    entries = [BASE + h for h in artifact['handlers']]
    for op, entry in zip(artifact['opcodes'], entries):
        assert struct.unpack('<Q', image[artifact['table'] + op * 8:artifact['table'] + op * 8 + 8])[0] == entry
    if mutation == 'nor':
        pc = image.index(bytes.fromhex('48f7d0'), artifact['handlers'][3])
        uc.mem_write(BASE + pc, b'\x90' * 3)
    elif mutation == 'drop':
        uc.mem_write(entries[7] + 3, b'\x10')
    elif mutation == 'pointer':
        uc.mem_write(entries[4] + 2, b'\xe0')
    elif mutation == 'mask':
        assert artifact.get('key') is None
        start = artifact['stream'][0]
        needle = bytes([artifact['opcodes'][6]]) + struct.pack('<Q', MASK ^ 0x815)
        pc = image.index(needle, start)
        uc.mem_write(BASE + pc + 1, b'\xeb')
    elif mutation == 'keywidth':
        pc = image.index(bytes.fromhex('4831c7'), artifact['handlers'][6])
        uc.mem_write(BASE + pc, b'\x40')
    elif mutation == 'rotate':
        pc = image.index(bytes.fromhex('48c1c811'), artifact['handlers'][6])
        uc.mem_write(BASE + pc + 3, b'\x10')
    visited = []
    decoded_fields = []
    updates = {BASE + i + 3: 1 for i in range(artifact['table'] - 2) if image[i:i+3] == bytes.fromhex('4030d7')}
    updates.update({BASE + i + 3: 8 for i in range(artifact['table'] - 2) if image[i:i+3] == bytes.fromhex('4831c7')})
    def observe(machine, pc, size, _):
        if transitions and pc in updates:
            address, width, plain, _, after = transitions[len(decoded_fields)]
            assert updates[pc] == width
            assert machine.reg_read(x.UC_X86_REG_RDI) == after, 'full rolling key'
            assert machine.reg_read(x.UC_X86_REG_RSI) == address + width, 'field cursor'
            register = x.UC_X86_REG_RAX if width == 8 else x.UC_X86_REG_RDX
            assert machine.reg_read(register) == plain, 'decoded field'
            decoded_fields.append(address)
        if pc not in entries:
            return
        index = len(visited)
        assert index < len(commands)
        handler, depth, _ = commands[index]
        assert pc == entries[handler], 'C++ handler order'
        visited.append(pc)
        sp = machine.reg_read(x.UC_X86_REG_RBP)
        assert sp == STACK - depth, 'C++ stack depth'
        assert machine.reg_read(x.UC_X86_REG_RSP) == CONTEXT
        def word(offset=0):
            return struct.unpack('<Q', machine.mem_read(sp + offset, 8))[0]
        local = index - 2
        if local == 3:
            assert (word(), word(8), word(16)) == (lhs, lhs, rhs), 'inverse input'
        if local == 5:
            assert (word(), word(8)) == (~lhs & MASK, rhs), 'inverse result'
        if local == 6:
            assert word(8) == (~result & MASK), 'ADD result'
            assert word() & 0x815 == flags & 0x815, 'ADD flags for merge'
        if local == 8:
            assert word() == STACK - 8, 'pre-push stack pointer'
        if local == 9:
            assert word() == word(8) == (~result & MASK), 'dereferenced duplicate'
        if local == 10:
            assert word(8) == result, 'final inversion result'
            assert word() & 0xc0 == flags & 0xc0, 'final inversion flags'
        if local == 28:
            assert word() & 0x8d5 == flags & 0x8d5, 'merged SUB flags'
    uc.hook_add(UC_HOOK_CODE, observe)
    uc.emu_start(BASE + artifact['entry'], BASE + artifact['done'], count=10000)
    assert uc.reg_read(x.UC_X86_REG_RIP) == BASE + artifact['done']
    assert len(visited) == len(ROWS) == 31
    regs[0] = result
    for offset, expected in zip(artifact['registers'], regs):
        assert struct.unpack('<Q', uc.mem_read(CONTEXT + offset, 8))[0] == expected
    assert struct.unpack('<Q', uc.mem_read(CONTEXT + artifact['flags'], 8))[0] & 0x8d5 == flags & 0x8d5
    assert uc.reg_read(x.UC_X86_REG_RBP) == STACK
    assert uc.reg_read(x.UC_X86_REG_RSI) == BASE + artifact['stream'][1]
    if key is not None:
        assert uc.reg_read(x.UC_X86_REG_RDI) == key
        assert len(decoded_fields) == len(transitions)
    assert bytes(uc.mem_read(STACK - 40, 16)) == b'\x5a' * 16
    assert bytes(uc.mem_read(STACK, 32)) == b'\x5a' * 32
    assert bytes(uc.mem_read(CONTEXT + 136, 16)) == b'\xa5' * 16
    assert bytes(uc.mem_read(CONTEXT - 16, 8)) == b'\xa5' * 8


class ComposedSubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = []
        for encrypted in (False, True):
            output = subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-vm', '--example',
                'body_instance', '--', '--sub'] + (['--encrypted'] if encrypted else []), cwd=ROOT, text=True)
            rows = [json.loads(line) for line in output.splitlines()]
            assert [row['variant'] for row in rows] == list(range(256))
            cls.artifacts.extend(rows)
        assert len(cls.artifacts) == 512

    def test_cpp_sequence_stack_flags_and_physical_fields(self):
        fixture = (Path(__file__).parent.parent / 'fixtures/cpp_qword_cryptor.txt').read_text().splitlines()
        assert fixture[0] == '# 4:1 8:0 7:17 3:1'
        for row in fixture[1:]:
            plain, ciphertext, before, after = [int(v, 16) for v in row.split()]
            assert qword_decode(ciphertext, before) == plain and before ^ plain == after
        for artifact in self.artifacts:
            for lhs, rhs in CASES:
                execute(artifact, lhs, rhs)

    def test_changed_nor_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'inverse result'):
            execute(self.artifacts[0], 1, 2, 'nor')

    def test_changed_discard_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'stack depth'):
            execute(self.artifacts[0], 1, 2, 'drop')

    def test_changed_stack_pointer_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'pre-push stack pointer'):
            execute(self.artifacts[0], 1, 2, 'pointer')

    def test_changed_merge_mask_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'merged SUB flags'):
            execute(self.artifacts[0], 0, 1, 'mask')

    def test_narrowed_qword_key_update_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'full rolling key'):
            execute(self.artifacts[256], 0, 1, 'keywidth')

    def test_changed_qword_rotation_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'full rolling key'):
            execute(self.artifacts[256], 0, 1, 'rotate')


if __name__ == '__main__':
    unittest.main()
