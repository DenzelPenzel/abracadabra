"""Execute Rust-generated body bytes, not a Python VM or a Windows ABI gate.

Run with the existing Unicorn interpreter. Requires cargo in PATH. The seven
literal rows are pinned C++/native observations, not computed with Rust's ADD.
"""
import json
from pathlib import Path
import struct
import subprocess
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x

ROOT = Path(__file__).resolve().parents[4]
BASE, CONTEXT, STACK = 0x140000000, 0x60001000, 0x60010000
CASES = [
    (0, 0, 0, 0x246), (1, 2, 3, 0x206),
    (0xffffffffffffffff, 1, 0, 0x257),
    (0x7fffffffffffffff, 1, 0x8000000000000000, 0xa96),
    (0x8000000000000000, 0x8000000000000000, 0, 0xa47),
    (15, 1, 16, 0x212),
    (0x123456789abcdef0, 0xfedcba9876543210, 0x1111111111111100, 0x207),
]


def execute(artifact, case, mutation=None):
    lhs, rhs, result, flags = case
    image = bytes(artifact['image'])
    m = Uc(UC_ARCH_X86, UC_MODE_64)
    m.mem_map(BASE, 0x10000)
    m.mem_write(BASE, image)
    m.mem_map(0x60000000, 0x20000)
    m.mem_write(CONTEXT - 16, b'\xa5' * 160)
    m.mem_write(STACK - 32, b'\x5a' * 64)
    registers = [0x1111000000000000 + i for i in range(15)]
    registers[1:3] = [lhs, rhs]
    offsets = artifact['registers']
    assert sorted(offsets + [artifact['flags']]) == list(range(0, 128, 8))
    for offset, value in zip(offsets, registers):
        m.mem_write(CONTEXT + offset, struct.pack('<Q', value))
    m.mem_write(CONTEXT + artifact['flags'], struct.pack('<Q', 0x202))
    for reg, value in [(x.UC_X86_REG_RSP, CONTEXT), (x.UC_X86_REG_RBP, STACK),
                       (x.UC_X86_REG_RSI, BASE + artifact['stream'][0]),
                       (x.UC_X86_REG_R10, BASE + artifact['table']),
                       (x.UC_X86_REG_R11, BASE + artifact['stream'][1]),
                       (x.UC_X86_REG_EFLAGS, 0x202)]:
        m.reg_write(reg, value)
    encrypted = artifact.get('key') is not None
    key = artifact.get('key') or 0
    if encrypted:
        assert key == BASE + artifact['stream'][0], 'address-derived initial key'
        m.reg_write(x.UC_X86_REG_RDI, key)
    p, q, a = artifact['opcodes']
    expected_fields = [p, offsets[1], q, offsets[0], p, offsets[2], p, offsets[0],
                       a, q, artifact['flags'], q, offsets[0]]
    operand_fields = {1, 3, 5, 7, 10, 12}
    updates = {BASE + i + 3 for i in range(artifact['table'] - 2)
               if image[i:i+3] == bytes.fromhex('4030d7')} if encrypted else set()
    if encrypted:
        assert len(updates) == 3, 'three generated decryptors'
        assert artifact['stream'][1] - artifact['stream'][0] == len(expected_fields)
    fields = []
    push, pop, add = [BASE + h for h in artifact['handlers']]
    if mutation == 'handler':
        assert bytes(m.mem_read(add + 4, 4)) == bytes.fromhex('48034508')
        m.mem_write(add + 5, b'\x2b')
    elif mutation == 'table':
        m.mem_write(BASE + artifact['table'] + artifact['opcodes'][2] * 8,
                    struct.pack('<Q', BASE + artifact['done']))
    elif mutation == 'stream':
        m.mem_write(BASE + artifact['stream'][0] + 1, bytes([offsets[2]]))
    elif mutation == 'ciphertext':
        start = BASE + artifact['stream'][0]
        m.mem_write(start, bytes([m.mem_read(start, 1)[0] ^ 1]))
    elif mutation == 'initial-key':
        m.reg_write(x.UC_X86_REG_RDI, key ^ 1)
    elif mutation == 'decryptor':
        constant = image.index(bytes.fromhex('80f21b')) + 2
        m.mem_write(BASE + constant, b'\x1a')
    visited = []
    def observe(machine, address, size, user):
        nonlocal key
        if address in updates:
            index = len(fields)
            assert index < len(expected_fields), 'field count'
            plain = expected_fields[index]
            assert machine.reg_read(x.UC_X86_REG_RDX) == plain, 'decrypted field'
            cursor = BASE + artifact['stream'][0] + index
            cipher = machine.mem_read(cursor, 1)[0]
            value = cipher ^ (key & 255)
            def ror(v, n):
                return ((v >> n) | (v << (8 - n))) & 255
            if index in operand_fields:
                value = (ror(~((value - 1) & 255) & 255, 1) + 1) & 255
            else:
                value = ror(~ror(value, 4) & 255, 7) ^ 0x1b
            assert value == plain, 'field ciphertext transform'
            after = key ^ plain
            assert machine.reg_read(x.UC_X86_REG_RDI) == after, 'field full rolling key'
            assert machine.reg_read(x.UC_X86_REG_RSI) == cursor + 1, 'field cursor'
            fields.append(dict(address=cursor, ciphertext=cipher, plaintext=plain,
                               key_before=key, key_after=after))
            key = after
        if address in (push, pop, add):
            visited.append(address)
        if address == add:
            assert machine.reg_read(x.UC_X86_REG_RBP) == STACK - 16
            assert struct.unpack('<QQ', machine.mem_read(STACK - 16, 16)) == (lhs, rhs), 'ADD inputs'
        if address == add + 16:
            stored_flags, stored_result = struct.unpack('<QQ', machine.mem_read(STACK - 16, 16))
            assert stored_result == result, 'ADD result'
            assert stored_flags & 0x8d5 == flags & 0x8d5, 'ADD flags'
    m.hook_add(UC_HOOK_CODE, observe)
    m.emu_start(BASE + artifact['entry'], BASE + artifact['done'], count=1000)
    assert m.reg_read(x.UC_X86_REG_RIP) == BASE + artifact['done'], 'completion'
    assert visited == [push, pop, push, push, add, pop, pop], 'handler order'
    registers[0] = result
    for offset, value in zip(offsets, registers):
        assert struct.unpack('<Q', m.mem_read(CONTEXT + offset, 8))[0] == value, 'guest register'
    assert struct.unpack('<Q', m.mem_read(CONTEXT + artifact['flags'], 8))[0] & 0x8d5 == flags & 0x8d5
    assert m.reg_read(x.UC_X86_REG_RSP) == CONTEXT
    assert m.reg_read(x.UC_X86_REG_RBP) == STACK
    assert m.reg_read(x.UC_X86_REG_RSI) == BASE + artifact['stream'][1]
    assert bytes(m.mem_read(STACK, 32)) == b'\x5a' * 32, 'older stack bytes'
    assert bytes(m.mem_read(STACK - 32, 16)) == b'\x5a' * 16, 'stack depth'
    assert bytes(m.mem_read(CONTEXT - 16, 8)) == b'\xa5' * 8, 'native stack depth'
    assert bytes(m.mem_read(CONTEXT + 128, 16)) == b'\xa5' * 16, 'context boundary'
    if encrypted:
        assert len(fields) == len(expected_fields), 'all fields observed'
    return fields


class GeneratedBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = subprocess.check_output([
            'cargo', 'run', '--quiet', '-p', 'vmp-vm', '--no-default-features',
            '--example', 'body_instance'], cwd=ROOT, text=True)
        cls.artifacts = [json.loads(line) for line in output.splitlines()]
        assert len(cls.artifacts) == 256
        assert [a['variant'] for a in cls.artifacts] == list(range(256))

    def test_generated_bytes_match_seven_native_cases_for_every_recipe(self):
        for artifact in self.artifacts:
            for case in CASES:
                with self.subTest(variant=artifact['variant'], case=case):
                    execute(artifact, case)

    def test_actual_add_to_sub_corruption_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'ADD result'):
            execute(self.artifacts[0], CASES[1], 'handler')

    def test_actual_table_corruption_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'handler order'):
            execute(self.artifacts[0], CASES[1], 'table')

    def test_actual_stream_corruption_is_detected(self):
        with self.assertRaisesRegex(AssertionError, 'ADD inputs'):
            execute(self.artifacts[0], CASES[1], 'stream')


if __name__ == '__main__':
    unittest.main()
