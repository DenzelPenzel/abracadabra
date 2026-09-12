"""Independent test mapping and native SEH catcher for Rust-generated leaf bodies."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from snapshot import REGS, STACK, STACK_SIZE, SP, STOP, UNWIND

BASE, PLACEMENT = 0x140000000, 0x2000


def check(image, entry, fault, bias):
    for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
        for stop in (STOP, fault):
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            uc.mem_map(BASE, len(image))
            uc.mem_write(BASE, image)
            uc.mem_map(STACK, STACK_SIZE)
            uc.mem_map(STOP, 4096)
            for index, (name, reg) in enumerate(REGS.items()):
                if name not in ('eflags', 'rip'):
                    uc.reg_write(reg, 0x1122000000000000 + index * 0x101)
            uc.reg_write(REGS['rsp'], SP)
            uc.reg_write(REGS['rcx'], lhs)
            uc.reg_write(REGS['rdx'], rhs)
            uc.reg_write(REGS['eflags'], 0x202)
            uc.mem_write(SP, struct.pack('<Q', STOP))
            uc.emu_start(entry, stop, count=100000, timeout=10000000)
            assert uc.reg_read(REGS['rip']) == stop
            if stop == STOP:
                assert uc.reg_read(REGS['rax']) == (lhs + rhs) & 0xffffffffffffffff
                assert uc.reg_read(REGS['rsp']) == SP + 8
            else:
                frame = uc.reg_read(REGS['rsp']) + bias
                assert struct.unpack('<6Q', uc.mem_read(frame + 192, 48)) == (
                    BASE + 0x1000, SP, 0x1122000000000606, 0x1122000000000404,
                    0x1122000000000505, 0x1122000000000101)


def main():
    output = subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-vm', '--example', 'leaf_unwind'], text=True)
    instances = [json.loads(line) for line in output.splitlines()]
    assert [row['variant'] for row in instances] == [0, 1, 127, 255]
    out = Path('target/rust-leaf-unwind')
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for row, site in ((row, site) for row in instances for site in ('add', 'flags-pop', 'after-pop')):
        code = bytes(row['image'])
        body_codes = bytearray(UNWIND)
        for offset in (4, 8, 10, 12, 14):
            body_codes[offset] = 0
        shifted_codes = bytearray(body_codes)
        shifted_codes[6] = 27
        assert list(map(bytes, row['codes'])) == [bytes(body_codes), bytes(shifted_codes), bytes(body_codes)]
        image = bytearray(65536)
        image[0x1000:0x1007] = bytes.fromhex('4889c84801d0c3')
        image[PLACEMENT:PLACEMENT + len(code)] = code
        # Body-only ranges have no partially executed prologue at their beginning
        image[0x8100:0x8110] = body_codes
        struct.pack_into('<II', image, 0x8110, PLACEMENT + row['handler'][0], 0)
        image[0x8120:0x8124] = bytes.fromhex('01000000')
        image[0x8140:0x8150] = bytes(row['codes'][1])
        struct.pack_into('<II', image, 0x8150, PLACEMENT + row['shifted_handler'], 0)
        ranges = [(0x1000, 0x1007, 0x8120),
                  (PLACEMENT + row['empty'], PLACEMENT + row['empty'] + 1, 0x8120),
                  (PLACEMENT + row['handler'][0], PLACEMENT + row['handler'][1], 0x8120)]
        ranges.extend((PLACEMENT + start, PLACEMENT + end, 0x8140 if index == 1 else 0x8100)
                      for index, (start, end) in enumerate(row['processor']))
        for index, record in enumerate(sorted(ranges)):
            struct.pack_into('<III', image, 0x8000 + index * 12, *record)
        signature = bytes.fromhex('48034508')
        assert code.count(signature) == 1
        fault = BASE + PLACEMENT + code.index(signature)
        entry = BASE + PLACEMENT + row['entry']
        # The flags transfer also belongs to the advertised processor range
        flags_transfer = bytes.fromhex('9c8f4500')
        assert code.count(flags_transfer) == 1
        flags_pop = code.index(flags_transfer) + 1
        assert row['processor'][1] == [flags_pop, flags_pop + 3]
        bias = 8 if site == 'flags-pop' else 0
        if bias:
            fault = BASE + PLACEMENT + flags_pop
        elif site == 'after-pop':
            fault = BASE + PLACEMENT + flags_pop + 3
        check(bytes(image), entry, fault, bias)
        path = out / f"{row['variant']}-{site}.image"
        path.write_bytes(image)
        if len(sys.argv) == 1:
            continue
        assert os.name == 'nt'
        executable = str(Path(sys.argv[1]).resolve())
        for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
            for mode in ('normal', 'fault', 'no-handler'):
                args = [executable, str(path.resolve())] + [str(n) for n in (
                    BASE, len(image), entry, 0x8000, len(ranges), fault,
                    BASE + PLACEMENT + row['handler'][0], BASE + 0x1000,
                    0x8140 if bias else 0x8100, lhs, rhs)] + [mode, str(bias)]
                result = subprocess.run(args, capture_output=True, text=True, timeout=30)
                print(row['variant'], lhs, rhs, mode, result.returncode, result.stdout, result.stderr, flush=True)
                if mode == 'no-handler':
                    assert result.returncode == 3221225501 and 'FAULT:' in result.stdout
                    assert not result.stderr and 'HANDLER:' not in result.stdout and 'PASS:' not in result.stdout
                else:
                    expected = 'PASS: native normal return' if mode == 'normal' else 'PASS: native exception dispatch'
                    assert result.returncode == 0 and expected in result.stdout
                    if mode == 'fault':
                        assert 'FAULT:' in result.stdout and 'HANDLER:' in result.stdout
                results.append({'variant': row['variant'], 'site': site, 'lhs': lhs, 'rhs': rhs, 'mode': mode,
                                'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    if len(sys.argv) > 1:
        assert len(results) == 108
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print('PASS: 36 Rust native returns; 36 exception dispatches; 36 removed-handler negatives')
    else:
        print('PASS: 4 Rust leaf layouts; 36 normal executions and 36 live shadow checkpoints')


if __name__ == '__main__':
    main()
