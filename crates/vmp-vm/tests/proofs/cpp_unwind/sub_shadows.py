"""Observe SUB's live shadows at every processor boundary, plus a smaller-frame negative."""
import json
from pathlib import Path
import struct
import subprocess

from rust_entry import states, BASE, PLACEMENT
from snapshot import SP

if not __debug__:
    raise RuntimeError('proof requires assertions')


def check(row, shrink=False):
    image = bytearray(65536)
    code = bytearray(row['image'])
    allocation = code.index(bytes.fromhex('4881ec10010000'), row['entry'])
    if shrink:
        code[allocation + 3] = 0
    image[PLACEMENT:PLACEMENT + len(code)] = code
    bounds = (BASE + PLACEMENT + 4, BASE + PLACEMENT + row['processor'][-1][1])
    snapshots, expected = states(row, image, bounds)
    for regs, memory in snapshots:
        pc = regs[-1] - BASE - PLACEMENT
        owners = [i for i, (start, end) in enumerate(row['processor']) if start <= pc < end]
        assert len(owners) == 1
        bias = 8 if row['processor_codes'][owners[0]][6] == 27 else 0
        frame = regs[4] + bias
        start = frame + 192 - (SP - 4096)
        assert struct.unpack_from('<6Q', memory, start) == (
            BASE + 0x1000, SP, expected['rbp'], expected['rsi'], expected['rdi'], expected['rbx']
        ), 'SUB operand stack overwrote live shadows'
    return len(snapshots)


def main():
    output = subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-vm', '--example',
                                     'leaf_unwind', '--', '--sub'], text=True)
    rows = [json.loads(line) for line in output.splitlines()]
    assert [row['variant'] for row in rows] == [0, 1, 127, 255]
    results = []
    for row in rows:
        count = check(row)
        try:
            check(row, shrink=True)
        except AssertionError as error:
            assert str(error) == 'SUB operand stack overwrote live shadows'
        else:
            raise AssertionError('shrinking the emitted frame must be detected')
        results.append(dict(variant=row['variant'], boundaries=count, smaller_frame_detected=True))
    out = Path('target/rust-sub-shadows')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS:', sum(row['boundaries'] for row in results), 'live SUB body boundaries; 4 smaller-frame negatives')


if __name__ == '__main__':
    main()
