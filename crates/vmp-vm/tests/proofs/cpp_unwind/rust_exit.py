"""Check every executed exit boundary against the caller's native context on Windows."""
import json
import os
from pathlib import Path
import struct
import subprocess

from rust_entry import states, windows, BASE, PLACEMENT


def main():
    output = subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-vm', '--example', 'leaf_unwind'], text=True)
    instances = [json.loads(line) for line in output.splitlines()]
    assert [row['variant'] for row in instances] == [0, 1, 127, 255]
    reports = []
    for row in instances:
        image = bytearray(65536)
        code = bytes(row['image'])
        image[PLACEMENT:PLACEMENT + len(code)] = code
        records = []
        offset = 0x8200
        assert len(row['exit_ranges']) == len(row['exit_codes']) == 18
        for index, ((begin, end), codes) in enumerate(zip(row['exit_ranges'], row['exit_codes'])):
            table = 0x8000 + index * 12
            struct.pack_into('<III', image, table, PLACEMENT + begin, PLACEMENT + end, offset)
            image[offset:offset + len(codes)] = bytes(codes)
            records.append((BASE + PLACEMENT + begin, BASE + PLACEMENT + end, table, offset))
            offset += len(codes)
        bounds = (records[0][0], records[-1][1])
        snapshots, expected = states(row, image, bounds)
        assert len(snapshots) == 50
        cases = windows(image, snapshots, expected, records) if os.name == 'nt' else []
        reports.append(dict(variant=row['variant'], boundaries=len(snapshots), cases=cases))
    out = Path('target/rust-exit-unwind')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'results.json').write_text(json.dumps(reports, indent=2) + '\n')
    print('PASS:', sum(r['boundaries'] for r in reports), 'live exit boundaries;',
          sum(len(r['cases']) for r in reports), 'Windows unwind/negative comparisons')


if __name__ == '__main__':
    main()
