"""Observe native exit exception delivery with original exit bytes restored before SEH search."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys

from native_dispatch import prepare
from snapshot import exit_snapshots, replay, REGS


def main():
    out = Path('target/cpp-exit-dispatch')
    out.mkdir(parents=True, exist_ok=True)
    rows = prepare(out)
    sites = {}
    for variant, _, _, site, data, uc in exit_snapshots():
        if site != 'popf':
            continue
        pc = uc.reg_read(REGS['rip'])
        trace = []
        replay(data, 1, 2, trace=trace)
        assert Counter(address for address, _ in trace)[pc] == 1
        sites[variant] = pc
    assert set(sites) == {'classic', 'advanced'}
    for row in rows:
        row['fault'] = sites[row['variant']]
    (out / 'inputs.json').write_text(json.dumps(rows, indent=2) + '\n')
    if len(sys.argv) == 1:
        print('PASS: 2 single-use original C++ POPF fault sites')
        return
    assert os.name == 'nt' and len(sys.argv) == 2
    reports = []
    for row in rows:
        for mode in ('normal', 'exit-fault'):
            args = [str(Path(sys.argv[1]).resolve()), row['image']] + [str(row[k]) for k in
                    ('base', 'size', 'entry', 'pdata', 'count', 'fault', 'handler', 'native_rip', 'unwind')]
            result = subprocess.run(args + ['1', '2', mode], capture_output=True, text=True, timeout=30)
            report = dict(variant=row['variant'], mode=mode, exit=result.returncode,
                          stdout=result.stdout, stderr=result.stderr)
            reports.append(report)
            print(json.dumps(report), flush=True)
            (out / 'results.json').write_text(json.dumps(reports, indent=2) + '\n')
            assert not result.stderr, 'harness failure is not an exit-unwind diagnosis'
            if mode == 'normal':
                assert result.returncode == 0 and 'PASS: native normal return' in result.stdout
            else:
                assert 'FAULT:' in result.stdout and 'HANDLER:' in result.stdout
                if result.returncode == 0:
                    assert 'PASS: native exception dispatch' in result.stdout
                else:
                    assert result.returncode == 21 and 'HANDLER_AV:' in result.stdout
                    assert 'PASS:' not in result.stdout
    assert len(reports) == 4
    print('PASS: 2 native normal returns; 2 classified exit exception outcomes')


if __name__ == '__main__':
    main()
