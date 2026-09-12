"""Probe real early-entry faults; exit 21 means observer-stopped secondary AV."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys

from native_dispatch import prepare
from snapshot import artifacts, replay, REGS


def main():
    out = Path('target/cpp-entry-dispatch')
    out.mkdir(parents=True, exist_ok=True)
    rows = prepare(out)
    files, _ = artifacts()
    for row in rows:
        data = files[f"unwind_{row['variant']}_add_protected.exe"]
        trace = []
        replay(data, 1, 2, trace=trace)
        counts = Counter(pc for pc, _ in trace)
        ordinal, (pc, _) = next((i, instruction) for i, instruction in enumerate(trace)
                                if 4 <= i < 20 and instruction[1] >= 2
                                and counts[instruction[0]] == 1)
        uc, events = replay(data, 1, 2, count=ordinal)
        assert not events and uc.reg_read(REGS['rip']) == pc
        row['fault'] = pc
    (out / 'inputs.json').write_text(json.dumps(rows, indent=2) + '\n')
    if len(sys.argv) == 1:
        print('PASS: 2 single-use early-entry fault sites, before shadow initialisation')
        return
    assert os.name == 'nt' and len(sys.argv) == 2
    reports = []
    for row in rows:
        for mode in ('normal', 'entry-fault'):
            args = [str(Path(sys.argv[1]).resolve()), row['image']] + [str(row[k]) for k in
                    ('base', 'size', 'entry', 'pdata', 'count', 'fault', 'handler', 'native_rip', 'unwind')]
            result = subprocess.run(args + ['1', '2', mode], capture_output=True, text=True, timeout=30)
            report = dict(variant=row['variant'], mode=mode, exit=result.returncode,
                          stdout=result.stdout, stderr=result.stderr)
            reports.append(report)
            print(json.dumps(report), flush=True)
            (out / 'results.json').write_text(json.dumps(reports, indent=2) + '\n')
            assert not result.stderr, 'harness failure is not a C++ unwind finding'
            if mode == 'normal':
                assert result.returncode == 0 and 'PASS: native normal return' in result.stdout
            else:
                assert 'FAULT:' in result.stdout and 'HANDLER:' in result.stdout
                assert result.returncode == 21 and 'HANDLER_AV:' in result.stdout
                assert 'PASS:' not in result.stdout
    assert len(reports) == 4
    print('PASS: 2 native normal returns; 2 early-entry secondary AVs (observer-stopped)')


if __name__ == '__main__':
    main()
