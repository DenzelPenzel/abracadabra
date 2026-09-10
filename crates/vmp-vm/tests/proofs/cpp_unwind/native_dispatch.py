"""Select a single-use fault instruction, then run isolated native Windows SEH children."""
from collections import Counter
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pefile
from snapshot import artifacts, replay, verified_image, UNWIND, REGS


def prepare(out):
    files, original = artifacts()
    rows = []
    for variant in ('classic', 'advanced'):
        data = files[f'unwind_{variant}_add_protected.exe']
        pe = pefile.PE(data=data)
        base = pe.OPTIONAL_HEADER.ImageBase
        choices = None
        for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
            trace = []
            uc, events = replay(data, lhs, rhs, trace=trace)
            counts = Counter(pc for pc, size in trace)
            # Completed native prologue shadows precede this interval; the native
            # ADD RSP epilogue update ends it. Shared handler PCs are excluded
            candidates = {pc for pc, size in trace[events[9][2]:events[10][2] - 1]
                          if size >= 2 and counts[pc] == 1}
            choices = candidates if choices is None else choices & candidates
            verified_image(pe, uc)
        entries = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION]
        owners = [e for e in entries if pe.get_data(e.UnwindData, 16) == UNWIND]
        assert len(owners) == 1
        owner = owners[0]
        choices = sorted(pc for pc in choices if owner.BeginAddress <= pc - base < owner.EndAddress - 1)
        assert choices, 'no single-use body fault instruction'
        fault = choices[0]
        handler = base + struct.unpack('<I', pe.get_data(owner.UnwindData + 16, 4))[0]
        # Stop before the selected instruction to bind the intended shadow state
        for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
            trace = []
            replay(data, lhs, rhs, trace=trace)
            ordinal = next(i for i, (pc, _) in enumerate(trace) if pc == fault)
            uc, _ = replay(data, lhs, rhs, count=ordinal)
            assert uc.reg_read(REGS['rip']) == fault
            frame = uc.reg_read(REGS['rsp'])
            assert struct.unpack('<Q', uc.mem_read(frame + 192, 8))[0] == original + 5
        image = pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage, b'\x00')
        path = out / f'{variant}.image'
        path.write_bytes(image)
        rows.append({'variant': variant, 'image': str(path.resolve()), 'base': base,
                     'size': len(image), 'entry': base + pe.DIRECTORY_ENTRY_EXPORT.symbols[0].address,
                     'pdata': pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress,
                     'count': len(entries), 'fault': fault, 'handler': handler,
                     'native_rip': original + 5, 'unwind': owner.UnwindData})
    (out / 'native-dispatch-inputs.json').write_text(json.dumps(rows, indent=2) + '\n')
    return rows


def main():
    out = Path('target/cpp-native-dispatch')
    out.mkdir(parents=True, exist_ok=True)
    rows = prepare(out)
    if len(sys.argv) == 1:
        print('PASS: 2 unique fault sites verified across 6 C++ replays; native execution not requested')
        return
    assert os.name == 'nt'
    executable = str(Path(sys.argv[1]).resolve())
    reports = []
    for row in rows:
        for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
            for mode in ('normal', 'fault', 'no-handler'):
                args = [executable, row['image']] + [str(row[k]) for k in
                       ('base', 'size', 'entry', 'pdata', 'count', 'fault', 'handler', 'native_rip', 'unwind')]
                result = subprocess.run(args + [str(lhs), str(rhs), mode], capture_output=True,
                                        text=True, timeout=30)
                print(row['variant'], lhs, rhs, mode, result.returncode, result.stdout, result.stderr, flush=True)
                if mode == 'normal':
                    assert result.returncode == 0 and 'PASS: native normal return' in result.stdout
                elif mode == 'fault':
                    assert result.returncode == 0 and 'PASS: native exception dispatch' in result.stdout
                    assert 'FAULT:' in result.stdout and 'HANDLER:' in result.stdout
                else:
                    assert result.returncode != 0 and 'FAULT:' in result.stdout
                    assert 'HANDLER:' not in result.stdout and 'PASS:' not in result.stdout
                reports.append({'variant': row['variant'], 'lhs': lhs, 'rhs': rhs, 'mode': mode,
                                'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    assert len(reports) == 18
    (out / 'results.json').write_text(json.dumps(reports, indent=2) + '\n')
    print('PASS: 6 native returns; 6 native exception dispatches; 6 removed-handler negatives')


if __name__ == '__main__':
    main()
