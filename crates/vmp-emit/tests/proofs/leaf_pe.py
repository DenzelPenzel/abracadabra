"""Exercise persisted PE unwind through LoadLibrary, not dynamic tables."""
if not __debug__:
    raise RuntimeError('proof requires assertions')
import json
from pathlib import Path
import struct
import subprocess
import sys
import pefile


def records(pe):
    return [(x.struct.BeginAddress, x.struct.EndAddress, x.struct.UnwindData)
            for x in pe.DIRECTORY_ENTRY_EXCEPTION]


def main():
    source, catcher = map(lambda s: Path(s).resolve(), sys.argv[1:])
    original = pefile.PE(str(source))
    old = records(original)
    assert old, 'fixture must contain an original runtime entry'
    native = next(s.address for s in original.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b'VmOriginal')
    out = Path('target/leaf-pe-unwind')
    out.mkdir(parents=True, exist_ok=True)
    results = []
    entry_results = []
    for variant in (0, 1, 127, 255):
        path = (out / f'{variant}.dll').resolve()
        row = json.loads(subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-emit', '--example',
                        'emit_leaf_pe', '--', str(source), str(path), str(variant)], text=True))
        pe = pefile.PE(str(path))
        entries = records(pe)
        assert entries[:len(old)] == old and len(entries) == len(old) + 6
        for section in original.sections:
            assert pe.get_data(section.VirtualAddress, section.SizeOfRawData) == section.get_data()
        assert pe.OPTIONAL_HEADER.CheckSum == pe.generate_checksum()
        generated = entries[len(old):]
        section = pe.get_section_by_rva(row['instance'])
        code = pe.get_data(row['instance'], generated[2][1] - row['instance'])
        assert code.count(bytes.fromhex('48034508')) == 1
        pop = code.index(bytes.fromhex('9c8f4500')) + 1 + row['instance']
        assert generated[1][:2] == (pop, pop + 3)
        handler = struct.unpack('<I', pe.get_data(generated[0][2] + 16, 4))[0]
        base = pe.OPTIONAL_HEADER.ImageBase
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        gate = next(record for record in generated if record[0] == row['entry'])
        prefix = pe.get_data(gate[2], 4)
        assert prefix[0] == 1 and prefix[2:] == bytes([18, 0])
        first_size = 2 if pe.get_data(gate[0], 1) == b'\x41' else 1
        for site, fault in [('first', gate[0]), ('saved-one', gate[0] + first_size),
                            ('allocated', gate[0] + prefix[1]), ('dispatch', gate[1] - 5)]:
            for mode in ('normal', 'gate-fault'):
                args = [str(catcher), str(path)] + list(map(str, [base, pe.OPTIONAL_HEADER.SizeOfImage,
                    base + row['entry'], directory.VirtualAddress, len(entries), base + fault,
                    base + handler, base + native, gate[2], 1, 2])) + [mode, '0', 'pe']
                r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                print(variant, site, mode, r.returncode, r.stdout, r.stderr, flush=True)
                assert r.returncode == 0 and not r.stderr and 'HANDLER:' not in r.stdout
                expected = 'PASS: native normal return' if mode == 'normal' else 'PASS: native exception dispatch'
                assert expected in r.stdout
                if mode == 'gate-fault':
                    assert 'FAULT:' in r.stdout
                entry_results.append(dict(variant=variant, site=site, mode=mode,
                                          exit=r.returncode, stdout=r.stdout, stderr=r.stderr))
        for site, fault, bias in [('add', row['instance'] + code.index(bytes.fromhex('48034508')), 0),
                                  ('flags-pop', pop, 8), ('after-pop', pop + 3, 0)]:
            unwind = next(u for start, end, u in generated if start <= fault < end)
            for lhs, rhs in ((1, 2), (0, 0), (0xffffffffffffffff, 1)):
                for mode in ('normal', 'fault', 'no-handler'):
                    args = [str(catcher), str(path)] + list(map(str, [base, pe.OPTIONAL_HEADER.SizeOfImage,
                        base + row['entry'], directory.VirtualAddress, len(entries), base + fault,
                        base + handler, base + native, unwind, lhs, rhs])) + [mode, str(bias), 'pe']
                    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    print(variant, site, mode, r.returncode, r.stdout, r.stderr, flush=True)
                    if mode == 'no-handler':
                        assert r.returncode == 3221225501 and 'FAULT:' in r.stdout and not r.stderr
                        assert 'HANDLER:' not in r.stdout and 'PASS:' not in r.stdout
                    else:
                        assert r.returncode == 0 and not r.stderr
                        assert ('PASS: native normal return' if mode == 'normal' else 'PASS: native exception dispatch') in r.stdout
                    results.append(dict(variant=variant, site=site, lhs=lhs, rhs=rhs, mode=mode,
                                        exit=r.returncode, stdout=r.stdout, stderr=r.stderr))
    assert len(results) == 108
    assert len(entry_results) == 32
    (out / 'entry-results.json').write_text(json.dumps(entry_results, indent=2) + '\n')
    print('PASS: 16 PE entry returns; 16 PE entry exception dispatches without body handler')
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS: 36 PE loader returns; 36 native dispatches; 36 removed-handler negatives')


if __name__ == '__main__':
    main()
