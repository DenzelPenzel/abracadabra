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
    redirected = sys.argv[-1:] == ['--redirect']
    source, catcher = map(lambda s: Path(s).resolve(), sys.argv[1:-1] if redirected else sys.argv[1:])
    original = pefile.PE(str(source))
    old = records(original)
    assert old, 'fixture must contain an original runtime entry'
    native = next(s.address for s in original.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b'VmOriginal')
    out = Path('target/leaf-pe-redirect' if redirected else 'target/leaf-pe-unwind')
    out.mkdir(parents=True, exist_ok=True)
    results = []
    entry_results = []
    exit_results = []
    for variant in (0, 1, 127, 255):
        path = (out / f'{variant}.dll').resolve()
        row = json.loads(subprocess.check_output(['cargo', 'run', '-q', '-p', 'vmp-emit', '--example',
                        'emit_leaf_pe', '--', str(source), str(path), str(variant)] +
                        (['--redirect'] if redirected else []), text=True))
        pe = pefile.PE(str(path))
        entries = records(pe)
        assert entries[:len(old)] == old and len(entries) == len(old) + 24
        for section in original.sections:
            expected_section = bytearray(section.get_data())
            if redirected and section.VirtualAddress <= native < section.VirtualAddress + section.SizeOfRawData:
                offset = native - section.VirtualAddress
                expected_section[offset:offset + 6] = b'\xe9' + struct.pack('<i', row['entry'] - native - 5) + b'\x90'
            assert pe.get_data(section.VirtualAddress, section.SizeOfRawData) == expected_section
        call_rva = native if redirected else row['entry']
        if redirected:
            gate_bytes = pe.get_data(native, 7)
            assert gate_bytes[0] == 0xe9 and gate_bytes[5:] == b'\x90\xc3'
            assert native + 5 + struct.unpack('<i', gate_bytes[1:5])[0] == row['entry']
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
        exits = [record for record in generated if generated[2][1] < record[0] < gate[0]]
        assert len(exits) == 18 and exits[-1][1] == gate[0]
        for site, (fault, _, unwind) in enumerate(exits):
            for mode in ('normal', 'gate-exit'):
                args = [str(catcher), str(path)] + list(map(str, [base, pe.OPTIONAL_HEADER.SizeOfImage,
                    base + call_rva, directory.VirtualAddress, len(entries), base + fault,
                    base + handler, base + native, unwind, 1, 2])) + [mode, '0', 'pe']
                r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                report = dict(variant=variant, site=site, mode=mode, exit=r.returncode,
                              stdout=r.stdout, stderr=r.stderr)
                exit_results.append(report)
                (out / 'exit-results.json').write_text(json.dumps(exit_results, indent=2) + '\n')
                print(json.dumps(report), flush=True)
                assert r.returncode == 0 and not r.stderr and 'HANDLER:' not in r.stdout
                expected = 'PASS: native normal return' if mode == 'normal' else 'PASS: native exception dispatch'
                assert expected in r.stdout
                if mode != 'normal':
                    assert 'FAULT:' in r.stdout
        assert prefix[0] == 1 and prefix[2:] == bytes([18, 0])
        first_size = 2 if pe.get_data(gate[0], 1) == b'\x41' else 1
        for site, fault in [('first', gate[0]), ('saved-one', gate[0] + first_size),
                            ('allocated', gate[0] + prefix[1]), ('dispatch', gate[1] - 2)]:
            for mode in ('normal', 'gate-fault'):
                args = [str(catcher), str(path)] + list(map(str, [base, pe.OPTIONAL_HEADER.SizeOfImage,
                    base + call_rva, directory.VirtualAddress, len(entries), base + fault,
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
                        base + call_rva, directory.VirtualAddress, len(entries), base + fault,
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
    assert len(exit_results) == 144
    (out / 'entry-results.json').write_text(json.dumps(entry_results, indent=2) + '\n')
    print('PASS: 16 PE entry returns; 16 PE entry exception dispatches without body handler')
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS: 36 PE loader returns; 36 native dispatches; 36 removed-handler negatives')


if __name__ == '__main__':
    main()
