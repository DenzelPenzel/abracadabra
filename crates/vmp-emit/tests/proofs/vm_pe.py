"""Reparse serialized PE artifacts and execute their rebased gate in Unicorn.

Requires pefile==2024.8.26 and unicorn. Not a Windows loader/unwind proof.
Artifacts and their SHA-256 manifest remain in the supplied output directory.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn import x86_const as x

ROOT = Path(__file__).resolve().parents[4]
REGS = [getattr(x, 'UC_X86_REG_' + r) for r in
        ['RAX', 'RCX', 'RDX', 'RBX', 'RBP', 'RSI', 'RDI'] +
        ['R' + str(i) for i in range(8, 16)]]
CASES = [(0, 0, 0, 0x246), (1, 2, 3, 0x206),
         (0xffffffffffffffff, 1, 0, 0x257),
         (0x7fffffffffffffff, 1, 0x8000000000000000, 0xa96),
         (0x8000000000000000, 0x8000000000000000, 0, 0xa47),
         (15, 1, 16, 0x212),
         (0x123456789abcdef0, 0xfedcba9876543210, 0x1111111111111100, 0x207)]


def execute(data, entry_rva, delta, case):
    m = Uc(UC_ARCH_X86, UC_MODE_64)
    stop, rsp = 0x50001000, 0x60010008
    m.mem_map(0x50000000, 0x2000)
    m.mem_write(0x50000000, bytes.fromhex('4889c84801d0c3'))
    entry = 0x50000000
    if data is not None:
        pe = pefile.PE(data=data)
        image = bytearray(pe.get_memory_mapped_image())
        base = pe.OPTIONAL_HEADER.ImageBase + delta
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for fixup in block.entries:
                if fixup.type == 0:
                    continue
                assert fixup.type == 10, 'proof fixture requires DIR64'
                old, = struct.unpack_from('<Q', image, fixup.rva)
                struct.pack_into('<Q', image, fixup.rva, old + delta)
        size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
        m.mem_map(base, size)
        m.mem_write(base, bytes(image))
        entry = base + entry_rva
    m.mem_map(0x60000000, 0x20000)
    m.mem_write(rsp - 4096, b'\x5a' * 4096)
    m.mem_write(rsp, struct.pack('<Q', stop))
    for i, reg in enumerate(REGS):
        m.reg_write(reg, 0x1111000000000000 + i)
    m.reg_write(x.UC_X86_REG_RCX, case[0])
    m.reg_write(x.UC_X86_REG_RDX, case[1])
    m.reg_write(x.UC_X86_REG_RSP, rsp)
    m.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    m.emu_start(entry, stop, count=100000)
    assert m.reg_read(x.UC_X86_REG_RIP) == stop, 'gate must actually return'
    assert m.reg_read(x.UC_X86_REG_RSP) == rsp + 8
    assert bytes(m.mem_read(rsp - 400, 8)) == b'\x5a' * 8
    result = ([m.reg_read(reg) for reg in REGS], m.reg_read(x.UC_X86_REG_EFLAGS))
    assert result[0][0] == case[2] and result[1] == case[3]
    return result


def omit_stream_fixup(data, entry_rva):
    pe = pefile.PE(data=data)
    section = pe.get_section_by_rva(entry_rva)
    gate = pe.get_data(entry_rva, section.VirtualAddress + section.Misc_VirtualSize - entry_rva)
    # The gate initializes RSI with a movabs immediate; omit that serialized record
    assert gate.count(bytes.fromhex('48be')) == 1
    target = entry_rva + gate.index(bytes.fromhex('48be')) + 2
    mutated = bytearray(data)
    matches = 0
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        start = block.struct.get_file_offset() + 8
        for offset in range(start, start + block.struct.SizeOfBlock - 8, 2):
            word, = struct.unpack_from('<H', data, offset)
            if word >> 12 == 10 and block.struct.VirtualAddress + (word & 4095) == target:
                struct.pack_into('<H', mutated, offset, word & 4095)
                matches += 1
    assert matches == 1, 'exactly one persisted stream pointer fixup'
    return bytes(mutated)


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    original = pefile.PE(str(ROOT / 'crates/vmp-pe/test-corpus/win64-app-msvc-amd64'))
    manifest = []
    comparisons = negatives = 0
    for variant in [0, 1, 15, 255]:
        path = output / f'vm-{variant}.exe'
        meta = json.loads(subprocess.check_output([
            'cargo', 'run', '--quiet', '-p', 'vmp-emit', '--example', 'emit_vm_pe',
            '--', str(path), str(variant)], cwd=ROOT, text=True))
        data = path.read_bytes()
        pe = pefile.PE(data=data)
        assert pe.verify_checksum()
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == original.OPTIONAL_HEADER.AddressOfEntryPoint
        section, = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.vmpvm']
        assert section.VirtualAddress == meta['instance_rva']
        assert section.Misc_VirtualSize == meta['instance_len']
        assert section.VirtualAddress <= meta['entry_rva'] < section.VirtualAddress + section.Misc_VirtualSize
        old = {(e.rva, e.type) for b in original.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type}
        new = {(e.rva, e.type) for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type}
        assert old <= new and len(new - old) == 260
        mutant = omit_stream_fixup(data, meta['entry_rva'])
        for delta in [-0x10000, 0, 0x10000]:
            for case in CASES:
                assert execute(data, meta['entry_rva'], delta, case) == execute(None, 0, 0, case)
                comparisons += 1
            if delta:
                try:
                    execute(mutant, meta['entry_rva'], delta, CASES[1])
                except (UcError, AssertionError):
                    negatives += 1
                else:
                    raise AssertionError('omitted serialized fixup escaped the execution oracle')
        manifest.append(dict(meta, path=str(path), sha256=hashlib.sha256(data).hexdigest()))
    manifest_path = output / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    saved = json.loads(manifest_path.read_text())
    assert len(saved) == len({m['variant'] for m in saved}) == 4
    for artifact in saved:
        assert hashlib.sha256(Path(artifact['path']).read_bytes()).hexdigest() == artifact['sha256']
    assert comparisons == 84 and negatives == 8
    print(f'PASS: {len(saved)} serialized PEs, {comparisons} native-oracle comparisons, '
          f'{negatives} omitted-fixup negatives; manifest: {manifest_path}')


if __name__ == '__main__':
    main()
