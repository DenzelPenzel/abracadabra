# Pinned PE fixtures

Six real Windows binaries taken from the C++ reference source tree's own
`test-binaries` set. They are committed here — rather than referenced from
outside the repository — because the suites that use them pin values belonging
to one specific file each: an entry point, an IAT slot address, an export
ordinal, a checksum. No substitute satisfies those assertions, so a corpus that
an ordinary checkout does not carry means those tests pass vacuously.

| Fixture | What it is | What it pins |
|---|---|---|
| `win32-app-test1-i386` | PE32 EXE, no relocations | C++ `open_exe` expectations: sections, three import libraries with their IAT slots |
| `win32-dll-test1-i386` | PE32 DLL, forwarder exports | C++ `open_dll` expectations: export names/ordinals, the twelve `HIGHLOW` fixups; the `HeaderDirectoryOverlapsSlot { directory: 11 }` refusal |
| `win64-app-msvc-amd64` | PE32+ EXE, MSVC | entry point, image base, section table; checksum `0xb8c9` against `os::FileGetCheckSum`; relocation and unwind rewrite |
| `win32-app-delphi-i386` | PE32 EXE, Delphi | checksum `0xe4490`; the `SectionHeaderSlotNotEmpty` refusal |
| `seh-x64` | PE32+ with `.pdata` | exception-table rewrite over real unwind data |
| `seh-x86` | PE32, legacy load config | load config whose internal `Size` exceeds the directory entry |

## Which variable points here

`VMP_TEST_BINARIES_DIR` overrides this directory for the pinned suites
(`corpus.rs`, `cpp_parity.rs`, `writer.rs`). It is deliberately **not**
`VMP_CORPUS_DIR`: that one redirects the property sweeps
(`corpus_sweep.rs`, `robustness.rs`) at an arbitrary set of PEs — CI points it at
freshly linked MSVC probes — and sharing it would silently disable every pinned
value above.

`VMP_REQUIRE_TEST_BINARIES=1` turns a missing fixture into a failure instead of
a skip. CI sets it in every job, so a fixture deleted from this directory is a
red build rather than a quiet loss of coverage.
