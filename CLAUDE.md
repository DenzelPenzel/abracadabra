# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A ground-up Rust rewrite of the VMProtect 3.5.1 executable protector. Host platform is
macOS on Apple Silicon, the first and only target is Windows x64 PE, and the interface is
a CLI (`vmp`).

The original C++ tree sits one level up: `../core/` (the protector), `../runtime/`,
`../unit-tests/`, `../test-binaries/`. It is **technical documentation and a behavioural
oracle, never a build dependency** — it is not compiled, not patched, and no C++ ships in
the product. Byte-for-byte compatibility with VMProtect output is explicitly out of scope.

Two protection modes are planned. `Mutation` is functionally closed end to end (select →
decode → mutate → append section → atomic publish, with a real Windows execution gate).
`Virtualization` is the work in progress: `vmp-vm` has versioned bytecode v1, a bounded
host reference interpreter and native-IR lowering for a narrow instruction subset, but
none of it is wired into the production pipeline yet.

`docs/` is deliberately **untracked** (blanket `docs` entry in `.gitignore`) yet
authoritative locally. `docs/plans/RUST_REWRITE_PLAN.md` (Russian) is the source of truth
for stage status and the current next slice; `docs/adr/` holds the binding architecture
decisions. Read the plan before starting a slice — the status paragraphs below go stale,
the plan does not. Do not propose tracking `docs/`; that has been decided.

Because of that, the durable facts and traps extracted from those catalogues live in the
tracked `PORTING-NOTES.md` at the repo root, indexed below.

## Commands

```bash
cargo build --workspace
cargo test --workspace --all-targets                  # debug; CI also runs --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
git diff --check                                      # CI rejects whitespace errors
```

Those six are the mandatory local gate after every finished slice; run them together, not
just the touched crate.

Narrowing a run:

```bash
cargo test -p vmp-vm --all-targets                    # one crate
cargo test -p vmp-vm --test lowering                  # one integration test file
cargo test -p vmp-vm --test lowering -- --list        # names in that file
cargo test -p vmp-vm --test native_differential -- native_shl   # by name substring
cargo test -p vmp-pe --lib                            # only the unit tests inside src/
```

### Tests that compile to nothing on this host

Five test files are `cfg`-gated away on macOS/arm64 and report `0 tests`, so a green local
run says nothing about them:

- `#![cfg(windows)]` — `vmp-pe/tests/windows_loader.rs`, `vmp-emit/tests/windows_mutation.rs`,
  `vmp-cli/tests/windows_sdk.rs`, `vmp-cli/tests/windows_symbol.rs`.
- `#![cfg(target_arch = "x86_64")]` — `vmp-vm/tests/native_differential.rs`.

```bash
# Typecheck the Windows gates without a linker or Windows SDK.
# Needs dangerouslyDisableSandbox: the sandbox blocks ~/.rustup and ~/.cargo/registry writes.
cargo clippy --workspace --all-targets --all-features \
  --target x86_64-pc-windows-msvc -- -D warnings

# Actually execute the asm! CPU oracle under Rosetta 2 — real flags, not just a typecheck.
# This prints the same `test result: ok. N passed` line the CI gate greps for.
cargo test --target x86_64-apple-darwin -p vmp-vm --test native_differential
```

Producing a Windows *binary* is out of reach locally (linking needs MSVC import
libraries), so anything that depends on linker output must print the evidence it branches
on, to be read from a CI log.

`vmp-cli` `tests::successful_publication_preserves_existing_destination_permissions` fails
on this machine on `main` too — setuid/setgid bits do not survive locally. Re-run it on
`main` before blaming a branch; do not "fix" or silence it.

### Test corpus and environment variables

`crates/vmp-pe/test-corpus/` holds six committed real Windows binaries; each pinned
assertion belongs to one specific file (an entry point, an IAT slot, an export ordinal, a
checksum). See its `README.md` for the fixture-to-assertion table.

Two variables point at binaries and must not be conflated:

| Variable | Consumers | Meaning |
|---|---|---|
| `VMP_TEST_BINARIES_DIR` | `vmp-pe/tests/{corpus,cpp_parity,writer}.rs`, `vmp-x86/tests/corpus.rs`, `vmp-emit/tests/protect.rs` | overrides the **pinned** fixture directory |
| `VMP_CORPUS_DIR` | `vmp-pe/tests/{corpus_sweep,robustness}.rs` | points the **property sweeps** at an arbitrary set of PEs (CI: freshly linked MSVC probes) |

`VMP_REQUIRE_TEST_BINARIES=1` / `VMP_REQUIRE_CORPUS=1` turn a missing fixture into a
failure instead of a skip; CI sets both in every job, so a deleted fixture is a red build
rather than a quiet loss of coverage. `VMP_LOADER_PROBE_EXTRA` and `VMP_SDK_*_PROBE` name
CI-built probe executables for the Windows gates.

## Architecture

Dependencies point outward-to-inward; low-level crates never know about the CLI or a
config format.

```text
vmp-cli ──> vmp-compiler ─┬─> vmp-emit ──> vmp-runtime-windows
  (plus vmp-pe/vmp-x86/   ├─> vmp-mutation
   vmp-ir directly, for   ├─> vmp-symbols ──> vmp-pdb, vmp-demangle
   inspect and disasm)    ├─> vmp-x86 ──> vmp-ir
                          └─> vmp-pe

vmp-vm ──> vmp-ir, vmp-x86   implemented, deliberately not yet reachable from vmp-compiler
every crate ──> vmp-types    typed addresses, architecture, protection mode
```

The boundaries that are easy to get wrong:

- **`vmp-pe` serialises bytes; `vmp-emit` decides which bytes.** `vmp-pe` is a
  bounds-checked parser + append-only writer (headers, sections, imports/exports,
  relocations, TLS, exception directory, checksum). `vmp-emit` is the backend that
  *generates* the content of new sections: trampolines, entry patches, layout, runtime-blob
  integration, SDK-marker excision. In the original both live tangled inside
  `core/intel.cc`; keeping them apart is deliberate.
- **`vmp-x86` builds the raw graph; `vmp-ir` owns it.** `vmp-x86` decodes/encodes (via
  iced-x86), builds basic blocks and edges, and adds what the library does not cover:
  liveness, a value/flag model, epilogue analysis, relocation round-tripping, SDK-marker
  scanning. The persistent function/block/edge model that `vmp-mutation` and `vmp-vm`
  consume lives in `vmp-ir`.
- **`vmp-vm` lowers; `vmp-runtime-windows` interprets.** Per ADR-0002 the MVP is *variant
  A*: one fixed interpreter and one opcode set for every file. Opcode handlers are **not**
  generated in `vmp-vm` — it only lowers native IR into fixed-format bytecode v1
  (ADR-0003). Variant B (per-file polymorphic handler generation, shuffled opcodes,
  encrypted stream — what the C++ actually does) comes after end-to-end Virtualization and
  will move codegen here. That variant A is knowably weaker protection is a recorded MVP
  limitation, not a defect.
- **`vmp-compiler` owns orchestration; `vmp-cli` is an adapter.** `protect_mutation`
  owns explicit/symbol/SDK/exception selection, dedup, emission and typed domain errors.
  The CLI does bounded IO, atomic publication and rendering — no library logic in commands.
- **`vmp-mutation`** is native IR → equivalent native IR. Junk is not random bytes: it
  writes only to registers and flags proven dead by the liveness analysis, and every
  rewrite has a local equivalence test and a fixed seed.

`vmp-demangle` (MSVC, GNU v3, Borland) and `vmp-pdb` are self-contained ports with no
workspace dependencies; `vmp-symbols` unifies PE-resident symbols, MAP and PDB on top of
them. There is no workspace-level `tests/` directory — all tests are crate-local.

### CLI surface

```text
vmp inspect <input.exe> [--json]
vmp validate <input.exe>
vmp disasm  <input.exe> [--rva <rva>] [--liveness] [--json]
vmp protect <input.exe> --output <out.exe>
            [--rva <rva>... | --symbol <name> [--symbol-index <n>]]
            [--seed <u64>] [--json]
```

Without an explicit selector, `protect` prefers SDK markers over the exception-directory
sweep. Omitting `--seed` draws one from the system CSPRNG and reports it, so any run can
be replayed byte-exactly. JSON output is a stable versioned contract: results to stdout,
errors to stderr.

## Implementation rules

- Library crates return typed `thiserror` errors; the CLI adds `anyhow` context without
  hiding the cause. No `unwrap()` on input data (`clippy::unwrap_used` is a workspace lint
  and CI runs `-D warnings`).
- `Rva`, `FileOffset`, `VirtualAddress` and `ImageBase` are distinct types and are never
  mixed as plain integers.
- Fail closed. Unrecognised or unsupported input (unusual unwind data, Control Flow Guard, an
  instruction outside the supported subset) produces a clear typed refusal **before** anything is written —
  never a silently corrupted file. Parsers state endianness explicitly and check overflow.
- Business-critical enums get exhaustive `match`, no wildcard arm.
- Target architecture is always passed explicitly; host `cfg(target_arch)` never decides
  anything about the file being processed.
- `unsafe_code` is a workspace lint. Every site that needs it opts in with a narrow
  `#[allow(unsafe_code)]` and a `SAFETY` comment stating the invariants; it is concentrated
  in `vmp-runtime-windows` and the OS-calling test gates. `vmp-pdb` uses
  `#![forbid(unsafe_code)]`. Never use `unsafe` to work around the borrow checker.
- Tests use an explicit deterministic seed; production randomness comes from the system
  CSPRNG.
- Comments are complete sentences with no trailing period. `rustfmt.toml`: edition 2021,
  `max_width = 100`.

## Three traps that bite regardless of layer

Full reasoning, measurements and the C++ anchors for all three are in `PORTING-NOTES.md`;
these three are inline because they corrupt output silently and are easy to reintroduce.

- **`undefined` is not a write.** Every eighth instruction in the corpus leaves at least one
  flag undefined. `dead(flag) = definitely_written AND NOT read_before_that_write`, and an
  undefined write does not count. Use `rflags_read()`, `rflags_written()` **and**
  `rflags_undefined()` — the C++ merges the last two into one `change_flags`, so its
  liveness decisions are not a safe oracle here. Shifts with `cl == 0` touch no flags at
  all, so statically they "may not write" and the old value stays live.
- **Re-encoding is not byte-exact.** `BlockEncoder` picks the shortest form: 41 of 5495
  corpus instructions change size when re-encoded to the same address. Never take a
  post-mutation address from anywhere but `Relocated::moved` / `new_instruction_offsets`.
- **The prologue is frozen on purpose, and that is stricter than the C++.** A faithful port
  would silently corrupt stack unwinding, because C++ never recomputes prologue
  `UNWIND_CODE` offsets. Do not "fix" `SkipReason::PrologueMoved` by copying it.

## Which reference section applies

`PORTING-NOTES.md` is the tracked catalogue of what was ported from the C++, what
deliberately diverges, and what is measured rather than assumed. Read the matching section
before changing behaviour in that layer — several of the divergences look like bugs.

| Working in | Read first |
|---|---|
| `vmp-x86` | §1 — flag semantics, liveness, re-encoding |
| `vmp-mutation` | §2 — the four rewrites and their side conditions, junk selection rule |
| `vmp-pe` | §3 — coordinate traps, why the append-only writer refuses, writer divergences |
| `vmp-emit` | §4 — prologue freeze, block placement, why the allocator is not worth porting |
| `vmp-vm` | §5.1 — the flag/termination comparison discipline a lowering slice must satisfy |
| `vmp-runtime-windows` | §5.2 — the C++ VM's register context, untyped stack and address-baked dispatch |
| any of them | `## Open decisions` — six questions that are the owner's call, not yours |

## How work is sequenced

Every legacy layer is ported in this order, and it is a proof gate, not a suggestion:

1. Understand one C++ layer.
2. Pin its observable behaviour with tests.
3. Port that layer to Rust.
4. Compare Rust against C++.
5. Only then move to the next layer.

Step 4 must compare observable semantics — results, state, errors, boundaries — against
exact `core/*.cc:line` anchors, independently pinned golden values, or a native oracle. A
shared-oracle round trip where a Rust producer and a Rust consumer repeat the same mistake
does not count as comparison. Never assert a C++ fact from memory or a subagent's report:
quote `file:line` from `../core/` first.

Where the Rust contract is **deliberately stricter** than the C++ (bounds, checked
arithmetic, fail-closed refusals, atomic publication, refusing to move a prologue whose
`UNWIND_CODE` offsets would go stale), that is recorded in the plan/ADR with negative
tests. Do not "fix" such a divergence by copying the C++ — several would corrupt real
binaries.

Slices land as RED→GREEN commit chains, visible in `git log`: `test(vm): pin the X wire
encoding and its typed decode failures` → `feat(vm): add X to the bytecode and the host
interpreter` → `test(vm): cover X across the lowering matrix` → `test(vm): compare X
against the native x64 flags` → `ci: require N passing native VM differential tests`.

That last step matters: `.github/workflows/ci.yml` greps the differential suite's summary
line for an **exact** test count (`11 passed; 0 failed; …`) and throws otherwise. Adding
or removing a test in `vmp-vm/tests/native_differential.rs` therefore requires bumping the
regex in the same change, and a Windows-executed CI run is the only proof that counts for
those gates.
