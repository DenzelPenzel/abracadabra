# Scalar native gate proof

`instance::NativeInstance` generates entry, body processor and exit in one placed
image. The native gate receives no output pointer or synthetic operands. An outer
SysV test probe seeds guest GPRs, CALLs the gate through stack-held metadata and
observes the state only after the gate RETs. This probe is test-only.

## Frame relative to gate-entry RSP S

| Region | Address range |
|---|---|
| Original native continuation | `[S, S+8)` |
| Saved context in instance slot order | `[S-128, S)` |
| VM stack maximum live operands | `[S-144, S-128)` |
| Scratch gap | `[S-256, S-144)` |
| Body context, addressed by native RSP | `[S-384, S-256)` |
| Temporary PUSHF word | `[S-392, S-384)` |

Entry emits inverse-slot-order PUSH/PUSHF before clobbering any guest register. RBP
captures S-128; SUB RSP,256 reserves the context and VM-stack area. MOV copies the
saved values into the low context. Instance-owned absolute addresses initialize
stream/table/end registers. Exit copies the modified context back, sets RSP=RBP,
POPs in slot order and RETs. POP/POPF/RET do not overwrite the restored arithmetic
flags. Frame copy is a Rust adaptation to the existing body interface, not a
byte-exact C++ entry translation. Original anchors and captured exit observations:
local `docs/proofs/cpp-add-emulator/native-gate-boundary.md`.

## Executed evidence

- API RED: `cargo test -p vmp-vm --test native_gate` failed with missing NativeInstance
- API GREEN: one test validates generation for all 256 recipes
- `cargo test --target x86_64-apple-darwin -p vmp-vm --test native_gate_cpu`
- Same native test with `--release`

Both native runs passed the one test covering all 256 recipes and seven literal
MOV/ADD arithmetic cases. Execution is x64 machine-code execution under Rosetta,
not Windows execution or bare x64 hardware. Checks cover all 15 GPRs, arithmetic
flags, IF=1/DF=0 for the seeded case, pre/post-call RSP and stack-depth witnesses.
The budget includes an additional eight-byte CALL continuation when measured from
the outer pre-call RSP. A live first-POP mutation RAX→RCX is detected by the outer
observation. Original emitted code is never left mutated: only a test mapping's
buffer is changed before its RX publication.

Mapping is test-owned RW→RX→unmap; output storage remains live across the call.
The Linux/macOS x64 cfg means this test reports zero on ARM and Windows. Linux
execution has not been performed locally. A future x64 Ubuntu workspace CI run
will execute it; this document does not claim such a run occurred.

Mandatory workspace debug/build/fmt/Clippy/rustdoc/diff checks, workspace release,
x64-macOS Clippy (including the native probe), Windows cross-Clippy and the existing
body Unicorn tests passed after the gate change. Prior native differential suites
also passed in debug and release. Independent review of the new gate found no
High/Medium correctness defects and independently reran native_gate and
native_gate_cpu under Rosetta in debug: one passing test in each suite.

The subsequent tests-only closure adds execution of original instruction bytes plus
RET as the native oracle, with identical inputs and post-return state comparison:

- MOV-only across all 256 recipes and eight arithmetic-flag patterns
- MOV/ADD across every ordered pair of 15 GPRs, including aliases, and 16 context rotations
- Three 256-body compositions (MOV-only, ADD-only, alternating) across all 256 recipes
- Live entry PUSHF to PUSH RAX mutation with benign RAX=0x202, preserving frame size
- Successful generation at the 256-body boundary alongside the existing 257-body refusal

Independent tests review found no actionable findings and closed the prior Low
coverage gaps in this bounded scope. Its debug run passed two instance tests and
four native_gate_cpu tests under Rosetta; parent release passed all four CPU tests.
Parent workspace debug/release, build, fmt, Clippy, cross-Clippy and rustdoc passed.
An additional parent debug/Unicorn repeat was consent-blocked and was not retried;
the reviewer's independently dispatched debug execution is separate evidence.
IF/DF remain fixed at IF=1/DF=0, the register-pair matrix is not crossed with all
256 opcode recipes, and the canary checks a boundary word, not arbitrary corruption.

## Excluded contracts

No cryptors, arbitrary guest streams, memory operands, SIMD/FP state proof, active TF,
exception delivery, unwind tables, Windows loader/ABI proof, PE embedding or native
entry patching. Unmodified bounded compiler output and a valid writable native stack
are preconditions; the trap instruction is not a recoverable production status API.
The original C++ tree and old runtime/Mutation proof subjects are unchanged.
