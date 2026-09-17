# Composed scalar SUB: mechanism and proof boundary

## Production contract

Only ordinary qword register SUB, both opcode directions, joins the existing
MOV/ADD scalar-leaf path. No native SUB VM primitive, bytecode version, general
interpreter, LOCK/memory form, non-leaf function or control-flow support is added.

`logical.rs` emits the 29-command all-NOR branch of the original decomposition:
source, destination twice, NOR, discarded flags, ADD and EFX capture, stack-pointer
capture and dereference, NOR and EIX capture, destination write, then two masks and
ADD to combine flags. P/O/A/C come from the ADD's EFX; the other bits come from the
final inversion's EIX. The NOR handler executes NOT, NOT, AND, so its flags describe
the inverted result. Undefined AF from that AND is not used as SUB's AF.

All-NOR is one deterministic choice already present in C++, not the full randomized
NOR/NAND lowering catalogue. The instance still owns handlers, opcode permutation,
context slots, cryptors, stream and relocation fields together. Native host models
and Python emulators remain proofs, not embedded runtime implementations.

## Source anchors and independent captures

Original `core/intel.cc`:

- 10053–10074: ordinary SUB/CMP decomposition and EFX/EIX merge mask
- 9674–9687, 9733–9741: register operands and duplicated-operand inversion
- 8735–8761: automatic flag-word disposal for `need_pushf = false`
- 8916–8933, 8947–8952: masking through NOR/NAND and combining disjoint flags
- 29148–29169, 28920–28950: pre-push VM SP capture and address dereference
- 29200–29214, 29230–29246: ADD and NOR results below raw flags
- 28892–28917, 27793–27824: one width-sized immediate field, fetch/decrypt/key update
- 30564–30582: compiler-side inverse transforms and key update from plaintext
- 28734–28744: loaded stream pointer minus a relocated-zero delta initializes the key

The last mechanism is also visible in the captured Classic native trace in the local
`docs/proofs/cpp-add-emulator/classic_add_trace.txt:135–140`: MOV RDI,RSI;
MOV R8,0; SUB RDI,R8. It is not a license to count this as a new C++ SUB PE execution.

`cpp_sub.py` compiles verbatim source fragments with a qword-GPR operand adapter,
argument-recording sink and deterministic existing all-NOR branches. Its actual
output is pinned in `../fixtures/cpp_sub_qword.txt`. The capture is **source-extracted
execution**, not the complete original compiler, processor generator or PE runtime.
The initial Rust regression failed on `BinaryOp::Sub` before the implementation changed.

`cpp_qword.py` compiles the original `ValueCommand`, `ValueCryptor::Init`, forward/inverse
transform and `OpcodeCryptor` methods with container/intrinsic adapters. Controlled RNG
choices select a qword DEC/NOT/ROR17/INC recipe through the original generator rather
than widening a Rust byte recipe. The ten ciphertext/key observations in
`../fixtures/cpp_qword_cryptor.txt` pin two distinct 64-bit starting keys.

Qword sources: `core/processors.h:391–403`, `core/processors.cc:562–665,693–758,775–813`.

Captured original-source SHA-256:

- `intel.cc`: `51329b44406a5077943ee31f83490d10d7112e7b0b62c88a00dfa9a819362cb4`
- `processors.cc`: `d74e623e29459753ef97a03e9237001f78f378a104e52358ca430e505f0d089e`
- `processors.h`: `91397aa95fce5986830f85ac0ecef006b3dea17c519db9ce0fec11933bfee505`

Reproduce capture and compare without changing the pinned fixtures or original sources:

```sh
python3 crates/vmp-vm/tests/proofs/cpp_sub.py --check crates/vmp-vm/tests/fixtures/cpp_sub_qword.txt
python3 crates/vmp-vm/tests/proofs/cpp_qword.py --check crates/vmp-vm/tests/fixtures/cpp_qword_cryptor.txt
```

These are maintainer commands requiring the sibling C++ tree and clang++; ordinary
Rust builds and CI consume only the pinned text and never build/link the legacy tree.

## Full-width fields and relocation

The native immediate handler reads one qword, XORs the full rolling key, executes
DEC/NOT/ROR17/INC, and XORs the full plaintext into the key once. The producer runs
inverse transforms in reverse order and mixes the pre-field key. A regression first
failed with eight field loads; another failed for the missing qword cryptor. Both
now require the full-width path. Opcode/register fields retain their byte recipes.

The encrypted gate copies the loaded stream pointer into RDI, loads the zero-valued
DIR64 relocation field into RAX, and subtracts it. The resulting key is the preferred
stream VA at every tested loader base. The zero field is a relocation delta, not a
pointer into the generated image. Negative deltas use the PE loader's modulo-64-bit
addition. The old requirement that only low-byte-equivalent rebases preserve the
key is no longer the mechanism. Regeneration at a different preferred base and
loader relocation are distinct operations.

## Frame and unwind

The complete sequence peaks at 24 operand bytes, not the direct handler's 16.
EIX occupies context+128. Shadows remain at context+192 through context+239;
SUB reserves 272 scratch bytes so operand pushes cannot reach those shadows.
MOV/ADD keep 256 scratch bytes. Entry and exit metadata describe the corresponding
reservation; the body callback's 208-byte shadow-based unwind allocation is unchanged.
Both ADD and NOR PUSHFQ/POP windows have separate shifted unwind ranges.

The entry key-normalization sequence has two additional instructions: each layout
now has 70 observed entry boundaries, 280 over the four layouts. Exit remains 200.

## Executed proof surfaces

- `tests/logical.rs`: exact extracted sequence, all GPR pairs, aliases and opcode directions
- `tests/native_stack.rs`: original physical SUB at all four widths versus the composed
  primitive sequence, retaining the independent ADD/SHL oracles and raw flag checks
- `tests/native_gate_cpu.rs`: original x64 versus generated plain/encrypted and rebased
  execution, GPR/flags/RSP/canaries, all pairs and 256-instruction compositions
- `sub_instance.py`: 512 plain/encrypted instances; C++ command order, intermediate
  operands/flags, stack boundaries and every physical field/cursor/full-key transition;
  negatives change NOR, discard, SP capture, merge mask, qword key width and rotation
- `cpp_unwind/sub_shadows.py`: 2552 live SUB processor boundaries and four actual
  smaller-frame mutations, requiring live shadows to remain intact
- `vmp-emit/tests/proofs/vm_pe.py --sub`: four persisted PEs, preferred base and ±64 KiB,
  84 original/generated comparisons and 16 missing stream/delta relocation negatives
- CLI publication test: ADD and SUB inputs, deterministic output, original-RVA gate,
  and preservation of an existing destination on an unsafe-entry refusal

```sh
cargo test -p vmp-vm --all-targets
cargo test --target x86_64-apple-darwin -p vmp-vm --test native_stack --test native_gate_cpu
cargo test --release --target x86_64-apple-darwin -p vmp-vm --test native_stack --test native_gate_cpu
python3 crates/vmp-vm/tests/proofs/sub_instance.py
python3 crates/vmp-vm/tests/proofs/cpp_unwind/sub_shadows.py
python3 crates/vmp-emit/tests/proofs/vm_pe.py target/vm-sub-pe-proof --sub
```

## Final local verification

The corrected qword/rebase snapshot passed the complete workspace build, debug tests,
format check, strict all-target/all-feature Clippy, strict all-feature rustdoc and
`git diff --check`. Workspace release tests also passed with
`VMP_REQUIRE_TEST_BINARIES=1 VMP_REQUIRE_CORPUS=1`. Windows-target all-target/all-feature
Clippy passed; it typechecks the gated paths without executing the Windows loader.

Both Rosetta profiles executed exactly four `native_gate_cpu` tests and three
`native_stack` tests. Both C++ capture `--check` commands passed against the pinned
fixtures and the source hashes above. Body and encrypted-instance emulator suites
passed four tests each, and the composed-SUB suite passed seven. The persisted ADD
control also passed 84 comparisons and eight missing-fixup negatives.

The entry/exit scripts reproduced 280/200 boundaries for both ADD and SUB. Their
macOS output explicitly reports **zero Windows unwind/negative comparisons**.
Generated observations remain in `target/rust-sub-shadows/results.json`,
`target/rust-{entry,exit}-unwind{-sub,}/results.json`, and the persisted PE manifests
in `target/vm-pe-proof/` and `target/vm-sub-pe-proof/`.

## Independent review

The bounded follow-up review accepted the fixed qword recipe and preferred-base key
recovery without P1/P2 findings. The reviewer independently read the original C++
generator, inverse transforms, producer/handler and DIR64/rebase path, compared the
Rust implementation and fixtures, and executed `cpp_qword.py --check` successfully.
This closes the earlier source-inspection gap caused by an approval timeout.

The reviewer did not execute Cargo, native, Unicorn or Windows gates; the local
execution results above belong to the primary verification run. The verdict is not
acceptance of the full randomized generator or complete C++ compiler/PE execution.

## Windows execution

The [Windows workflow](https://github.com/DenzelPenzel/abracadabra/actions/runs/35273113779)
passed on `db202f2ec2b5e055233ce693a8b9a8c8b4a0c9a7`. It built a separate SUB
fixture and subtraction catcher, published the protected PE through the CLI, and
executed it with the Windows loader and native exception dispatcher.

The downloaded SUB observations contain exactly:

- 280 positive entry metadata walks and 276 removed-metadata negatives
- 200 positive exit metadata walks and four removed-metadata negatives
- 72 normal body returns, 72 exception dispatches and 72 removed-handler negatives,
  covering ADD/NOR and both flags-pop/after-pop windows
- 16 entry returns and 16 entry exceptions without the body handler
- 72 exit returns and 72 exit exceptions without the body handler

The native cases cover all four layouts and the declared argument/site matrices;
removed-handler cases end with the exact expected illegal-instruction status, not
an arbitrary failure. This is bounded Windows execution evidence, separate from
the Rosetta CPU comparisons and Unicorn frame/relocation proofs.

## Acceptance limits

The exception probes instrument selected instructions and do not establish exception
resumption or full SIMD/FP preservation at every possible machine boundary.

The original C++ tree, SDK contract, selection policy and unsupported-input boundaries
are unchanged. Full randomized cryptor generation, NAND branch coverage and the general
C++ compiler-produced SUB artifact are not claimed by this bounded slice.
