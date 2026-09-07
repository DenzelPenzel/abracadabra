# Generated body instance proof

`body_instance.py` executes bytes emitted by Rust `instance::BodyInstance` via the
`body_instance` example. It is a separate, explicit emulator gate, not automatically
run by `cargo test`. No Python or Unicorn dependency enters the Rust product.

Run from the workspace root with a Python interpreter containing Unicorn 2.1.4:

```sh
python crates/vmp-vm/tests/proofs/body_instance.py
```

Local working interpreter: `/tmp/vmp351-classic-proof/proof/venv/bin/python`.

## Boundary and provenance

This is an unencrypted, forward Classic-style **body engine**, not a complete VM gate.
The generator owns the 256-slot table, matching opcode values and stream, context byte
offsets and native handlers in one placed image. `variant` is a deterministic layout
recipe, not security randomness. Code templates and physical work registers are fixed
in this first bounded slice. No stable wire version is introduced. Table addresses are
baked for the supplied base; relocation records and PE integration are absent.

Original `core/intel.cc` anchors (read directly):

- 27793–27824: field fetch/direction and optional cryptor updates
- 28624–28635, 28668–28727: work-register allocation versus saved context, VM stack
  capture, separate native scratch/context reservation
- 28751–28772: Classic x64 table register and qword indexed dispatch
- 28849–28859: register byte-offset fetch, `[RSP + offset]` context read, descending
  VM byte-stack push
- 28879–28889: VM stack pop, byte-offset fetch, context write
- 29200–29214: qword ADD reads top and next operand, stores result at stack+8, then
  PUSHF/POP writes the qword flags at stack+0

Rust uses equivalent native instruction templates (including a memory-form ADD), not
copies of the captured binary. The Python gate seeds context and work registers; that
setup is test-only and is not a translation of the full C++ entry sequence. The context
slot recipe is owned by this instance, not the C++ captured register permutation.
End-of-stream completion and unused-opcode traps are bounded harness/engine safeguards,
not C++ RET semantics. The caller must satisfy the documented entry preconditions;
externally supplied or corrupted streams are not a supported execution interface.

The seven literal input/output rows are the native/C++ observations documented in the
local `docs/proofs/cpp-add-emulator/logical-mov-add-boundary.md`, previously matched to
both captured variants and their PE/compiler hashes. Tests do not read ignored docs.
They compare arithmetic flags under mask `0x8d5`, not arbitrary raw high flag transport.

## What executes

- All 256 recipes on the seven literal MOV RAX,RCX / ADD RAX,RDX cases
- Exactly seven native handler entries per case
- ADD entry `[lhs][rhs]` and exit `[flags][result]` at the same VM stack pointer
- All 15 context GPR values, arithmetic flags, final VM/native stack pointers,
  consumed stream, older bytes and canaries beyond both scratch budgets
- Live ADD-to-SUB, dispatch-table and source-operand corruption after generation;
  the tests require semantic assertion failures, not compilation/emulator failures

The Rust integration suite tests coupling/replay for every recipe and typed empty,
body-count and address-overflow refusals. It began RED with missing `vmp_vm::instance`,
then passed after implementation. Native execution proof was added after this initial
API RED/GREEN and includes the actual generated-byte corruption controls above.

This does not prove Windows execution, a callable native entry/exit gate, unwind,
cryptors, stack growth, arbitrary logical programs or whole-function virtualization.
The existing physical CPU suites remain separate proof assets. Body-engine code review
found no High/Medium defects and reran the Rust/Unicorn checks; the reviewer's direct
C++ lookup was blocked, so source provenance remains attributed to parent inspection.
The subsequent scalar native gate and its outer execution probe are documented in
`native-gate.md`; that gate has its own review boundary.
