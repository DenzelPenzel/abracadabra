# Serialized VM PE proof

`emit_vm_pe.rs` is a test-only Cargo example target, not a product CLI or VM format.
It appends the current captured encrypted MOV/ADD instance to the committed MSVC x64
fixture without redirecting its original entry point. `vm_pe.py` executes the gate
from the written file, not regenerated code.

Run from the repository root with Python packages `unicorn==2.1.4` and `pefile==2024.8.26`:

```sh
python crates/vmp-emit/tests/proofs/vm_pe.py docs/proofs/vm-pe-artifacts
```

CI runs the same proof in the `vm-pe-proof` Ubuntu job with Python 3.11. Any failed
comparison or negative control fails the job. Generated files under `target/vm-pe-proof/`
are uploaded as the `vm-pe-proof` artifact with seven-day retention, including partial
output on failure. This is an emulator gate, separate from the Windows loader job.

The output directory retains four `.exe` files and `manifest.json` with entry RVAs
and SHA-256 hashes. Existing files of those names are overwritten on replay. The
manifest is proof metadata; the original PE AddressOfEntryPoint is unchanged.

Expected summary: four serialized PEs, 84 comparisons against separately executed
native MOV/ADD/RET, eight omitted-fixup negatives. The comparison uses Unicorn for
both native instruction streams, seven literal result/flag cases, and preferred base
plus positive/negative 64-KiB deltas. It checks all 15 non-RSP GPRs, flags, returned RSP
and a stack canary. Relocation data is reparsed with pefile and applied to copied
serialized bytes. A negative control replaces the persisted stream-pointer DIR64
entry with ABSOLUTE padding before reparsing and execution.

This is not Windows loader execution, import resolution, TLS initialization, unwind,
original-function redirection, or production Virtualization. Section mapping in the
harness does not enforce Windows memory protections. Corruption negatives prove
oracle sensitivity, not safe execution of hostile VM images.
