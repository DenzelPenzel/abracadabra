# Captured Classic byte cryptors in a generated instance

## Scope and ownership

`BodyInstance::generate_encrypted` and `NativeInstance::generate_encrypted` use one
captured Classic forward byte-cryptor pair. The same private `Cryptors` value supplies
inverse field encoding and native decryptor emission; handlers, mapping, table,
context offsets, physical stream and initial key remain in the instance owner.
The unencrypted constructors and proof subjects remain available and unchanged in
contract. This is not a stable bytecode protocol, a fixed external interpreter,
randomized cryptor selection or a claim of cryptographic strength.

Only opcode bytes and register/flags-offset bytes are present in the accepted
MOV/ADD bodies. Wider fields, backward traversal, Advanced handler deltas,
per-handler varied operand recipes, multiple VMs and link/key resets are excluded.
The captured push/pop operand recipes happen to match; this does not generalize
that property to arbitrary C++ handlers. No Windows/unwind/PE integration is claimed.

## Source and concrete evidence before implementation

Original source freshly inspected:

- `core/intel.cc:27793–27824`: forward fetch, XOR key, ordered transforms, key update
- `core/intel.cc:30564–30597`: section initial key from VM address; inverse transforms
  followed by key mixing; update from the old plaintext; end/link key-reset boundary
- `core/processors.cc:693–708`: forward transform order and inverse reverse order
- `core/processors.cc:775–813`: opcode cryptor selects XOR and its inverse is XOR

The existing adapted Classic/Advanced PE evidence was rerun before production edits:
`verify_all_cryptors.py` passed 84 fields per artifact; Classic physical dispatch replay
passed four tests. These remain captured artifact proofs, not pristine C++ builds.

Captured Classic byte recipes, from `classic_cryptors.txt`:

- Opcode: XOR low key; ROR4; NOT; ROR7; XOR 0x1b; key-low XOR plaintext
- Operand: XOR low key; SUB1; NOT; ROR1; ADD1; key-low XOR plaintext

Pinned consecutive source fields, starting at 0x14000307f:

| Kind | Plain | Cipher | Key before | Key after |
|---|---|---|---|---|
| opcode | 32 | c9 | 14000307f | 14000304d |
| operand | 28 | ff | 14000304d | 140003065 |
| opcode | 4c | 20 | 140003065 | 140003029 |
| operand | 58 | 7b | 140003029 | 140003071 |

Values are hexadecimal. The unit test pins these literals, rather than deriving
expected ciphertext from a Rust decoder. New instance mappings/addresses differ
from the C++ artifact; representation byte equality is not the instance contract.

## Native implementation boundary

Fetch uses DL, byte cryptor operations and DIL as the low rolling key. High key bits
are preserved. The first key is the placed stream VA. The native gate initializes
RDI only after capturing guest GPRs, and restores guest RDI through the existing
context exit. The raw body harness supplies RDI explicitly. Decryptor instructions
do not consume extra stack or overwrite the RAX value carried by PopReg.

## Executable verification

API RED: `cargo test -p vmp-vm --test encrypted_instance` failed for the missing
constructors. Subsequent API and captured-field unit tests passed.

```
cargo test -p vmp-vm --test encrypted_instance --test instance
cargo test -p vmp-vm --lib captured_cpp_fields_pin_ciphertext_and_full_key
cargo test --target x86_64-apple-darwin -p vmp-vm --test native_gate_cpu
cargo test --release --target x86_64-apple-darwin -p vmp-vm --test native_gate_cpu
/tmp/vmp351-classic-proof/proof/venv/bin/python crates/vmp-vm/tests/proofs/encrypted_instance.py
```

The native suite passed four tests in debug and release. Its MOV-only flags,
register-pair and 256-body composition comparisons now execute both plain and
encrypted gates against the original x64 instructions. Rosetta is not Windows.

The encrypted Unicorn suite passed four tests. Across 256 layouts and seven literal
cases it checks every field's plaintext, full key-after, cursor and independent
ciphertext transform before dispatch/operand use. It retains handler order,
intermediate ADD operands/flags/result, context and stack checks. Ciphertext, initial
key and emitted-decryptor mutations each trigger a specific semantic assertion,
not an emulator error. The unchanged plain Unicorn suite also passed four tests.

The exporter records one (lhs=1,rhs=2) field trace per layout alongside the generated
image and its SHA-256. It is test evidence, not a product format:

```
/tmp/vmp351-classic-proof/proof/venv/bin/python crates/vmp-vm/tests/proofs/encrypted_instance.py --export docs/proofs/cpp-add-emulator/rust-encrypted-fields.jsonl
```

Full workspace gates and independent review of this encrypted extension are pending.
