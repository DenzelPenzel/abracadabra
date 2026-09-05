# Porting notes: measured facts and traps

Reference for porting work, kept out of `CLAUDE.md` because each section only matters while
you are inside the layer it describes; `CLAUDE.md` names the section to read per crate.

Condensed from the untracked catalogues — `docs/x86-instructions.md`,
`docs/vmp-emit-vs-cpp-core.md`, `docs/vmp-pe-vs-cpp-core.md`, `docs/adr/` — which additionally
hold the C++ code quotes, the full PE/COFF structure reference, the 58-mnemonic tier
inventory and the finer `vmp-pe` semantic divergences. Every `core/…:line` here was
hand-verified; those files mark unverified pointers with `※`. Keep that distinction and
cite only what you read yourself.

Corpus for every number below: all 115 `.pdata`-declared functions of
`crates/vmp-pe/test-corpus/win64-app-msvc-amd64` (MSVC x64, static CRT) — 5495 unique
instructions, 58 mnemonics. One program, one compiler: treat the numbers as priority, not
as a specification.

## 1. x86-64 semantics and re-encoding — `vmp-x86`

### 1.1 Liveness: `undefined` is not a write

The single easiest way to generate silently broken code. 672 of those 5495 instructions —
every eighth — leave at least one flag **undefined**: `test`/`xor`/`and`/`or` leave `AF`;
`shr`/`sar`/`shl`/`rol`/`ror` leave `OF` (for counts other than 1) and `AF`; `imul` leaves
`SF/ZF/AF/PF`; `div` leaves all six. The naive rule "the instruction writes the flag, so
the old value is dead" is wrong for those:

```text
dead(flag) = definitely_written(flag) AND NOT read_before_that_write(flag)
undefined does NOT count as a write
```

`iced-x86` exposes `rflags_read()`, `rflags_written()` and `rflags_undefined()` separately
and all three must be used. The C++ model cannot express this — it has a single
`change_flags` that merges defined writes and undefined ones (`core/intel.cc:11889`), so
its liveness decisions are not a safe oracle here.

Shifts are worse: with `cl == 0` they touch **no** flags at all, so one opcode either
writes flags or does not depending on a runtime value. Statically the only sound reading is
"may not write" ⇒ the previous flag value stays live.

### 1.2 Re-encoding does not preserve bytes

`iced-x86::BlockEncoder` picks the **shortest** form, not the original one. Measured on the
corpus: 41 of 5495 instructions change size when re-encoded to the same address — 31
dropped an empty `REX` prefix (`40 53` → `53`), 3 near→short `jmp`, 3 short→near `jcc`, 4
other (`jmp` 7→6, `nop` 4→2). Observable behaviour is preserved (mnemonic sequence and
every branch target round-trip); bytes are not.

Consequences that are easy to get wrong:

- Never read a post-mutation address from anywhere but `Relocated::moved` /
  `new_instruction_offsets`. Instruction sizes are not stable across encoding.
- C++ sidesteps this by pre-widening every short branch to its near form **before**
  allocating addresses (`core/intel.cc:16163`), so sizes never change afterwards. We do not
  have that step and must not assume it.
- Revisiting ADR-0001 is only warranted if byte-exact preservation of untouched
  instructions becomes a requirement (e.g. not eating hot-patch padding); the fix then is
  "original bytes for unmodified instructions, encoder only for new ones", not a
  wholesale `BlockEncoder` pass.

Pinned by `re_encoding_drops_a_redundant_rex_prefix` in `vmp-x86/tests/corpus.rs`.

## 2. Mutation catalogue — `vmp-mutation`

### 2.1 The rewrite catalogue and its side conditions

C++ `IntelFunction::Mutate` has a five-branch `switch` with **four** working rewrites
(`core/intel.cc:16293-16371`; the `cmCall` branch has an empty body but still burns one
`rand()`). Each fires on its own `rand() & 1`. All four exist in
`vmp-mutation/src/rewrite.rs`:

- `xor reg,reg` → `sub reg,reg` (`zeroing_xor_to_sub`). Needs **no** flag-liveness check,
  and C++ deliberately omits one too: `xor` leaves `AF` undefined, `sub` defines it as 0,
  so the rewrite only ever removes undefinedness. **The reverse direction is unsafe**
  without proving `AF` dead. Our version changes only the opcode and keeps the encoding
  direction, so `31 c9` (MR) becomes `29 c9` where C++ re-derives `2b c9` (RM) — one byte,
  same instruction, same length. Irrelevant on MSVC output: all 168 self-zeroing `xor`s in
  the fixture are `33 /r`; the divergence only shows on GCC/clang.
- `add reg,X` → `lea reg,[reg+X]` and `sub reg,X` → `lea reg,[reg-X]` (`add_to_lea`,
  `sub_to_lea`). `lea` is the only arithmetic that writes no flags, which is what makes the
  whole catalogue possible — and it is exactly why the rewrite **requires**
  written_flags ⊆ dead_flags (C++: `core/intel.cc:16311`). `arithmetic_to_lea` folds
  `rflags_undefined()` into the set that must be dead, which is the rule above applied:
  the C++ check cannot, because its `change_flags` already merged them. Excludes `rsp` as
  destination and as index.
- `jmp <reg|mem>` → `push` + `ret` (`indirect_jump_to_push_ret`). Live trap: between the
  `push` and the `ret`, `rsp` is 8 below what `UNWIND_INFO` describes, so an exception
  inside that window unwinds wrongly. C++ ships it anyway; our implementation currently has
  no unwind-range guard either. Closing this means either refusing the rewrite inside
  unwind-covered ranges or updating `.xdata`.

Worth copying when the need arises: the x64 `call <next>` idiom, which materialises a
return address without clobbering anything (`core/intel.cc:16243`) —
`push rax` / `lea rax,[<next>]` / `xchg [rsp],rax`. On x86 it is one `push imm32` plus a
new base relocation (`16233`).

Minimum protectable function size is 5 bytes, matching C++ (`core/intel.cc:15978` and
`langs/en.lng:155`) — independently re-derived here from the length of `E9 rel32`
(`STUB_LEN`, `SkipReason::TooShortForStub`). Two fixture functions (`0x4c80`, `0x4c90`) are
a single `c3`, so their refusal is physics, not a defect.

Two transforms our plan has that C++ has **zero** of: reordering independent instructions,
and reallocating registers in native code. Both need exactly what C++ lacks by
construction — read/write sets that distinguish undefined, and real CFG edges.

### 2.2 Inert junk: the selection rule

C++ hardcodes 78 live junk templates (`core/intel.cc:16053-16158`; 73 on x86, fewer under
`for_virtualization`) and inserts `rand() % 4` of them per site. A template is admissible
only if (`core/intel.cc:16386-16422`):

```text
for every write the template performs:
    writes a "free" register  -> at least one register must be provably dead
    writes flags              -> written_flags subset-of dead_flags
    writes a named register   -> that register is dead AND wide enough
```

Never insert after an instruction that transfers control (`is_end`, `core/intel.cc:16378`)
or after one with unknown semantics — the dead-register set is simply unknown there. The
cheapest group to start from is flags-only (`cmp`/`test` forms): it needs no dead register
at all, only dead flags.

## 3. PE container — `vmp-pe`

### 3.1 PE coordinate traps

- **Security directory (index 4) stores a file offset, not an RVA** — certificate tables are
  not mapped. It must never be typed as `Rva` or passed through `rva_to_offset`.
- `mapped_size = max(VirtualSize, SizeOfRawData)` for range checks and RVA lookup. An RVA
  landing between `SizeOfRawData` and `VirtualSize` is in the zero-filled virtual tail and
  has **no** file byte; the RVA→offset formula does not apply there, nor to overlay, nor to
  absolute VAs inside TLS or load config.
- Directories must fit the *declared* optional header
  (`fixed_optional_size + min(NumberOfRvaAndSizes, 16) * 8 <= SizeOfOptionalHeader`).
  Bytes physically being there does not authorise reading them as directories — the section
  table may already start.
- Section names carry no semantics; go by data directories and `Characteristics`.
- Trailing bytes after the last section are legal (certificate table, overlay), so the end
  of the last section need not equal the file size.

### 3.2 The append-only writer refuses by design

Nothing existing moves and `SizeOfHeaders` never changes, so a new 40-byte section header
must fit the already-declared header region or the append is a typed refusal. C++ instead
re-emits the image and grows headers (`core/pefile.cc:4341-4342`). Consequence: **2 of the
6 corpus fixtures are legitimately unwritable** — `win32-app-delphi-i386` gives
`SectionHeaderSlotNotEmpty`, `win32-dll-test1-i386` gives
`HeaderDirectoryOverlapsSlot { directory: 11 }`. That is the pinned expectation of
`every_corpus_pe_parses_and_rewrites_or_is_refused`, not a bug to fix.

Three writer divergences are deliberate and must not be "corrected" toward the C++:

1. `SizeOfCode` / `SizeOfInitializedData` / `SizeOfUninitializedData` are recomputed; C++
   never writes them, so they will not be byte-identical to genuine VMProtect output.
2. `SizeOfHeaders` is never touched — correct here, because header growth is refused
   outright, so it can never need to change.
3. The checksum is always written; C++ writes it only when the original was non-zero
   (`core/pefile.cc:4301`), which is 3 of the 6 fixtures. Signed images are refused
   (`CertificateTablePresent`), so there is no signature to invalidate.

Also settled as identical to C++, so it does not get reinvented: relocation-block
serialisation (sort first, `block_rva = rva & 0xfffff000`, pad when `SizeOfBlock & 3`, **no**
terminating null block); `.xdata` blobs are never relocated by either side; the synthesised
leaf `UNWIND_INFO` is byte-identical (`[1, 0, 0, 0]`); checksum is written last.

`vmp-pe/tests/cpp_parity.rs` is a differential **without building C++**: assertions
transplanted from `../unit-tests/pefile_tests.cc` with the source test name and line, VAs
converted to RVAs. 4 of its 12 tests were portable; the other 9 exercise the protector
itself (VM, LZMA packing, running output). The highest-value one is `CalcCheckSum` —
`0xe4490` and `0xb8c9` produced by the independent `os::FileGetCheckSum`, matched with no
adjustment.

Open risk, not a defect: `PeFile::parse` is eager, but the loader reads the **exception
(3)** and **export (0)** directories lazily. For those two we are therefore stricter than
"loads and runs", so an obfuscated or post-processed binary with unusual-but-loadable
`.pdata` gets rejected on the inspect path. No counterexample has been built. If one turns
up, the known fix is making those two directories non-fatal ("directory present, model
absent") instead of failing all of `parse`.

## 4. Placement and unwind metadata — `vmp-emit`

### 4.1 The prologue is frozen, and that is stricter than C++ on purpose

`vmp-emit` freezes `[entry, entry + size_of_prolog)` (`Frozen`) and, after re-encoding,
`prologue_kept_its_layout` requires **every** prologue instruction to keep its offset from
entry — otherwise `SkipReason::PrologueMoved`.

C++ has no equivalent, verified line by line: `IntelFunction::Mutate` does not exclude the
prologue (`core/intel.cc:16039-16561` never mentions `prolog_size`), prologue `UNWIND_CODE`s
are registered with all three patch pointers `NULL` so nothing is recomputed
(`core/pefile.cc:3009`), and `prolog_size` is only ever read — never written back. The one
compensation pads the first block back to the recorded `SizeOfProlog` with `rand()` bytes
(`core/processors.cc:2604`), which restores the *total* size but not the *internal* offsets.

Concretely, on `ci-fixtures/probe-amd64.exe` RVA `0x1c80`: `40 53 push rbx` loses its
redundant `REX`, the prologue shrinks 6→5, and `CodeOffset=0x02` then names the wrong
instruction boundary — `RtlVirtualUnwind` would conclude `rbx` had not been pushed yet.
**So do not "fix" `PrologueMoved` by porting the C++.** The real options are recomputing
`UNWIND_CODE` for the new layout, or emitting the prologue byte-for-byte around
`BlockEncoder`. (`is_breaked_address` is not a prior art either — it is a single tail
cut-off driven by the `BreakOffset` project attribute, i.e. a GUI knob.)

### 4.2 Block shuffling and the MemoryManager: nothing to port on x64

C++ shuffles all blocks of all functions with `rand()`-swaps (`core/processors.cc:2572`)
and then, **if `.pdata` is non-empty, sorts them back** by `FunctionInfo` and
`original_begin` (`processors.cc:2576`, comparator at `2815`), because a `FunctionInfo` is
one contiguous `[begin, end)` and `RtlLookupFunctionEntry` must find it. So on x64 the main
anti-analysis win of the allocator is cancelled by the original itself; randomness survives
only within one `AddressRange` and among blocks with no unwind data.

Likewise `MemoryManager` (277 lines, `core/files.cc:2684-2960`) degenerates on x64: the
appended region is the only one that keeps `mtExecutable` when `.pdata` is non-empty
(`core/pefile.cc:4528`, `core/files.cc:3290-3311`, `2890`), and allocation inside it is
strictly monotonic — i.e. already what `PayloadBuilder` + `align_up` do. **Do not build the
allocator now**; it only pays off on x86, and it is useless without a link layer to patch
references after addresses are handed out (20 `lt*` link types in C++, whereas today
`BlockEncoder` does the late binding within a single function).

## 5. VM v1 and the runtime — `vmp-vm`, `vmp-runtime-windows`

### 5.1 The comparison discipline a lowering slice must satisfy

Beyond what `bytecode.rs` encodes, ADR-0003 fixes how a lowering slice is allowed to be
declared correct:

- Flags are `(bits, defined_mask)` over `CF, PF, AF, ZF, SF, OF`. The native oracle and the
  VM must produce **the exact same defined mask first**; only then are bits compared under
  that mask. Never intersect the masks — that would let a missing VM-defined flag or a
  spuriously defined one disappear.
- `jcc` requires its condition's complete flag set to be defined **before** evaluating,
  with no value-dependent short circuit: `BE` traps on undefined `ZF` even when `CF=1`
  already decides the native expression.
- `Ret` is an abstract termination marker, not native `RET`. The oracle stops immediately
  before the terminal `RET`, so there is no return-address read and no `RSP` increment;
  final GPR comparison excludes `RSP`. Stack-memory and caller-return effects belong to
  later trampoline/ABI tests.
- Lowering uses the **semantic** operand width, not the immediate's byte count: an x64
  arithmetic `imm32` sign-extended to 64 bits becomes an 8-byte slot, not a 4-byte one.
- `RSP` (logical GPR id 4) stays reserved and is rejected by decoder, verifier and
  lowering, so no accepted v1 program can have shadow-RSP semantics.
- Encoder/decoder round-trip alone is not proof — a shared wrong schema fake-greens. Golden
  bytes plus malformed byte-level negative controls are required.
- Required order: typed model + codec → golden/malformed/limit tests → host interpreter and
  flag tests → lowering with an independent oracle → full host-equivalence gate → **only
  then** Windows runtime and PE integration. Starting at the runtime before the earlier
  steps are independently green violates the ADR.

### 5.2 The C++ VM processor, and where variant A deliberately differs

Measured against `../core/`, not remembered. Read this before touching a runtime handler:
three of these facts look like defects in our code until you know the C++ shape, and two
are places where C++ is **not** a usable template.

- **The interpreter is generated, not shipped as a blob.**
  `IntelVirtualMachineProcessor : public IntelFunction` (`core/intel.h:1485`): the processor
  is a function in the function list, emitted one instruction at a time through
  `processor_->AddCommand(...)` and serialised by the ordinary writer. Open decision 7 was
  closed on this anchor — `vmp-runtime-windows` emits bytes instead of carrying `naked_asm!`.
- **Guest registers live in an indexed context based at the native RSP.** The push-register
  handler reads one operand byte from the stream and uses it as an index:
  `mov/movzx reg2, [rsp + reg1]` (`otMemory | otBaseRegistr | otRegistr, (regESP << 4) | reg1`,
  `core/intel.cc:28850`). Under `cpEncryptBytecode` that byte is decrypted by a per-file
  `registr_cryptor` (`:28840-28843`). The context is 24 slots on x64 and 16 on x86, reserved
  below RSP together with 128 bytes of red zone and `and rsp, -16` (`:28701`, `:28724-28727`).
  There is no push-order offset arithmetic anywhere in the C++.
- **The VM operand stack is the native stack, and it carries no type tags.**
  `mov stack_registr_, regESP` (`:28724`) seeds it from the entry RSP and it grows downward.
  Width is a property of the **opcode**, not of a slot: a separate handler and opcode number
  is generated per width (`opcode_list_.Add(cmPush, otRegistr, size, ...)`, `:28859`), and each
  handler moves the pointer by the exact byte size of its own operand
  (`sub stack_registr_, result_size`, `:28853-28857`). A byte operand is stored as a word
  (`mov_size = (size == osByte) ? osWord : size`, `:28838`). Our typed `Slot { width, value }`
  and `PopWidthMismatch` have **no C++ counterpart**; they are a Rust addition, so the C++
  stack model cannot be copied into the native runtime.
- **Running out of VM stack is not an error there.** `check_stack` compares the VM stack
  pointer against `[rsp + (context_registr_count + 8) * 8]` and, when it gets too close,
  relocates the guest context lower and copies it instead of refusing (`:28783-28812`). Any
  bound we keep is ours, not parity, and must be recorded as such.
- **Scratch registers are randomized per file.** `pcode_registr_`, `stack_registr_`,
  `jmp_registr_` and `crypt_registr_` are drawn with `work_registr_list.GetRandom()`
  (`:28630-28635`); the fixed `regESI`/`regEBP`/`regEDI`/`regR11` assignment applies only to
  the demo/unregistered branch (`:28601-28609`). Our fixed assignment is ADR-0002 variant A
  and is knowingly weaker protection, not an oversight.
- **Dispatch is address-baked, not position-independent.** Advanced mode adds a dword delta
  read from the bytecode stream to `jmp_registr_` and jumps through the register
  (`AddEndHandlerCommands`, `:27836-27859`), so the stream carries handler offsets rather than
  opcode numbers and there is no central switch. x64 Classic jumps through a table of absolute
  handler addresses — `jmp qword ptr [jmp_reg + reg*8]`, scale 3 (`:28770-28771`). The base is
  seeded by a `lea` whose operand is resolved by a compile-time link to its own address
  (`AddLink(1, ltOffset, opcode_entry)`, `:28746-28747`), and on x86 that operand receives a
  base relocation (`NEED_FIXUP` -> `fixup_list()->AddDefault(...)`, `:8687-8691`; sentinels in
  `core/files.h:519-520`). The position independence of our emitted blob is an addition that
  buys embedding without a single relocation entry — not a ported property.
- **Windows needs an explicit instruction-cache flush** after a page is made executable and
  before generated code runs, so the mapping is published only after `FlushInstructionCache`
  succeeds. The Unix mapping path needs no flush: it only ever compiles for x86-64.
- C++ has no host reference interpreter at all. `vmp-vm::host` is a new Rust safety oracle,
  and it — not the C++ — is the normative model the native runtime must match.
- C++ `check_stack` protects its internal `REP MOVS` with `PUSHF; CLD; ...; POPF`
  (`core/intel.cc:28809-28815`), so it restores the incoming `DF`. Variant A deliberately keeps
  VM-visible flags in its control frame but normalises `DF=0` before native Win64 continuation.
  `IF` is preserved. Active `TF` belongs to the registered-unwind proof. Incoming `AC`
  stays in the saved VM flags, but live `AC` is cleared after the immutable frame is
  established and restored on normal return. Arithmetic handlers update only their
  defined arithmetic flags, not the saved control bits. This is an explicit Rust policy,
  not C++ parity: Windows run `33970576704` first observed the intended bytecode-fetch AV,
  then recursive alignment faults in `ntdll.dll` before VEH delivery with live `AC` set.
  Body exception proof therefore requires normalized live `AC` and preserved saved `AC`;
  it does not cover AC-active exceptions before normalization or after exit restoration.
- A defense-in-depth status after canonical v1 validation is an internal contract violation:
  the production trampoline uses `FAST_FAIL_FATAL_APP_EXIT` and never resumes the original
  function. The standalone status slot remains test transport, not part of the protected
  function ABI.
- Variant A touches at most 272 bytes below the emitted production-entry `RSP`: 128 bytes of
  saved GPR/RFLAGS context, up to eight bytes of alignment, the 128-byte operand stack, and one
  transient handler qword. The complete protected-function extent is 320 bytes below its
  original Win64 entry `RSP` after adding five metadata qwords and the dispatcher call return.

## Open decisions — do not settle these unilaterally

Recorded in the catalogues as awaiting the owner's call:

1. Whether to erase the original function body. C++ erases it (`rand()` bytes, or `0xcc`
   in debug mode — the same choice our `pad_to` makes); we overwrite only the 5 stub bytes
   because a crash dump needs the evidence. A flag defaulting to "do not erase" is the
   likely compromise.
2. Whether to delete the protected function's stale `.pdata` entry. Neither side deletes
   it; C++ neutralises it by stripping `mtReadable` from the freed region, which we have no
   equivalent for.
3. Whether to randomise section names. C++ defaults to a dot plus 3 random characters; we
   hardcode `.vmpc`/`.vmpx`, which is a fingerprint. Configurability already exists
   (`Options::code_section`, `Options::pdata_section`); randomisation does not.
4. How to close `PrologueMoved` — recompute `UNWIND_CODE`, or emit the prologue byte-exact
   around `BlockEncoder`.
5. `HasAbsoluteFixups` never fired on x64 and will fire on x86; it needs `.reloc` editing.
6. `UnwindNotReEmittable` — refused whenever `UnwindInfo.handler.is_some()`. On the fixture
   that is exactly the 20 of 115 `RUNTIME_FUNCTION`s with `flags != 0`. C++ ports these by
   turning the handler RVA into a relocatable reference (`core/pefile.cc:3040-3043`) and
   recomputing scope-table `Begin`/`End` addresses, which *are* registered with real patch
   pointers — the deliberate mirror of the prologue's `NULL` ones.
