use iced_x86::code_asm::{
    al, byte_ptr, eax, ebp, qword_ptr, r10, r11, r12, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx,
    rdi, rdx, rsi, rsp, CodeAssembler, CodeLabel,
};
use iced_x86::IcedError;
use thiserror::Error;

/// Bytecode steps one gate entry may dispatch before it fails closed.
pub(crate) const MAX_RUNTIME_STEPS: u32 = 1_000_000;

/// Status codes the dispatcher publishes in the outcome record's first field.
pub(crate) mod status {
    pub(crate) const OK: u64 = 0;
    pub(crate) const TRUNCATED_BYTECODE: u64 = 1;
    pub(crate) const UNSUPPORTED_OPCODE: u64 = 2;
    pub(crate) const INVALID_OPERAND: u64 = 3;
    pub(crate) const STACK_UNDERFLOW: u64 = 4;
    pub(crate) const STACK_OVERFLOW: u64 = 5;
    pub(crate) const NON_EMPTY_STACK: u64 = 6;
    pub(crate) const STEP_LIMIT: u64 = 7;
}

const OP_RET: i32 = 0x01;
const OP_PUSH_REG: i32 = 0x11;
const OP_POP_REG: i32 = 0x12;
const OP_ADD: i32 = 0x20;
const WIDTH_QWORD: i32 = 8;
const REG_RAX: i32 = 0;
const REG_RCX: i32 = 1;
const REG_RDX: i32 = 2;

// Offsets from the immutable saved-context base in R15. The dispatcher pushes
// RFLAGS and all fifteen modeled GPRs, so the saved frame is 128 bytes and the
// entry metadata follows the return address above it.
const SAVED_RDX: i32 = 96;
const SAVED_RCX: i32 = 104;
const SAVED_RAX: i32 = 112;
const SAVED_RFLAGS: i32 = 120;
const ENTRY_CODE: i32 = 136;
const ENTRY_CODE_END: i32 = 144;
const ENTRY_OUTPUT: i32 = 152;

/// Bytes reserved for the bounded VM operand stack, above the native RSP.
const OPERAND_STACK_BYTES: i32 = 128;

// Field offsets of the outcome record the gate fills in. They must agree with
// the `#[repr(C)]` layout in `runtime_x64`.
const OUT_STATUS: i32 = 0;
const OUT_RAX: i32 = 8;
const OUT_RUNTIME_RFLAGS: i32 = 16;
const OUT_OBSERVED_RFLAGS: i32 = 24;
const OUT_RCX: i32 = 32;
const OUT_RDX: i32 = 40;

/// Win64 stack slot of the fifth argument at gate entry: return address plus
/// the four-register shadow space.
const GATE_ARG_OUTPUT: i32 = 40;

/// Failure to assemble the interpreter.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmitError {
    #[error("interpreter assembly failed: {reason}")]
    Assembly { reason: String },
}

impl From<IcedError> for EmitError {
    fn from(error: IcedError) -> Self {
        Self::Assembly {
            reason: error.to_string(),
        }
    }
}

/// Emitted interpreter bytes and the offset of their Win64 entry point.
///
/// The bytes are position-independent: every branch is relative and stays
/// inside the blob, and no operand holds an absolute address. Nothing in here
/// depends on where the bytes are eventually mapped or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBlob {
    bytes: Vec<u8>,
    entry_offset: u32,
}

impl RuntimeBlob {
    /// Emitted machine code.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Offset of the Win64 gate entry point within [`RuntimeBlob::bytes`].
    pub fn entry_offset(&self) -> u32 {
        self.entry_offset
    }
}

/// Assemble the v1 interpreter.
///
/// The blob holds two parts: a Win64 gate at [`RuntimeBlob::entry_offset`] that
/// converts normal arguments into the dispatcher's entry frame and reports the
/// guest state observed after the return, and the dispatcher itself. The
/// accepted bytecode subset is `PushReg` for RCX/RDX, qword `Add`, `PopReg` to
/// RAX, and `Ret`; everything else fails closed with a status code.
pub fn emit_interpreter() -> Result<RuntimeBlob, EmitError> {
    emit_interpreter_at(0)
}

/// Assemble the interpreter using `ip` as its origin.
///
/// `ip` is the assumed address of the first instruction, used by the assembler
/// to calculate relative branches. It does not allocate or map memory.
/// Position-independent output must be identical for every `ip`.
pub(crate) fn emit_interpreter_at(ip: u64) -> Result<RuntimeBlob, EmitError> {
    let mut asm = CodeAssembler::new(64)?;
    let mut dispatch = asm.create_label();

    // The Win64 gate: RCX is the bytecode pointer, RDX its end, R8 and R9 the
    // guest RCX and RDX, and the fifth stack argument the outcome record.
    asm.push(qword_ptr(rsp + GATE_ARG_OUTPUT))?;
    asm.push(rdx)?;
    asm.push(rcx)?;
    asm.mov(rcx, r8)?;
    asm.mov(rdx, r9)?;
    asm.call(dispatch)?;
    asm.lea(rsp, qword_ptr(rsp + 24))?;
    // Observe the state that reached the native continuation without changing
    // any guest register or flag; none of these moves writes RFLAGS.
    asm.push(r10)?;
    asm.mov(r10, qword_ptr(rsp + (GATE_ARG_OUTPUT + 8)))?;
    asm.mov(qword_ptr(r10 + OUT_RCX), rcx)?;
    asm.mov(qword_ptr(r10 + OUT_RDX), rdx)?;
    asm.push(rax)?;
    asm.pushfq()?;
    asm.pop(rax)?;
    asm.mov(qword_ptr(r10 + OUT_OBSERVED_RFLAGS), rax)?;
    asm.pop(rax)?;
    asm.pop(r10)?;
    asm.ret()?;

    emit_dispatcher(&mut asm, &mut dispatch)?;

    let bytes = asm.assemble(ip)?;
    Ok(RuntimeBlob {
        bytes,
        entry_offset: 0,
    })
}

/// Emit the dispatch loop.
///
/// Entry stack above the return address: bytecode begin, bytecode end, outcome
/// pointer. The dispatcher captures all modeled GPRs and RFLAGS before it uses
/// any of them as runtime scratch registers, and restores them on every exit.
fn emit_dispatcher(asm: &mut CodeAssembler, dispatch: &mut CodeLabel) -> Result<(), EmitError> {
    let mut fetch = asm.create_label();
    let mut op_push_reg = asm.create_label();
    let mut push_rcx = asm.create_label();
    let mut push_store = asm.create_label();
    let mut op_pop_reg = asm.create_label();
    let mut op_add = asm.create_label();
    let mut op_ret = asm.create_label();
    let mut truncated = asm.create_label();
    let mut unsupported = asm.create_label();
    let mut invalid_operand = asm.create_label();
    let mut underflow = asm.create_label();
    let mut overflow = asm.create_label();
    let mut non_empty = asm.create_label();
    let mut step_limit = asm.create_label();
    let mut publish = asm.create_label();

    asm.set_label(dispatch)?;
    asm.pushfq()?;
    asm.push(rax)?;
    asm.push(rcx)?;
    asm.push(rdx)?;
    asm.push(rbx)?;
    asm.push(rbp)?;
    asm.push(rsi)?;
    asm.push(rdi)?;
    asm.push(r8)?;
    asm.push(r9)?;
    asm.push(r10)?;
    asm.push(r11)?;
    asm.push(r12)?;
    asm.push(r13)?;
    asm.push(r14)?;
    asm.push(r15)?;
    // R15 is the immutable saved-context base.
    asm.mov(r15, rsp)?;
    asm.mov(r13, qword_ptr(r15 + ENTRY_CODE))?;
    asm.mov(r12, qword_ptr(r15 + ENTRY_CODE_END))?;
    // Reserve a bounded operand stack above RSP and keep its empty top in R11,
    // so the dispatcher's own pushes below RSP cannot reach operand slots.
    asm.sub(rsp, OPERAND_STACK_BYTES)?;
    asm.and(rsp, -16)?;
    asm.mov(r14, rsp)?;
    asm.mov(r11, rsp)?;
    asm.lea(rbx, qword_ptr(rsp + OPERAND_STACK_BYTES))?;
    asm.mov(ebp, MAX_RUNTIME_STEPS as i32)?;

    // Fetch one opcode, failing closed at the bytecode boundary.
    asm.set_label(&mut fetch)?;
    asm.test(ebp, ebp)?;
    asm.jz(step_limit)?;
    asm.dec(ebp)?;
    asm.cmp(r13, r12)?;
    asm.jae(truncated)?;
    asm.movzx(eax, byte_ptr(r13))?;
    asm.inc(r13)?;
    asm.cmp(al, OP_RET)?;
    asm.je(op_ret)?;
    asm.cmp(al, OP_PUSH_REG)?;
    asm.je(op_push_reg)?;
    asm.cmp(al, OP_POP_REG)?;
    asm.je(op_pop_reg)?;
    asm.cmp(al, OP_ADD)?;
    asm.je(op_add)?;
    asm.jmp(unsupported)?;

    // PUSH_REG qword, bounded to RCX and RDX for this vertical slice.
    asm.set_label(&mut op_push_reg)?;
    asm.mov(rax, r12)?;
    asm.sub(rax, r13)?;
    asm.cmp(rax, 2)?;
    asm.jb(truncated)?;
    asm.cmp(byte_ptr(r13), WIDTH_QWORD)?;
    asm.jne(invalid_operand)?;
    asm.movzx(eax, byte_ptr(r13 + 1))?;
    asm.add(r13, 2)?;
    asm.lea(r10, qword_ptr(r14 + 8))?;
    asm.cmp(r10, rbx)?;
    asm.ja(overflow)?;
    asm.cmp(al, REG_RCX)?;
    asm.je(push_rcx)?;
    asm.cmp(al, REG_RDX)?;
    asm.jne(invalid_operand)?;
    asm.mov(rax, qword_ptr(r15 + SAVED_RDX))?;
    asm.jmp(push_store)?;
    asm.set_label(&mut push_rcx)?;
    asm.mov(rax, qword_ptr(r15 + SAVED_RCX))?;
    asm.set_label(&mut push_store)?;
    asm.mov(qword_ptr(r14), rax)?;
    asm.mov(r14, r10)?;
    asm.jmp(fetch)?;

    // POP_REG qword, bounded to RAX for this slice.
    asm.set_label(&mut op_pop_reg)?;
    asm.mov(rax, r12)?;
    asm.sub(rax, r13)?;
    asm.cmp(rax, 2)?;
    asm.jb(truncated)?;
    asm.cmp(byte_ptr(r13), WIDTH_QWORD)?;
    asm.jne(invalid_operand)?;
    asm.cmp(byte_ptr(r13 + 1), REG_RAX)?;
    asm.jne(invalid_operand)?;
    asm.add(r13, 2)?;
    asm.cmp(r14, r11)?;
    asm.je(underflow)?;
    asm.sub(r14, 8)?;
    asm.mov(rax, qword_ptr(r14))?;
    asm.mov(qword_ptr(r15 + SAVED_RAX), rax)?;
    asm.jmp(fetch)?;

    // ADD qword: the right and left operands are popped, and the result plus
    // the native ADD flags are written back to the saved guest context.
    asm.set_label(&mut op_add)?;
    asm.cmp(r13, r12)?;
    asm.jae(truncated)?;
    asm.cmp(byte_ptr(r13), WIDTH_QWORD)?;
    asm.jne(invalid_operand)?;
    asm.inc(r13)?;
    asm.mov(rax, r14)?;
    asm.sub(rax, r11)?;
    asm.cmp(rax, 16)?;
    asm.jb(underflow)?;
    asm.sub(r14, 8)?;
    asm.mov(rax, qword_ptr(r14))?;
    asm.sub(r14, 8)?;
    asm.add(qword_ptr(r14), rax)?;
    asm.pushfq()?;
    asm.pop(rax)?;
    asm.mov(qword_ptr(r15 + SAVED_RFLAGS), rax)?;
    asm.add(r14, 8)?;
    asm.jmp(fetch)?;

    // RET requires an empty VM operand stack.
    asm.set_label(&mut op_ret)?;
    asm.cmp(r14, r11)?;
    asm.jne(non_empty)?;
    asm.mov(eax, status::OK as u32)?;
    asm.jmp(publish)?;

    for (label, code) in [
        (&mut truncated, status::TRUNCATED_BYTECODE),
        (&mut unsupported, status::UNSUPPORTED_OPCODE),
        (&mut invalid_operand, status::INVALID_OPERAND),
        (&mut underflow, status::STACK_UNDERFLOW),
        (&mut overflow, status::STACK_OVERFLOW),
        (&mut non_empty, status::NON_EMPTY_STACK),
    ] {
        asm.set_label(label)?;
        asm.mov(eax, code as u32)?;
        asm.jmp(publish)?;
    }
    asm.set_label(&mut step_limit)?;
    asm.mov(eax, status::STEP_LIMIT as u32)?;

    // Publish the outcome before restoring every captured register and RFLAGS.
    // The restored RFLAGS carry the guest flags a handler last wrote.
    asm.set_label(&mut publish)?;
    asm.mov(r10, qword_ptr(r15 + ENTRY_OUTPUT))?;
    asm.mov(qword_ptr(r10 + OUT_STATUS), rax)?;
    asm.mov(rax, qword_ptr(r15 + SAVED_RAX))?;
    asm.mov(qword_ptr(r10 + OUT_RAX), rax)?;
    asm.mov(rax, qword_ptr(r15 + SAVED_RFLAGS))?;
    asm.mov(qword_ptr(r10 + OUT_RUNTIME_RFLAGS), rax)?;
    asm.mov(rsp, r15)?;
    asm.pop(r15)?;
    asm.pop(r14)?;
    asm.pop(r13)?;
    asm.pop(r12)?;
    asm.pop(r11)?;
    asm.pop(r10)?;
    asm.pop(r9)?;
    asm.pop(r8)?;
    asm.pop(rdi)?;
    asm.pop(rsi)?;
    asm.pop(rbp)?;
    asm.pop(rbx)?;
    asm.pop(rdx)?;
    asm.pop(rcx)?;
    asm.pop(rax)?;
    asm.popfq()?;
    asm.ret()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};

    #[test]
    fn the_emitted_blob_starts_at_its_win64_gate() {
        let blob = emit_interpreter().expect("the interpreter must assemble");

        assert_eq!(blob.entry_offset(), 0);
        assert!(!blob.bytes().is_empty());
        // A single page keeps the eventual PE section arithmetic trivial.
        assert!(
            blob.bytes().len() < 4096,
            "blob is {} bytes",
            blob.bytes().len()
        );
    }

    #[test]
    fn the_emitted_blob_does_not_depend_on_where_it_is_assembled() {
        let low = emit_interpreter_at(0).expect("the interpreter must assemble at zero");
        let high = emit_interpreter_at(0x7fff_0000_1000)
            .expect("the interpreter must assemble at a mapped address");

        assert_eq!(low.bytes(), high.bytes());
        assert_eq!(low.entry_offset(), high.entry_offset());
    }

    #[test]
    fn the_emitted_blob_references_nothing_outside_itself() {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let length = blob.bytes().len() as u64;
        let mut decoder = Decoder::with_ip(64, blob.bytes(), 0, DecoderOptions::NONE);
        let mut decoded = 0usize;
        let mut end = 0u64;

        for instruction in decoder.iter() {
            assert!(
                !instruction.is_invalid(),
                "byte {} does not decode",
                instruction.ip()
            );
            decoded += 1;
            end = instruction.next_ip();

            if matches!(
                instruction.flow_control(),
                FlowControl::UnconditionalBranch
                    | FlowControl::ConditionalBranch
                    | FlowControl::Call
            ) {
                assert_eq!(instruction.op0_kind(), OpKind::NearBranch64);
                let target = instruction.near_branch64();
                assert!(
                    target < length,
                    "branch at {} leaves the blob for {target}",
                    instruction.ip()
                );
            }

            for index in 0..instruction.op_count() {
                match instruction.op_kind(index) {
                    OpKind::Memory => {
                        assert_ne!(
                            instruction.memory_base(),
                            Register::RIP,
                            "instruction at {} is RIP-relative",
                            instruction.ip()
                        );
                        assert!(
                            instruction.memory_base() != Register::None
                                || instruction.memory_index() != Register::None,
                            "instruction at {} holds an absolute address",
                            instruction.ip()
                        );
                    }
                    OpKind::Immediate64 => panic!(
                        "instruction at {} carries a 64-bit immediate",
                        instruction.ip()
                    ),
                    _ => {}
                }
            }
        }

        assert_eq!(end, length, "decoding stopped before the end of the blob");
        assert!(decoded > 60, "only {decoded} instructions decoded");
    }
}
