use iced_x86::code_asm::{
    al, byte_ptr, eax, ebp, qword_ptr, r10, r11, r12, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx,
    rdi, rdx, rsi, rsp, CodeAssembler, CodeLabel,
};
use iced_x86::{
    BlockEncoderOptions, Decoder, DecoderOptions, IcedError, Mnemonic, OpKind, Register,
};
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
const AC: i32 = 1 << 18;
const ARITHMETIC_FLAGS: i32 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

// Offsets from the immutable saved-context base in R15. The dispatcher pushes
// all fifteen modeled GPRs and then RFLAGS, so the saved frame is 128 bytes and
// the entry metadata follows the return address above it.
const SAVED_RFLAGS: i32 = 0;
const SAVED_RDX: i32 = 104;
const SAVED_RCX: i32 = 112;
const SAVED_RAX: i32 = 120;
const ENTRY_CODE_BASE: i32 = 136;
const ENTRY_PC: i32 = 144;
const ENTRY_CODE_END: i32 = 152;
const ENTRY_STATUS: i32 = 160;
const ENTRY_RUNTIME_RFLAGS: i32 = 168;

/// Bytes reserved for the bounded VM operand stack, above the native RSP.
const OPERAND_STACK_BYTES: i32 = 128;

/// Maximum bytes touched below the emitted production-entry RSP.
///
/// This includes the saved native context, alignment padding, the operand
/// stack, and one transient handler push.
pub const MAX_PRODUCTION_ENTRY_STACK_USAGE: usize = 272;

/// Maximum bytes touched below the original protected-function entry RSP.
///
/// This adds five trampoline metadata slots and the production-entry return
/// address to the emitted entry's physical stack depth.
pub const MAX_PROTECTED_FUNCTION_STACK_USAGE: usize = 320;

// Field offsets of the test adapter input and output records. They must agree
// with the `#[repr(C)]` layouts in `runtime_x64`.
const IN_CODE_BASE: i32 = 0;
const IN_ENTRY_PC: i32 = 8;
const IN_CODE_END: i32 = 16;
const IN_RFLAGS: i32 = 24;
const IN_RAX: i32 = 32;
const IN_RCX: i32 = 40;
const IN_RDX: i32 = 48;
const IN_RBX: i32 = 56;
const IN_RBP: i32 = 64;
const IN_RSI: i32 = 72;
const IN_RDI: i32 = 80;
const IN_R8: i32 = 88;
const IN_R9: i32 = 96;
const IN_R10: i32 = 104;
const IN_R11: i32 = 112;
const IN_R12: i32 = 120;
const IN_R13: i32 = 128;
const IN_R14: i32 = 136;
const IN_R15: i32 = 144;

const OUT_STATUS: i32 = 0;
const OUT_RUNTIME_RFLAGS: i32 = 8;
const OUT_OBSERVED_RFLAGS: i32 = 16;
const OUT_RSP_BEFORE: i32 = 24;
const OUT_RSP_AFTER: i32 = 32;
const OUT_RAX: i32 = 40;
const OUT_RCX: i32 = 48;
const OUT_RDX: i32 = 56;
const OUT_RBX: i32 = 64;
const OUT_RBP: i32 = 72;
const OUT_RSI: i32 = 80;
const OUT_RDI: i32 = 88;
const OUT_R8: i32 = 96;
const OUT_R9: i32 = 104;
const OUT_R10: i32 = 112;
const OUT_R11: i32 = 120;
const OUT_R12: i32 = 128;
const OUT_R13: i32 = 136;
const OUT_R14: i32 = 144;
const OUT_R15: i32 = 152;

/// Failure to assemble the interpreter.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmitError {
    #[error("interpreter assembly failed: {reason}")]
    Assembly { reason: String },
    #[error("generated an invalid unwind plan")]
    UnwindPlan,
}

impl From<IcedError> for EmitError {
    fn from(error: IcedError) -> Self {
        Self::Assembly {
            reason: error.to_string(),
        }
    }
}

/// Half-open machine-code range within an emitted runtime blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeRange {
    start: u32,
    end: u32,
}

impl CodeRange {
    /// Offset of the first byte in the range.
    pub fn start(self) -> u32 {
        self.start
    }

    /// Offset immediately after the range.
    pub fn end(self) -> u32 {
        self.end
    }
}

/// A nonvolatile Win64 register representable by `UNWIND_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum UnwindRegister {
    Rbx = 3,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

/// One stack or frame-pointer effect at an emitted instruction boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwindOperation {
    PushNonvolatile {
        code_offset: u8,
        register: UnwindRegister,
    },
    StackAllocation {
        code_offset: u8,
    },
    SetFramePointer {
        code_offset: u8,
    },
}

impl UnwindOperation {
    fn code_offset(self) -> u8 {
        match self {
            Self::PushNonvolatile { code_offset, .. }
            | Self::StackAllocation { code_offset, .. }
            | Self::SetFramePointer { code_offset, .. } => code_offset,
        }
    }
}

/// Unwind contract of one contiguous emitted Win64 frame function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnwindFunction {
    pub(crate) range: CodeRange,
    pub(crate) prologue_size: u8,
    pub(crate) frame_register: Option<UnwindRegister>,
    pub(crate) frame_offset: u8,
    pub(crate) operations: Vec<UnwindOperation>,
}

/// Complete unwind contract for the callable entries in one runtime blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeUnwindPlan {
    pub(crate) functions: [UnwindFunction; 2],
}

/// A generated unwind plan cannot describe the emitted runtime safely.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum UnwindPlanError {
    #[error("runtime function {index} lies outside the emitted blob")]
    FunctionOutsideBlob { index: usize },
    #[error("runtime function {index} is not strictly ordered after its predecessor")]
    FunctionsNotStrictlyOrdered { index: usize },
    #[error("runtime function {index} has a prologue outside its range")]
    PrologueOutsideFunction { index: usize },
    #[error("unwind operation {operation} in function {function} lies outside its prologue")]
    OperationOutsidePrologue { function: usize, operation: usize },
    #[error("unwind operation {operation} in function {function} is not after its predecessor")]
    OperationsNotIncreasing { function: usize, operation: usize },
    #[error("runtime function {function} has inconsistent frame-pointer metadata")]
    FramePointerMismatch { function: usize },
    #[error("runtime function {function} has an unencodable frame offset")]
    FrameOffsetTooLarge { function: usize },
    #[error("unwind operation {operation} in function {function} does not match emitted code")]
    OperationDoesNotMatchCode { function: usize, operation: usize },
}

impl RuntimeUnwindPlan {
    pub(crate) fn validate(&self, bytes: &[u8]) -> Result<(), UnwindPlanError> {
        let mut previous_end = 0;
        for (index, function) in self.functions.iter().enumerate() {
            let range = function.range;
            if range.start >= range.end || range.end as usize > bytes.len() {
                return Err(UnwindPlanError::FunctionOutsideBlob { index });
            }
            if index != 0 && range.start < previous_end {
                return Err(UnwindPlanError::FunctionsNotStrictlyOrdered { index });
            }
            if range
                .start
                .checked_add(u32::from(function.prologue_size))
                .is_none_or(|prologue_end| prologue_end > range.end)
            {
                return Err(UnwindPlanError::PrologueOutsideFunction { index });
            }
            let mut previous_code_offset = 0;
            let mut has_set_frame_pointer = false;
            for (operation, unwind) in function.operations.iter().copied().enumerate() {
                let code_offset = unwind.code_offset();
                if code_offset == 0 || code_offset > function.prologue_size {
                    return Err(UnwindPlanError::OperationOutsidePrologue {
                        function: index,
                        operation,
                    });
                }
                if code_offset <= previous_code_offset {
                    return Err(UnwindPlanError::OperationsNotIncreasing {
                        function: index,
                        operation,
                    });
                }
                previous_code_offset = code_offset;
                if matches!(unwind, UnwindOperation::SetFramePointer { .. }) {
                    if has_set_frame_pointer {
                        return Err(UnwindPlanError::FramePointerMismatch { function: index });
                    }
                    has_set_frame_pointer = true;
                }
            }
            let declared_frame = function
                .frame_register
                .map(|register| (register, function.frame_offset));
            if function.frame_offset > 15 {
                return Err(UnwindPlanError::FrameOffsetTooLarge { function: index });
            }
            if function.frame_register.is_some() != has_set_frame_pointer
                || function.frame_register.is_none() && function.frame_offset != 0
            {
                return Err(UnwindPlanError::FramePointerMismatch { function: index });
            }
            let expected = derive_unwind_function(
                bytes,
                range,
                u32::from(function.prologue_size),
                declared_frame,
            )
            .map_err(|_| UnwindPlanError::OperationDoesNotMatchCode {
                function: index,
                operation: 0,
            })?;
            if expected.operations != function.operations {
                let operation = expected
                    .operations
                    .iter()
                    .zip(&function.operations)
                    .position(|(expected, actual)| expected != actual)
                    .unwrap_or(expected.operations.len().min(function.operations.len()));
                return Err(UnwindPlanError::OperationDoesNotMatchCode {
                    function: index,
                    operation,
                });
            }
            previous_end = range.end;
        }
        Ok(())
    }
}

/// Emitted interpreter bytes and offsets of its callable entry points.
///
/// The bytes are position-independent: every branch is relative and stays
/// inside the blob, and no operand holds an absolute address. Nothing in here
/// depends on where the bytes are eventually mapped or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBlob {
    bytes: Vec<u8>,
    test_entry_offset: u32,
    production_entry_offset: u32,
    test_adapter_range: CodeRange,
    dispatcher_range: CodeRange,
    handlers_range: CodeRange,
    pub(crate) unwind_plan: RuntimeUnwindPlan,
}

impl RuntimeBlob {
    /// Emitted machine code.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Offset of the Win64 test adapter within [`RuntimeBlob::bytes`].
    pub fn test_entry_offset(&self) -> u32 {
        self.test_entry_offset
    }

    /// Offset of the native-state capture entry within [`RuntimeBlob::bytes`].
    ///
    /// Its stack frame contains bytecode base, entry PC, bytecode end, status,
    /// and runtime-RFLAGS slots above the native return address.
    pub fn production_entry_offset(&self) -> u32 {
        self.production_entry_offset
    }

    /// Machine-code range occupied by the Win64 test adapter.
    pub fn test_adapter_range(&self) -> CodeRange {
        self.test_adapter_range
    }

    /// Machine-code range occupied by state capture and opcode dispatch.
    pub fn dispatcher_range(&self) -> CodeRange {
        self.dispatcher_range
    }

    /// Machine-code range occupied by handlers and state restoration.
    pub fn handlers_range(&self) -> CodeRange {
        self.handlers_range
    }
}

/// Assemble the v1 interpreter.
///
/// The blob contains a Win64 test adapter, a separate native-state capture
/// entry, the dispatcher, and its handlers. The accepted bytecode subset is
/// `PushReg` for RCX/RDX, qword `Add`, `PopReg` to RAX, and `Ret`; everything
/// else fails closed with a status code.
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
    let mut handlers = asm.create_label();
    let mut test_prologue_end = asm.create_label();
    let mut production_prologue_end = asm.create_label();

    // The Win64 test adapter receives input and output records in RCX and RDX.
    // Preserve its caller's nonvolatile registers before loading guest values.
    asm.push(rbx)?;
    asm.push(rbp)?;
    asm.push(rsi)?;
    asm.push(rdi)?;
    asm.push(r12)?;
    asm.push(r13)?;
    asm.push(r14)?;
    asm.push(r15)?;
    asm.push(rdx)?;
    asm.push(rcx)?;

    // Production metadata is passed outside guest registers. The two writable
    // slots carry the native status and the flags selected by the last handler.
    asm.push(0)?;
    asm.push(-1)?;
    asm.push(qword_ptr(rcx + IN_CODE_END))?;
    asm.push(qword_ptr(rcx + IN_ENTRY_PC))?;
    asm.push(qword_ptr(rcx + IN_CODE_BASE))?;
    asm.set_label(&mut test_prologue_end)?;
    asm.mov(qword_ptr(rdx + OUT_RSP_BEFORE), rsp)?;

    // Load the complete guest context without changing the supplied RFLAGS.
    // R15 retains the input pointer until it is loaded last.
    asm.mov(r15, rcx)?;
    asm.mov(rax, qword_ptr(r15 + IN_RFLAGS))?;
    asm.push(rax)?;
    asm.popfq()?;
    asm.mov(rax, qword_ptr(r15 + IN_RAX))?;
    asm.mov(rcx, qword_ptr(r15 + IN_RCX))?;
    asm.mov(rdx, qword_ptr(r15 + IN_RDX))?;
    asm.mov(rbx, qword_ptr(r15 + IN_RBX))?;
    asm.mov(rbp, qword_ptr(r15 + IN_RBP))?;
    asm.mov(rsi, qword_ptr(r15 + IN_RSI))?;
    asm.mov(rdi, qword_ptr(r15 + IN_RDI))?;
    asm.mov(r8, qword_ptr(r15 + IN_R8))?;
    asm.mov(r9, qword_ptr(r15 + IN_R9))?;
    asm.mov(r10, qword_ptr(r15 + IN_R10))?;
    asm.mov(r11, qword_ptr(r15 + IN_R11))?;
    asm.mov(r12, qword_ptr(r15 + IN_R12))?;
    asm.mov(r13, qword_ptr(r15 + IN_R13))?;
    asm.mov(r14, qword_ptr(r15 + IN_R14))?;
    asm.mov(r15, qword_ptr(r15 + IN_R15))?;
    asm.call(dispatch)?;

    // Observe the restored state without changing RFLAGS. The production core
    // only addresses its inline control slots, never this test output record.
    asm.push(r10)?;
    asm.mov(r10, qword_ptr(rsp + 56))?;
    asm.mov(qword_ptr(r10 + OUT_RAX), rax)?;
    asm.mov(qword_ptr(r10 + OUT_RCX), rcx)?;
    asm.mov(qword_ptr(r10 + OUT_RDX), rdx)?;
    asm.mov(qword_ptr(r10 + OUT_RBX), rbx)?;
    asm.mov(qword_ptr(r10 + OUT_RBP), rbp)?;
    asm.mov(qword_ptr(r10 + OUT_RSI), rsi)?;
    asm.mov(qword_ptr(r10 + OUT_RDI), rdi)?;
    asm.mov(qword_ptr(r10 + OUT_R8), r8)?;
    asm.mov(qword_ptr(r10 + OUT_R9), r9)?;
    asm.mov(qword_ptr(r10 + OUT_R11), r11)?;
    asm.mov(qword_ptr(r10 + OUT_R12), r12)?;
    asm.mov(qword_ptr(r10 + OUT_R13), r13)?;
    asm.mov(qword_ptr(r10 + OUT_R14), r14)?;
    asm.mov(qword_ptr(r10 + OUT_R15), r15)?;
    asm.mov(rax, qword_ptr(rsp))?;
    asm.mov(qword_ptr(r10 + OUT_R10), rax)?;
    asm.mov(rax, qword_ptr(rsp + 32))?;
    asm.mov(qword_ptr(r10 + OUT_STATUS), rax)?;
    asm.mov(rax, qword_ptr(rsp + 40))?;
    asm.mov(qword_ptr(r10 + OUT_RUNTIME_RFLAGS), rax)?;
    asm.pushfq()?;
    asm.pop(rax)?;
    asm.mov(qword_ptr(r10 + OUT_OBSERVED_RFLAGS), rax)?;
    asm.lea(rax, qword_ptr(rsp + 8))?;
    asm.mov(qword_ptr(r10 + OUT_RSP_AFTER), rax)?;
    asm.pop(r10)?;
    asm.lea(rsp, qword_ptr(rsp + 56))?;
    asm.pop(r15)?;
    asm.pop(r14)?;
    asm.pop(r13)?;
    asm.pop(r12)?;
    asm.pop(rdi)?;
    asm.pop(rsi)?;
    asm.pop(rbp)?;
    asm.pop(rbx)?;
    asm.ret()?;

    emit_dispatcher(
        &mut asm,
        &mut dispatch,
        &mut handlers,
        &mut production_prologue_end,
    )?;

    let assembled =
        asm.assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;
    let production_entry_offset = label_offset(&assembled, &dispatch, ip)?;
    let handlers_offset = label_offset(&assembled, &handlers, ip)?;
    let test_prologue_size = label_offset(&assembled, &test_prologue_end, ip)?;
    let production_prologue_size = label_offset(&assembled, &production_prologue_end, ip)?
        .checked_sub(production_entry_offset)
        .ok_or_else(|| EmitError::Assembly {
            reason: "production prologue precedes its entry".to_owned(),
        })?;
    let bytes = assembled.inner.code_buffer;
    let blob_end = u32::try_from(bytes.len()).map_err(|_| EmitError::Assembly {
        reason: "interpreter exceeds the 32-bit blob offset range".to_owned(),
    })?;
    let test_adapter_range = CodeRange {
        start: 0,
        end: production_entry_offset,
    };
    let production_range = CodeRange {
        start: production_entry_offset,
        end: blob_end,
    };
    let unwind_plan = RuntimeUnwindPlan {
        functions: [
            derive_unwind_function(&bytes, test_adapter_range, test_prologue_size, None)?,
            derive_unwind_function(
                &bytes,
                production_range,
                production_prologue_size,
                Some((UnwindRegister::R15, 0)),
            )?,
        ],
    };
    unwind_plan
        .validate(&bytes)
        .map_err(|_| EmitError::UnwindPlan)?;
    Ok(RuntimeBlob {
        bytes,
        test_entry_offset: 0,
        production_entry_offset,
        test_adapter_range,
        dispatcher_range: CodeRange {
            start: production_entry_offset,
            end: handlers_offset,
        },
        handlers_range: CodeRange {
            start: handlers_offset,
            end: blob_end,
        },
        unwind_plan,
    })
}

fn label_offset(
    assembled: &iced_x86::code_asm::CodeAssemblerResult,
    label: &CodeLabel,
    origin: u64,
) -> Result<u32, EmitError> {
    let offset = assembled
        .label_ip(label)?
        .checked_sub(origin)
        .ok_or_else(|| EmitError::Assembly {
            reason: "interpreter label precedes the blob origin".to_owned(),
        })?;
    u32::try_from(offset).map_err(|_| EmitError::Assembly {
        reason: "interpreter label exceeds the 32-bit blob offset range".to_owned(),
    })
}

fn derive_unwind_function(
    bytes: &[u8],
    range: CodeRange,
    prologue_size: u32,
    frame: Option<(UnwindRegister, u8)>,
) -> Result<UnwindFunction, EmitError> {
    let prologue_size = u8::try_from(prologue_size).map_err(|_| EmitError::Assembly {
        reason: "runtime prologue exceeds the Win64 unwind offset range".to_owned(),
    })?;
    let start = range.start as usize;
    let end = start
        .checked_add(prologue_size as usize)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| EmitError::Assembly {
            reason: "runtime prologue lies outside its blob".to_owned(),
        })?;
    let mut operations = Vec::new();
    let mut decoder = Decoder::with_ip(64, &bytes[start..end], 0, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.next_ip() > u64::from(prologue_size) {
            return Err(EmitError::Assembly {
                reason: "runtime prologue does not end at an instruction boundary".to_owned(),
            });
        }
        let code_offset = instruction.next_ip() as u8;
        let operation = match instruction.mnemonic() {
            Mnemonic::Push if instruction.op0_kind() == OpKind::Register => {
                match unwind_register(instruction.op0_register()) {
                    Some(register) => UnwindOperation::PushNonvolatile {
                        code_offset,
                        register,
                    },
                    None => UnwindOperation::StackAllocation { code_offset },
                }
            }
            Mnemonic::Push | Mnemonic::Pushfq => UnwindOperation::StackAllocation { code_offset },
            Mnemonic::Mov
                if instruction.op0_register() == Register::R15
                    && instruction.op1_register() == Register::RSP =>
            {
                frame.ok_or_else(|| EmitError::Assembly {
                    reason: "runtime prologue sets an undeclared frame pointer".to_owned(),
                })?;
                UnwindOperation::SetFramePointer { code_offset }
            }
            _ => {
                return Err(EmitError::Assembly {
                    reason: "runtime prologue contains an unsupported instruction".to_owned(),
                });
            }
        };
        operations.push(operation);
    }
    let (frame_register, frame_offset) = frame.unzip();
    Ok(UnwindFunction {
        range,
        prologue_size,
        frame_register,
        frame_offset: frame_offset.unwrap_or(0),
        operations,
    })
}

fn unwind_register(register: Register) -> Option<UnwindRegister> {
    match register {
        Register::RBX => Some(UnwindRegister::Rbx),
        Register::RBP => Some(UnwindRegister::Rbp),
        Register::RSI => Some(UnwindRegister::Rsi),
        Register::RDI => Some(UnwindRegister::Rdi),
        Register::R12 => Some(UnwindRegister::R12),
        Register::R13 => Some(UnwindRegister::R13),
        Register::R14 => Some(UnwindRegister::R14),
        Register::R15 => Some(UnwindRegister::R15),
        _ => None,
    }
}

/// Emit the dispatch loop.
///
/// Entry stack above the return address: bytecode base, entry PC, bytecode end,
/// status slot, and runtime-RFLAGS slot. The dispatcher captures all modeled
/// GPRs and RFLAGS before assigning scratch registers.
fn emit_dispatcher(
    asm: &mut CodeAssembler,
    dispatch: &mut CodeLabel,
    handlers: &mut CodeLabel,
    prologue_end: &mut CodeLabel,
) -> Result<(), EmitError> {
    let mut fetch = asm.create_label();
    let op_push_reg = *handlers;
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
    asm.pushfq()?;
    // R15 is the immutable saved-context base.
    asm.mov(r15, rsp)?;
    asm.set_label(prologue_end)?;
    // Normalize live AC only after the unwind frame is established
    asm.push(qword_ptr(r15 + SAVED_RFLAGS))?;
    asm.and(qword_ptr(rsp), !AC)?;
    asm.popfq()?;
    asm.mov(rsi, qword_ptr(r15 + ENTRY_CODE_BASE))?;
    asm.mov(r13, qword_ptr(r15 + ENTRY_PC))?;
    asm.mov(r12, qword_ptr(r15 + ENTRY_CODE_END))?;
    asm.cmp(rsi, r12)?;
    asm.ja(invalid_operand)?;
    asm.cmp(r13, rsi)?;
    asm.jb(invalid_operand)?;
    asm.cmp(r13, r12)?;
    asm.ja(invalid_operand)?;
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
    asm.set_label(handlers)?;
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
    asm.and(rax, ARITHMETIC_FLAGS)?;
    asm.and(qword_ptr(r15 + SAVED_RFLAGS), !ARITHMETIC_FLAGS)?;
    asm.or(qword_ptr(r15 + SAVED_RFLAGS), rax)?;
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

    // Publish control state into the production frame before restoring every
    // captured register and RFLAGS.
    asm.set_label(&mut publish)?;
    asm.mov(qword_ptr(r15 + ENTRY_STATUS), rax)?;
    asm.mov(rax, qword_ptr(r15 + SAVED_RFLAGS))?;
    asm.mov(qword_ptr(r15 + ENTRY_RUNTIME_RFLAGS), rax)?;
    asm.push(qword_ptr(r15 + SAVED_RFLAGS))?;
    asm.popfq()?;
    // Native Win64 continuation always starts with forward string direction.
    asm.cld()?;
    asm.lea(rsp, qword_ptr(r15 + 8))?;
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
    asm.ret()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    #[test]
    fn the_emitted_blob_separates_test_and_production_ranges() {
        let blob = emit_interpreter().expect("the interpreter must assemble");

        assert_eq!(MAX_PRODUCTION_ENTRY_STACK_USAGE, 272);
        assert_eq!(MAX_PROTECTED_FUNCTION_STACK_USAGE, 320);
        assert_eq!(blob.test_entry_offset(), 0);
        assert_ne!(blob.test_entry_offset(), blob.production_entry_offset());
        assert_eq!(blob.test_adapter_range().start(), blob.test_entry_offset());
        assert_eq!(
            blob.test_adapter_range().end(),
            blob.production_entry_offset()
        );
        assert_eq!(
            blob.dispatcher_range().start(),
            blob.production_entry_offset()
        );
        assert_eq!(blob.dispatcher_range().end(), blob.handlers_range().start());
        assert_eq!(blob.handlers_range().end() as usize, blob.bytes().len());
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
        assert_eq!(low.test_entry_offset(), high.test_entry_offset());
        assert_eq!(
            low.production_entry_offset(),
            high.production_entry_offset()
        );
        assert_eq!(low.test_adapter_range(), high.test_adapter_range());
        assert_eq!(low.dispatcher_range(), high.dispatcher_range());
        assert_eq!(low.handlers_range(), high.handlers_range());
    }

    #[test]
    fn body_normalizes_only_live_ac_after_frozen_prologue() {
        let blob = emit_interpreter().expect("assemble");
        let function = &blob.unwind_plan.functions[1];
        let start = function.range.start() as usize;
        let end = start + function.prologue_size as usize;
        assert_eq!(
            &blob.bytes()[start..end],
            &[
                0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
                0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x9c, 0x49, 0x89, 0xe7
            ]
        );
        let body: Vec<_> = Decoder::new(64, &blob.bytes()[end..], DecoderOptions::NONE)
            .into_iter()
            .take(3)
            .collect();
        assert_eq!(body[0].mnemonic(), Mnemonic::Push);
        assert_eq!(body[0].memory_base(), Register::R15);
        assert_eq!(body[0].memory_displacement64(), 0);
        assert_eq!(body[1].mnemonic(), Mnemonic::And);
        assert_eq!(body[1].memory_base(), Register::RSP);
        assert_eq!(body[1].immediate32(), !(1u32 << 18));
        assert_eq!(body[2].mnemonic(), Mnemonic::Popfq);
        let remaining: Vec<_> = Decoder::new(64, &blob.bytes()[end..], DecoderOptions::NONE)
            .into_iter()
            .collect();
        let restores: Vec<_> = remaining
            .iter()
            .enumerate()
            .filter(|(_, i)| i.mnemonic() == Mnemonic::Popfq)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(restores, [2, remaining.len() - 19]);
    }

    #[test]
    fn add_merges_only_arithmetic_flags_into_guest_snapshot() {
        let blob = emit_interpreter().expect("assemble");
        let instructions: Vec<_> = Decoder::new(64, blob.bytes(), DecoderOptions::NONE)
            .into_iter()
            .collect();
        let add = instructions
            .iter()
            .position(|i| {
                i.mnemonic() == Mnemonic::Add
                    && i.memory_base() == Register::R14
                    && i.op1_register() == Register::RAX
            })
            .expect("ADD handler");
        assert_eq!(instructions[add + 3].mnemonic(), Mnemonic::And);
        assert_eq!(instructions[add + 3].immediate32(), 0x8d5);
        assert_eq!(instructions[add + 4].mnemonic(), Mnemonic::And);
        assert_eq!(instructions[add + 4].memory_base(), Register::R15);
        assert_eq!(instructions[add + 4].immediate32(), !0x8d5u32);
        assert_eq!(instructions[add + 5].mnemonic(), Mnemonic::Or);
        assert_eq!(instructions[add + 5].memory_base(), Register::R15);
    }

    #[test]
    fn production_exit_has_a_canonical_frame_pointer_epilog() {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let instructions: Vec<_> = Decoder::with_ip(64, blob.bytes(), 0, DecoderOptions::NONE)
            .into_iter()
            .collect();
        let tail = instructions
            .get(instructions.len().saturating_sub(20)..)
            .expect("the production exit has twenty instructions");

        assert_eq!(tail[0].mnemonic(), Mnemonic::Push);
        assert_eq!(tail[0].memory_base(), Register::R15);
        assert_eq!(tail[0].memory_displacement64(), 0);
        assert_eq!(tail[1].mnemonic(), Mnemonic::Popfq);
        assert_eq!(tail[2].mnemonic(), Mnemonic::Cld);
        assert_eq!(tail[3].mnemonic(), Mnemonic::Lea);
        assert_eq!(tail[3].op0_register(), Register::RSP);
        assert_eq!(tail[3].memory_base(), Register::R15);
        assert_eq!(tail[3].memory_displacement64(), 8);

        let expected_pops = [
            Register::R15,
            Register::R14,
            Register::R13,
            Register::R12,
            Register::R11,
            Register::R10,
            Register::R9,
            Register::R8,
            Register::RDI,
            Register::RSI,
            Register::RBP,
            Register::RBX,
            Register::RDX,
            Register::RCX,
            Register::RAX,
        ];
        for (instruction, register) in tail[4..19].iter().zip(expected_pops) {
            assert_eq!(instruction.mnemonic(), Mnemonic::Pop);
            assert_eq!(instruction.op0_register(), register);
        }
        assert_eq!(tail[19].mnemonic(), Mnemonic::Ret);
    }

    #[test]
    fn unwind_plan_describes_both_real_prologues() {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let functions = &blob.unwind_plan.functions;

        assert_eq!(functions.len(), 2);
        let adapter = &functions[0];
        assert_eq!(adapter.range, blob.test_adapter_range());
        assert_eq!((adapter.frame_register, adapter.frame_offset), (None, 0));
        assert_eq!(operation_counts(&adapter.operations), (8, 7));

        let production = &functions[1];
        assert_eq!(production.range.start(), blob.production_entry_offset());
        assert_eq!(production.range.end() as usize, blob.bytes().len());
        assert_eq!(
            (production.frame_register, production.frame_offset),
            (Some(UnwindRegister::R15), 0)
        );
        assert!(matches!(
            production.operations.last(),
            Some(UnwindOperation::SetFramePointer { .. })
        ));
        assert_eq!(operation_counts(&production.operations), (8, 8));

        for function in functions {
            let instruction_ends: Vec<u8> = Decoder::with_ip(
                64,
                &blob.bytes()[function.range.start() as usize..],
                0,
                DecoderOptions::NONE,
            )
            .into_iter()
            .map(|instruction| instruction.next_ip() as u8)
            .take_while(|offset| *offset <= function.prologue_size)
            .collect();
            for operation in &function.operations {
                assert!(instruction_ends.contains(&operation.code_offset()));
            }
        }
    }

    fn operation_counts(operations: &[UnwindOperation]) -> (usize, usize) {
        operations
            .iter()
            .fold((0, 0), |(pushes, allocations), operation| match operation {
                UnwindOperation::PushNonvolatile { .. } => (pushes + 1, allocations),
                UnwindOperation::StackAllocation { .. } => (pushes, allocations + 1),
                UnwindOperation::SetFramePointer { .. } => (pushes, allocations),
            })
    }

    #[test]
    fn unwind_plan_rejects_a_function_outside_the_blob() {
        assert_invalid_plan(
            |blob, plan| plan.functions[1].range.end = blob.bytes().len() as u32 + 1,
            UnwindPlanError::FunctionOutsideBlob { index: 1 },
        );
    }

    #[test]
    fn unwind_plan_rejects_overlapping_functions() {
        assert_invalid_plan(
            |_, plan| plan.functions[1].range.start = plan.functions[0].range.end - 1,
            UnwindPlanError::FunctionsNotStrictlyOrdered { index: 1 },
        );
    }

    #[test]
    fn unwind_plan_rejects_a_prologue_outside_its_function() {
        assert_invalid_plan(
            |_, plan| {
                plan.functions[0].range.end = plan.functions[0].range.start + 1;
                plan.functions[0].prologue_size = 2;
            },
            UnwindPlanError::PrologueOutsideFunction { index: 0 },
        );
    }

    #[test]
    fn unwind_plan_rejects_an_operation_after_the_prologue() {
        assert_invalid_plan(
            |_, plan| {
                let code_offset = plan.functions[0].prologue_size + 1;
                plan.functions[0].operations[0] = UnwindOperation::StackAllocation { code_offset };
            },
            UnwindPlanError::OperationOutsidePrologue {
                function: 0,
                operation: 0,
            },
        );
    }

    #[test]
    fn unwind_plan_rejects_nonincreasing_operation_offsets() {
        assert_invalid_plan(
            |_, plan| plan.functions[0].operations.swap(0, 1),
            UnwindPlanError::OperationsNotIncreasing {
                function: 0,
                operation: 1,
            },
        );
    }

    #[test]
    fn unwind_plan_rejects_a_frame_header_without_matching_set_fpreg() {
        assert_invalid_plan(
            |_, plan| plan.functions[1].frame_register = None,
            UnwindPlanError::FramePointerMismatch { function: 1 },
        );
    }

    #[test]
    fn unwind_plan_rejects_an_unencodable_frame_offset() {
        assert_invalid_plan(
            |_, plan| plan.functions[1].frame_offset = 16,
            UnwindPlanError::FrameOffsetTooLarge { function: 1 },
        );
    }

    #[test]
    fn unwind_plan_rejects_an_operation_that_does_not_match_the_code() {
        assert_invalid_plan(
            |_, plan| {
                let code_offset = plan.functions[0].operations[0].code_offset();
                plan.functions[0].operations[0] = UnwindOperation::PushNonvolatile {
                    code_offset,
                    register: UnwindRegister::Rbp,
                };
            },
            UnwindPlanError::OperationDoesNotMatchCode {
                function: 0,
                operation: 0,
            },
        );
    }

    fn assert_invalid_plan(
        corrupt: impl FnOnce(&RuntimeBlob, &mut RuntimeUnwindPlan),
        expected: UnwindPlanError,
    ) {
        let blob = emit_interpreter().expect("the interpreter must assemble");
        let mut plan = blob.unwind_plan.clone();
        corrupt(&blob, &mut plan);
        assert_eq!(plan.validate(blob.bytes()), Err(expected));
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
