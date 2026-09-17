//! Coupled native handlers, context offsets, table and stream for bounded x64 bodies
//!
//! For the raw `BodyInstance`, RSP points to a writable 128-byte context, RBP to
//! the top of a separate descending byte stack, RSI to the stream, R10 to the table,
//! and R11 to the stream end. SUB also needs an intermediate flags word at context+128
//! Reserve `max_stack_bytes` below RBP and 8 bytes below RSP
//! Entry is `entry_offset`; stop before `completion_offset` and read the context
//! RAX, RDX and native flags are scratch. Never execute externally modified images
//! Context, both stack scratch regions and image must be disjoint; flags output guarantees
//! only arithmetic bits. Native control flags must be benign (no TF); this is not POPF replay
//! Encrypted bodies additionally require RDI = `initial_key` and use it as scratch
//! `NativeInstance` adds scalar capture/restore and optional leaf body exception metadata
//! Neither emits stack growth or serialized PE directories

use std::ops::Range;
mod cryptor;
mod unwind;
use cryptor::{ByteCryptor, Cryptors};
use thiserror::Error;
pub use unwind::LeafUnwind;
use vmp_types::VirtualAddress;

use crate::{
    logical::{Command, ContextRegister, LogicalInstruction},
    operand::{Register, Width},
    stack::{BinaryOp, Instruction},
};

#[derive(Debug, Error)]
pub enum InstanceError {
    #[error("expected between 1 and 256 logical instruction bodies")]
    BodyCount,
    #[error("instance address range overflows")]
    AddressOverflow,
    #[error("unsupported logical body command")]
    UnsupportedCommand,
    #[error("unable to allocate bounded instance storage")]
    Allocation,
    #[error("body-only unwind requires contiguous leaf instructions writing volatile registers")]
    UnsupportedLeaf,
}

/// One placed body instance; all offsets are relative to the supplied image base
#[derive(Debug)]
pub struct BodyInstance {
    image: Vec<u8>,
    stream: Range<usize>,
    table: usize,
    handlers: Vec<usize>,
    /// One window per ALU handler where its PUSHFQ result still occupies a native slot
    flags_pops: Vec<Range<usize>>,
    opcodes: Vec<u8>,
    variant: u8,
    initial_key: Option<u64>,
    cryptors: Option<Cryptors>,
    max_stack_bytes: usize,
}

impl BodyInstance {
    /// Generates an unencrypted forward stream and its matching native processor
    ///
    /// `variant` selects a bounded deterministic layout recipe, not cryptographic entropy
    /// Sealed MOV/ADD/SUB bodies have balanced stack use of at most 24 bytes
    pub fn generate(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        Self::build(bodies, base, variant, None)
    }

    /// Uses one captured Classic byte-cryptor recipe, not randomized cryptographic strength
    pub fn generate_encrypted(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        Self::build(bodies, base, variant, Some(Cryptors::captured_classic()))
    }

    fn build(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
        cryptors: Option<Cryptors>,
    ) -> Result<Self, InstanceError> {
        if bodies.is_empty() || bodies.len() > 256 {
            return Err(InstanceError::BodyCount);
        }
        // Each command occupies at most nine bytes; fixed templates, table and gates fit
        // in the extra reservation even when the body uses all 256 instruction slots
        let capacity = 8192
            + bodies
                .iter()
                .map(|body| body.commands().len() * 9)
                .sum::<usize>();
        base.0
            .checked_add(capacity as u64)
            .ok_or(InstanceError::AddressOverflow)?;
        let mut image = Vec::new();
        image
            .try_reserve_exact(capacity)
            .map_err(|_| InstanceError::Allocation)?;
        // Trap, completion marker, then checked end-of-body dispatch
        image.extend_from_slice(&[0x0f, 0x0b, 0x0f, 0x0b]);
        image.extend_from_slice(&[0x4c, 0x39, 0xde]); // cmp rsi, r11
        image.extend_from_slice(&[0x0f, 0x84]);
        relative(&mut image, 2);
        image.extend_from_slice(&[0x0f, 0x87]); // ja trap
        relative(&mut image, 0);
        fetch(&mut image, cryptors.map(|c| c.opcode));
        image.extend_from_slice(&[0x41, 0xff, 0x24, 0xd2]); // jmp [r10 + rdx*8]

        let push = image.len();
        fetch(&mut image, cryptors.map(|c| c.operand));
        image.extend_from_slice(&[0x48, 0x8b, 0x04, 0x14]); // mov rax, [rsp + rdx]
        image.extend_from_slice(&[0x48, 0x83, 0xed, 8, 0x48, 0x89, 0x45, 0]);
        jump_dispatch(&mut image);

        let pop = image.len();
        image.extend_from_slice(&[0x48, 0x8b, 0x45, 0, 0x48, 0x83, 0xc5, 8]);
        fetch(&mut image, cryptors.map(|c| c.operand));
        image.extend_from_slice(&[0x48, 0x89, 0x04, 0x14]);
        jump_dispatch(&mut image);

        // One handler per ALU operation, in BINARY_OPS order
        let alu: Vec<AluHandler> = BINARY_OPS
            .iter()
            .map(|operation| alu_handler(&mut image, *operation))
            .collect();
        let push_sp = image.len();
        image.extend_from_slice(&[0x48, 0x89, 0xe8]); // mov rax, rbp
        image.extend_from_slice(&[0x48, 0x83, 0xed, 8, 0x48, 0x89, 0x45, 0]);
        jump_dispatch(&mut image);
        let load = image.len();
        image.extend_from_slice(&[0x48, 0x8b, 0x45, 0, 0x48, 0x8b, 0, 0x48, 0x89, 0x45, 0]);
        jump_dispatch(&mut image);
        let immediate = image.len();
        image.extend_from_slice(&[0x48, 0x8b, 0x06, 0x48, 0x83, 0xc6, 8]);
        if let Some(c) = cryptors {
            c.immediate.emit(&mut image);
        }
        image.extend_from_slice(&[0x48, 0x83, 0xed, 8, 0x48, 0x89, 0x45, 0]);
        jump_dispatch(&mut image);
        let drop = image.len();
        image.extend_from_slice(&[0x48, 0x83, 0xc5, 8]);
        jump_dispatch(&mut image);
        while image.len() % 8 != 0 {
            image.push(0xcc);
        }
        let table = image.len();
        let mut handlers = vec![push, pop];
        handlers.extend(alu.iter().map(|handler| handler.entry));
        handlers.extend([push_sp, load, immediate, drop]);
        let flags_pops: Vec<Range<usize>> =
            alu.into_iter().map(|handler| handler.flags_pop).collect();
        // XOR is a permutation, so each handler receives a distinct instance-owned opcode
        let count = u8::try_from(handlers.len()).map_err(|_| InstanceError::UnsupportedCommand)?;
        let opcodes: Vec<u8> = (0..count).map(|index| variant ^ index).collect();
        for opcode in 0..=u8::MAX {
            let offset = opcodes
                .iter()
                .position(|o| *o == opcode)
                .map_or(0, |i| handlers[i]);
            image.extend_from_slice(&(base.0 + offset as u64).to_le_bytes());
        }
        let start = image.len();
        let initial_key = cryptors.map(|_| base.0 + start as u64);
        let mut key = initial_key.unwrap_or(0);
        for body in bodies {
            for command in body.commands() {
                let field_start = image.len();
                match *command {
                    Command::Stack(Instruction::PushReg {
                        width: Width::Qword,
                        register,
                    }) => {
                        image.extend_from_slice(&[opcodes[0], register_offset(register, variant)]);
                    }
                    Command::Stack(Instruction::PopReg {
                        width: Width::Qword,
                        register,
                    }) => {
                        image.extend_from_slice(&[opcodes[1], register_offset(register, variant)]);
                    }
                    Command::Stack(Instruction::PopFlags) => {
                        image.extend_from_slice(&[opcodes[1], slot_offset(15, variant)]);
                    }
                    Command::PushContext(register) => {
                        image.extend_from_slice(&[opcodes[0], context_offset(register, variant)]);
                    }
                    Command::PopContext(register) => {
                        image.extend_from_slice(&[opcodes[1], context_offset(register, variant)]);
                    }
                    Command::Stack(Instruction::PushStackPointer) => image.push(opcodes[4]),
                    Command::Stack(Instruction::LoadStack {
                        width: Width::Qword,
                    }) => image.push(opcodes[5]),
                    Command::Stack(Instruction::PushImm {
                        width: Width::Qword,
                        value,
                    }) => {
                        image.push(opcodes[6]);
                        image.extend_from_slice(&value.to_le_bytes());
                    }
                    Command::Stack(Instruction::Drop {
                        width: Width::Qword,
                    }) => image.push(opcodes[7]),
                    Command::Binary {
                        op,
                        width: Width::Qword,
                    } => {
                        let index = BINARY_OPS
                            .iter()
                            .position(|candidate| *candidate == op)
                            .ok_or(InstanceError::UnsupportedCommand)?;
                        image.push(opcodes[2 + index]);
                    }
                    Command::Stack(
                        Instruction::PushImm {
                            width: Width::Byte | Width::Word | Width::Dword,
                            ..
                        }
                        | Instruction::Drop {
                            width: Width::Byte | Width::Word | Width::Dword,
                        }
                        | Instruction::LoadStack {
                            width: Width::Byte | Width::Word | Width::Dword,
                        }
                        | Instruction::PushReg {
                            width: Width::Byte | Width::Word | Width::Dword,
                            ..
                        }
                        | Instruction::PopReg {
                            width: Width::Byte | Width::Word | Width::Dword,
                            ..
                        },
                    )
                    | Command::Binary {
                        width: Width::Byte | Width::Word | Width::Dword,
                        ..
                    } => {
                        return Err(InstanceError::UnsupportedCommand);
                    }
                }
                if let Some(c) = cryptors {
                    image[field_start] = c.opcode.encode(image[field_start], &mut key);
                    if let Command::Stack(Instruction::PushImm { value, .. }) = *command {
                        let encrypted = c.immediate.encode(value, &mut key);
                        image[field_start + 1..].copy_from_slice(&encrypted.to_le_bytes());
                    } else {
                        for byte in &mut image[field_start + 1..] {
                            *byte = c.operand.encode(*byte, &mut key);
                        }
                    }
                }
            }
        }
        let end = image.len();
        Ok(Self {
            image,
            stream: start..end,
            table,
            handlers,
            flags_pops,
            opcodes,
            variant,
            initial_key,
            cryptors,
            max_stack_bytes: bodies
                .iter()
                .map(LogicalInstruction::max_stack_bytes)
                .max()
                .unwrap_or(0),
        })
    }

    pub fn image(&self) -> &[u8] {
        &self.image
    }
    pub fn initial_key(&self) -> Option<u64> {
        self.cryptors.and(self.initial_key)
    }
    pub fn stream(&self) -> Range<usize> {
        self.stream.clone()
    }
    pub fn table_offset(&self) -> usize {
        self.table
    }
    /// Handler offsets: push, pop, ADD, NOR, push SP, stack load, immediate, discard
    pub fn handlers(&self) -> &[usize] {
        &self.handlers
    }
    /// Opcodes in the same order as [`BodyInstance::handlers`]
    pub fn opcodes(&self) -> &[u8] {
        &self.opcodes
    }
    pub fn register_offset(&self, register: Register) -> u8 {
        register_offset(register, self.variant)
    }
    pub fn flags_offset(&self) -> u8 {
        slot_offset(15, self.variant)
    }
    pub fn entry_offset(&self) -> usize {
        4
    }
    pub fn completion_offset(&self) -> usize {
        2
    }
    pub fn max_stack_bytes(&self) -> usize {
        self.max_stack_bytes
    }
}

/// Scalar native CALL/RET gate and its body processor in one placed image
///
/// Captures RFLAGS and all GPRs except RSP before using work registers, and restores
/// them from the modified context before RET. ADD/SUB promise the six arithmetic flag values
/// The caller supplies a writable native stack, benign control flags and the original
/// return address. The leaf-unwind constructor additionally describes entry, body and exit
/// SIMD/control-state preservation and PE serialization are outside this generator
#[derive(Debug)]
pub struct NativeInstance {
    body: BodyInstance,
    entry: usize,
    exit: usize,
    gate_addresses: [usize; 4],
    shadow_address: Option<usize>,
    unwind: Option<LeafUnwind>,
    max_native_stack_bytes: usize,
}

impl NativeInstance {
    pub fn generate(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        Self::with_body(BodyInstance::generate(bodies, base, variant)?, base, None)
    }

    /// Initializes the instance-owned rolling key after capturing all guest registers
    pub fn generate_encrypted(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        Self::with_body(
            BodyInstance::generate_encrypted(bodies, base, variant)?,
            base,
            None,
        )
    }

    /// Generates an encrypted leaf with native shadows and a body-only exception handler
    ///
    /// The source instructions must be the complete contiguous body of a native leaf
    /// with no prologue, stack changes or nonvolatile writes; its RET is not a body
    /// The caller must retain its native address/range for subsequent Windows unwind
    /// Gate metadata tracks partial saves and restores without invoking the body handler
    pub fn generate_leaf_unwind(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        use iced_x86::Register as R;
        let first = bodies
            .first()
            .ok_or(InstanceError::BodyCount)?
            .source()
            .raw()
            .ip();
        let mut expected = first;
        for body in bodies {
            let raw = body.source().raw();
            if raw.ip() != expected
                || !matches!(
                    raw.op0_register(),
                    R::RAX | R::RCX | R::RDX | R::R8 | R::R9 | R::R10 | R::R11
                )
            {
                return Err(InstanceError::UnsupportedLeaf);
            }
            expected = expected
                .checked_add(raw.len() as u64)
                .ok_or(InstanceError::AddressOverflow)?;
        }
        Self::with_body(
            BodyInstance::generate_encrypted(bodies, base, variant)?,
            base,
            Some(first),
        )
    }

    pub fn unwind(&self) -> Option<&LeafUnwind> {
        self.unwind.as_ref()
    }

    fn with_body(
        mut body: BodyInstance,
        base: VirtualAddress,
        native_rip: Option<u64>,
    ) -> Result<Self, InstanceError> {
        // Native register IDs in ascending context-slot order; 16 denotes flags
        let mut order = [16u8; 16];
        // Shadows end at 240; operand scratch must not overlap them at maximum depth
        let scratch = (240 + body.max_stack_bytes()).next_multiple_of(16).max(256);
        for register in [
            Register::Rax,
            Register::Rcx,
            Register::Rdx,
            Register::Rbx,
            Register::Rbp,
            Register::Rsi,
            Register::Rdi,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ] {
            order[usize::from(body.register_offset(register) / 8)] = register.id();
        }
        let exit = body.image.len();
        // Copy modified low context back to the saved frame above operand scratch
        for offset in (0..128u8).step_by(8) {
            body.image
                .extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, offset]);
            body.image.extend_from_slice(&[0x48, 0x89, 0x45, offset]);
        }
        body.image.extend_from_slice(&[0x48, 0x89, 0xec]); // mov rsp, rbp
        let mut exit_unwind = Vec::new();
        if native_rip.is_some() {
            exit_unwind.push((exit..body.image.len(), unwind::exit_codes(&order, scratch)));
        }
        for (index, id) in order.into_iter().enumerate() {
            let start = body.image.len();
            saved_register(&mut body.image, id, false);
            if native_rip.is_some() {
                exit_unwind.push((
                    start..body.image.len(),
                    unwind::exit_codes(&order[index..], 0),
                ));
            }
        }
        let ret = body.image.len();
        body.image.push(0xc3);
        if native_rip.is_some() {
            exit_unwind.push((ret..body.image.len(), unwind::exit_codes(&[], 0)));
        }

        let entry = body.image.len();
        let mut push_offsets = [0; 16];
        for (index, id) in order.into_iter().rev().enumerate() {
            saved_register(&mut body.image, id, true);
            push_offsets[index] = (body.image.len() - entry) as u8;
        }
        body.image.extend_from_slice(&[0x48, 0x89, 0xe5]); // mov rbp, rsp
        body.image.extend_from_slice(&[0x48, 0x81, 0xec]); // sub rsp, scratch
        body.image
            .extend_from_slice(&(scratch as u32).to_le_bytes());
        let entry_codes = unwind::entry_codes(
            order,
            push_offsets,
            (body.image.len() - entry) as u8,
            scratch,
        );
        // The body addresses context at RSP; its descending VM stack starts at RBP
        for offset in (0..128u8).step_by(8) {
            body.image.extend_from_slice(&[0x48, 0x8b, 0x45, offset]);
            body.image
                .extend_from_slice(&[0x48, 0x89, 0x44, 0x24, offset]);
        }
        let shadow_address = native_rip.map(|rip| unwind::shadows(&mut body, rip));
        let mut gate_addresses = [0; 4];
        for (index, (prefix, offset)) in [
            ([0x48, 0xbe], body.stream.start),
            ([0x49, 0xba], body.table),
            ([0x49, 0xbb], body.stream.end),
        ]
        .into_iter()
        .enumerate()
        {
            body.image.extend_from_slice(&prefix);
            gate_addresses[index] = body.image.len();
            body.image
                .extend_from_slice(&(base.0 + offset as u64).to_le_bytes());
        }
        if body.initial_key().is_some() {
            // The loader relocates zero into its signed delta; remove that delta from
            // the loaded stream pointer to recover the compiler's preferred-address key
            body.image.extend_from_slice(&[0x48, 0x89, 0xf7]); // mov rdi, rsi
            body.image.extend_from_slice(&[0x48, 0xb8]); // mov rax, relocation delta
            gate_addresses[3] = body.image.len();
            body.image.extend_from_slice(&0u64.to_le_bytes());
            body.image.extend_from_slice(&[0x48, 0x29, 0xc7]); // sub rdi, rax
        }
        // A register-direct jump is not a Windows tail epilogue; the entry frame is still live
        body.image.extend_from_slice(&[0x48, 0x8d, 0x05]);
        relative(&mut body.image, 4);
        body.image.extend_from_slice(&[0xff, 0xe0]);
        // Retarget the owned dispatch completion JE, leaving raw-body layout unchanged
        body.image[9..13].copy_from_slice(&(exit as i32 - 13).to_le_bytes());
        let unwind =
            native_rip.map(|_| unwind::handler(&mut body, entry, entry_codes, exit_unwind));
        Ok(Self {
            body,
            entry,
            exit,
            gate_addresses,
            shadow_address,
            unwind,
            max_native_stack_bytes: 128 + scratch + 8,
        })
    }

    pub fn image(&self) -> &[u8] {
        &self.body.image
    }
    pub fn entry_offset(&self) -> usize {
        self.entry
    }
    pub fn exit_offset(&self) -> usize {
        self.exit
    }

    /// Sorted image-relative offsets of little-endian fields requiring DIR64 relocation
    ///
    /// Includes table slots, gate pointers and the zero-valued loader-delta field
    /// Consumers must check conversion to their own address coordinates before publication
    /// Key initialization removes the loader delta, leaving encrypted fields unchanged
    pub fn absolute_address_offsets(&self) -> impl Iterator<Item = usize> + '_ {
        let count = if self.body.initial_key().is_some() {
            4
        } else {
            3
        };
        (self.body.table..self.body.table + 256 * 8)
            .step_by(8)
            .chain(self.shadow_address)
            .chain(self.gate_addresses[..count].iter().copied())
    }
    /// Below gate-entry RSP: saved context, aligned scratch and one PUSHF qword
    pub fn max_native_stack_bytes(&self) -> usize {
        self.max_native_stack_bytes
    }
}

fn fetch(image: &mut Vec<u8>, cryptor: Option<ByteCryptor>) {
    image.extend_from_slice(&[0x0f, 0xb6, 0x16, 0x48, 0xff, 0xc6]);
    if let Some(c) = cryptor {
        c.emit(image);
    }
}

fn saved_register(image: &mut Vec<u8>, id: u8, push: bool) {
    if id == 16 {
        image.push(if push { 0x9c } else { 0x9d });
    } else {
        if id >= 8 {
            image.push(0x41);
        }
        image.push((if push { 0x50 } else { 0x58 }) + (id & 7));
    }
}

fn register_offset(register: Register, variant: u8) -> u8 {
    let id = register.id();
    slot_offset(if id > 4 { id - 1 } else { id }, variant)
}

fn slot_offset(slot: u8, variant: u8) -> u8 {
    ((slot + (variant & 15)) & 15) * 8
}

/// Supported binary primitives in handler, opcode and unwind-range order
///
/// Each consumes `[rbp]` and `[rbp + 8]` and replaces them with flags above its result
const BINARY_OPS: [BinaryOp; 2] = [BinaryOp::Add, BinaryOp::Nor];

fn context_offset(register: ContextRegister, variant: u8) -> u8 {
    match register {
        ContextRegister::Flags => slot_offset(15, variant),
        ContextRegister::IntermediateFlags => 128,
    }
}

/// One generated binary ALU handler and the window its flags word is in flight
struct AluHandler {
    entry: usize,
    flags_pop: Range<usize>,
}

/// Emits a binary primitive over the two topmost VM stack slots, with raw flags on top
///
/// The PUSHFQ result lives on the *native* stack until the following POP moves it onto
/// the VM stack, so that one instruction runs with RSP 8 below the established frame.
/// Its range is reported separately because Windows unwind needs the shifted handler there
fn alu_handler(image: &mut Vec<u8>, operation: BinaryOp) -> AluHandler {
    let entry = image.len();
    image.extend_from_slice(&[0x48, 0x8b, 0x45, 0]); // mov rax, [rbp]
    match operation {
        BinaryOp::Add => image.extend_from_slice(&[0x48, 0x03, 0x45, 8]),
        BinaryOp::Nor => {
            image.extend_from_slice(&[0x48, 0x8b, 0x55, 8]); // mov rdx, [rbp + 8]
            image.extend_from_slice(&[0x48, 0xf7, 0xd0, 0x48, 0xf7, 0xd2]); // not rax; not rdx
            image.extend_from_slice(&[0x48, 0x21, 0xd0]); // and rax, rdx
        }
    }
    image.extend_from_slice(&[0x48, 0x89, 0x45, 8, 0x9c]);
    let start = image.len();
    image.extend_from_slice(&[0x8f, 0x45, 0]); // pop qword [rbp]
    let flags_pop = start..image.len();
    jump_dispatch(image);
    AluHandler { entry, flags_pop }
}

fn jump_dispatch(image: &mut Vec<u8>) {
    image.push(0xe9);
    relative(image, 4);
}

fn relative(image: &mut Vec<u8>, target: i32) {
    // Only fixed native templates call this, before the table and bounded stream
    let displacement = target - (image.len() as i32 + 4);
    image.extend_from_slice(&displacement.to_le_bytes());
}
