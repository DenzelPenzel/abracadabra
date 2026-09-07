//! Coupled native handlers, context offsets, table and stream for bounded x64 bodies
//!
//! For the raw `BodyInstance`, RSP points to a writable 128-byte context, RBP to
//! the top of a separate descending byte stack, RSI to the stream, R10 to the table,
//! and R11 to the stream end. Reserve 16 bytes below RBP and 8 bytes below RSP
//! Entry is `entry_offset`; stop before `completion_offset` and read the context
//! RAX, RDX and native flags are scratch. Never execute externally modified images
//! Context, both stack scratch regions and image must be disjoint; flags output guarantees
//! only arithmetic bits. Native control flags must be benign (no TF); this is not POPF replay
//! Encrypted bodies additionally require RDI = `initial_key` and use it as scratch
//! `NativeInstance` adds scalar capture/restore; neither emits stack growth,
//! relocation records or unwind metadata

use std::ops::Range;
mod cryptor;
use cryptor::{ByteCryptor, Cryptors};
use thiserror::Error;
use vmp_types::VirtualAddress;

use crate::{
    logical::{Command, LogicalInstruction},
    operand::{Register, Width},
    stack::Instruction,
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
}

/// One placed body instance; all offsets are relative to the supplied image base
#[derive(Debug)]
pub struct BodyInstance {
    image: Vec<u8>,
    stream: Range<usize>,
    table: usize,
    handlers: [usize; 3],
    opcodes: [u8; 3],
    variant: u8,
    initial_key: Option<u64>,
    cryptors: Option<Cryptors>,
}

impl BodyInstance {
    /// Generates an unencrypted forward stream and its matching native processor
    ///
    /// `variant` selects a bounded deterministic layout recipe, not cryptographic entropy
    /// Only sealed MOV/ADD bodies are accepted; each has balanced stack use of at most 16 bytes
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
        // The bounded code, 256 table slots and at most 9 stream bytes per body fit here
        const CAPACITY: usize = 8192;
        base.0
            .checked_add(CAPACITY as u64)
            .ok_or(InstanceError::AddressOverflow)?;
        let mut image = Vec::new();
        image
            .try_reserve_exact(CAPACITY)
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

        let add = image.len();
        image.extend_from_slice(&[0x48, 0x8b, 0x45, 0]);
        image.extend_from_slice(&[0x48, 0x03, 0x45, 8]); // add rax, [rbp + 8]
        image.extend_from_slice(&[0x48, 0x89, 0x45, 8, 0x9c, 0x8f, 0x45, 0]);
        jump_dispatch(&mut image);
        while image.len() % 8 != 0 {
            image.push(0xcc);
        }
        let table = image.len();
        let handlers = [push, pop, add];
        let opcodes = [variant, variant ^ 1, variant ^ 2];
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
                    Command::Add {
                        width: Width::Qword,
                    } => image.push(opcodes[2]),
                    Command::Stack(
                        Instruction::PushImm { .. }
                        | Instruction::Drop { .. }
                        | Instruction::PushReg {
                            width: Width::Byte | Width::Word | Width::Dword,
                            ..
                        }
                        | Instruction::PopReg {
                            width: Width::Byte | Width::Word | Width::Dword,
                            ..
                        },
                    )
                    | Command::Add {
                        width: Width::Byte | Width::Word | Width::Dword,
                    } => {
                        return Err(InstanceError::UnsupportedCommand);
                    }
                }
                if let Some(c) = cryptors {
                    for (index, byte) in image[field_start..].iter_mut().enumerate() {
                        let cryptor = if index == 0 { c.opcode } else { c.operand };
                        *byte = cryptor.encode(*byte, &mut key);
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
            opcodes,
            variant,
            initial_key,
            cryptors,
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
    /// Push, pop and ADD handler offsets, in that order
    pub fn handlers(&self) -> [usize; 3] {
        self.handlers
    }
    pub fn opcodes(&self) -> [u8; 3] {
        self.opcodes
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
        16
    }
}

/// Scalar native CALL/RET gate and its body processor in one placed image
///
/// Captures RFLAGS and all GPRs except RSP before using work registers, and restores
/// them from the modified context before RET. Only arithmetic flags are promised for ADD
/// The caller supplies a writable native stack, benign control flags and the original
/// return address. No exception/unwind, SIMD/control-state or PE integration is claimed
#[derive(Debug)]
pub struct NativeInstance {
    body: BodyInstance,
    entry: usize,
    exit: usize,
}

impl NativeInstance {
    pub fn generate(
        bodies: &[LogicalInstruction<'_>],
        base: VirtualAddress,
        variant: u8,
    ) -> Result<Self, InstanceError> {
        Self::with_body(BodyInstance::generate(bodies, base, variant)?, base)
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
        )
    }

    fn with_body(mut body: BodyInstance, base: VirtualAddress) -> Result<Self, InstanceError> {
        // Native register IDs in ascending context-slot order; 16 denotes flags
        let mut order = [16u8; 16];
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
        for id in order {
            saved_register(&mut body.image, id, false);
        }
        body.image.push(0xc3);

        let entry = body.image.len();
        for id in order.into_iter().rev() {
            saved_register(&mut body.image, id, true);
        }
        body.image.extend_from_slice(&[0x48, 0x89, 0xe5]); // mov rbp, rsp
        body.image
            .extend_from_slice(&[0x48, 0x81, 0xec, 0, 1, 0, 0]); // sub rsp, 256
                                                                 // The body addresses context at RSP; its descending VM stack starts at RBP
        for offset in (0..128u8).step_by(8) {
            body.image.extend_from_slice(&[0x48, 0x8b, 0x45, offset]);
            body.image
                .extend_from_slice(&[0x48, 0x89, 0x44, 0x24, offset]);
        }
        for (prefix, offset) in [
            ([0x48, 0xbe], body.stream.start),
            ([0x49, 0xba], body.table),
            ([0x49, 0xbb], body.stream.end),
        ] {
            body.image.extend_from_slice(&prefix);
            body.image
                .extend_from_slice(&(base.0 + offset as u64).to_le_bytes());
        }
        if let Some(key) = body.initial_key() {
            body.image.extend_from_slice(&[0x48, 0xbf]); // mov rdi, initial key
            body.image.extend_from_slice(&key.to_le_bytes());
        }
        jump_dispatch(&mut body.image);
        // Retarget the owned dispatch completion JE, leaving raw-body layout unchanged
        body.image[9..13].copy_from_slice(&(exit as i32 - 13).to_le_bytes());
        Ok(Self { body, entry, exit })
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
    /// Below gate-entry RSP: 128 saved bytes, 256 scratch bytes, one PUSHF qword
    pub fn max_native_stack_bytes(&self) -> usize {
        392
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

fn jump_dispatch(image: &mut Vec<u8>) {
    image.push(0xe9);
    relative(image, 4);
}

fn relative(image: &mut Vec<u8>, target: i32) {
    // Only fixed native templates call this, before the table and bounded stream
    let displacement = target - (image.len() as i32 + 4);
    image.extend_from_slice(&displacement.to_le_bytes());
}
