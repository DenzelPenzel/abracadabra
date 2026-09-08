//! Operand types shared by logical commands and host semantic models

/// Operand width in bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Width {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

impl Width {
    pub(crate) fn byte_len(self) -> usize {
        self as usize
    }

    pub(crate) fn mask(self) -> u64 {
        match self {
            Self::Byte => u64::from(u8::MAX),
            Self::Word => u64::from(u16::MAX),
            Self::Dword => u64::from(u32::MAX),
            Self::Qword => u64::MAX,
        }
    }
}

/// Supported x64 general-purpose registers, excluding the native stack pointer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    pub(crate) fn id(self) -> u8 {
        match self {
            Self::Rax => 0,
            Self::Rcx => 1,
            Self::Rdx => 2,
            Self::Rbx => 3,
            Self::Rbp => 5,
            Self::Rsi => 6,
            Self::Rdi => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
            Self::R11 => 11,
            Self::R12 => 12,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
        }
    }
}

/// Canonical x86 condition-code nibble
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Condition {
    O = 0,
    No = 1,
    B = 2,
    Ae = 3,
    E = 4,
    Ne = 5,
    Be = 6,
    A = 7,
    S = 8,
    Ns = 9,
    P = 10,
    Np = 11,
    L = 12,
    Ge = 13,
    Le = 14,
    G = 15,
}
