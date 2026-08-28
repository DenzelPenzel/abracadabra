//! Typed decoding errors.
//!
//! Only conditions that make decoding impossible are errors. Anything the
//! decoder can describe but not vouch for — an indirect jump, a branch out of
//! the function — is a [`DecodeIssue`](vmp_ir::DecodeIssue) on the resulting
//! function instead, so diagnostics still get a partial CFG.

use thiserror::Error;

use vmp_pe::PeError;
use vmp_types::Rva;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum X86Error {
    /// The image itself could not be read.
    #[error("PE error: {0}")]
    Pe(#[from] PeError),

    /// The requested entry point is not inside any section.
    #[error("entry {rva} is not mapped by any section")]
    EntryUnmapped { rva: Rva },

    /// The requested entry point is in a section without execute permission.
    #[error("entry {rva} is not in an executable section")]
    EntryNotExecutable { rva: Rva },

    /// Not a single instruction could be decoded at the entry.
    #[error("no instruction could be decoded at {rva}")]
    NothingDecoded { rva: Rva },

    /// Re-encoding the function failed.
    #[error("failed to encode block at {rva}: {reason}")]
    Encode { rva: Rva, reason: String },
}
