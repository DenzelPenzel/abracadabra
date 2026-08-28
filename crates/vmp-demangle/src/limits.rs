//! Conservative resource limits for demangler implementations.
//!
//! Unless documented otherwise, each limit is cumulative within one demangling attempt.

/// Maximum total decorated input accepted by one demangling attempt.
pub(crate) const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Maximum recursive grammar nesting depth reached during one demangling attempt.
///
/// Kept deliberately below the input-size-derived maximum so both the accepted
/// boundary and one-over rejection, including nested template class argument
/// frames, fit on a 64 KiB parser thread stack in debug and release builds.
pub(crate) const MAX_NESTING_DEPTH: usize = 8;

/// Maximum recursive depth for the mechanical MSVC undname port.
///
/// MSVC grammar frames are larger than GNU v3 frames; 6 is the exact accepted
/// boundary. Its cross-platform debug/release stack gate runs on a bounded
/// 256 KiB parser thread stack.
pub(crate) const MAX_MSVC_NESTING_DEPTH: usize = 6;

/// Maximum number of name/type components parsed during one demangling attempt.
///
/// Exact component accounting is defined by parser state.
pub(crate) const MAX_COMPONENTS: usize = 4 * 1024;

/// Maximum dimensions accepted in one standalone MSVC `$$B` array.
///
/// The bundled parser has no native cap for this loop. This per-array safety
/// boundary is separate from cumulative component accounting.
pub(crate) const MAX_STANDALONE_ARRAY_DIMENSIONS: usize = 4 * 1024;

/// Maximum number of datatypes collected by one MSVC argument-list helper.
///
/// The bundled native collector grows without a grammar-defined bound. This
/// per-list cap prevents an attacker-controlled collection loop from doing so.
pub(crate) const MAX_ARGUMENTS: usize = 128;

/// Maximum number of component back-references memorized during one demangling attempt.
///
/// Exact back-reference accounting is defined by parser state.
pub(crate) const MAX_BACKREFERENCES: usize = 4 * 1024;

/// Maximum total rendered output produced by one demangling attempt.
pub(crate) const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
