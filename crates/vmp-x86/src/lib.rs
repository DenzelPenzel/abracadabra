//! x86-64 decoding, control-flow recovery and re-encoding.
//!
//! Given a parsed image and the address of a function, [`decode_function`]
//! reconstructs that function as a [`vmp_ir::Function`]: basic blocks, real
//! control-flow edges, and every operand reference that has to be rebound when
//! the code moves.
//!
//! The traversal is whose worklist mixes a linear
//! sweep with a four-pass link oracle and a speculative sub-disassembly for
//! ambiguous jumps; the `sweep` module documents the correspondence. Codec,
//! register and flags model, and block encoding come from iced-x86 per ADR-0001.
//!
//! # What makes a function unprotectable
//!
//! Decoding is deliberately generous — it returns whatever it could recover so
//! that diagnostics have something to show — and records every doubt in
//! [`vmp_ir::Function::issues`]. Only a function with no issues may be
//! modified. Indirect jumps are the common case: jump-table recovery is not
//! part of this stage, so any indirect jump makes the function off limits.

mod cfg;
mod decode;
mod encode;
mod epilogue;
mod error;
mod format;
mod image;
mod liveness;
pub mod marker_region;
mod refs;
pub mod sdk_markers;
mod sweep;

use std::cell::Cell;

use vmp_ir::{DecodeIssue, Function};
use vmp_types::Rva;

pub use encode::{encode_one, relocate, Relocated};
pub use epilogue::{epilogues, Epilogue};
pub use error::X86Error;
pub use format::TextFormatter;
pub use image::{Image, ImportName};
pub use liveness::{analyze as analyze_liveness, Flags, Liveness, Registers, State};

/// Generous for real functions, small enough to bound a hostile input.
pub const DEFAULT_BUDGET: usize = 200_000;

/// Knobs for [`decode_function_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Upper bound on the instructions one call may decode, including those
    /// decoded by speculative probes.
    ///
    /// The C++ original has no such bound; a protector that must fail closed
    /// cannot be made to spin on a crafted input.
    pub budget: usize,
}

impl Default for DecodeOptions {
    fn default() -> DecodeOptions {
        DecodeOptions {
            budget: DEFAULT_BUDGET,
        }
    }
}

/// Decodes the function that starts at `entry`.
pub fn decode_function(image: Image<'_>, entry: Rva) -> Result<Function, X86Error> {
    decode_function_with(image, entry, DecodeOptions::default())
}

/// Decodes the function that starts at `entry` with explicit options.
pub fn decode_function_with(
    image: Image<'_>,
    entry: Rva,
    options: DecodeOptions,
) -> Result<Function, X86Error> {
    decode_function_with_spent(image, entry, options).map(|(function, _)| function)
}

/// Decodes one function and reports all budget spent, including probes.
pub(crate) fn decode_function_with_spent(
    image: Image<'_>,
    entry: Rva,
    options: DecodeOptions,
) -> Result<(Function, usize), X86Error> {
    if !image.is_mapped(entry) {
        return Err(X86Error::EntryUnmapped { rva: entry });
    }
    if !image.is_executable(entry) {
        return Err(X86Error::EntryNotExecutable { rva: entry });
    }

    let budget = Cell::new(options.budget);
    let mut sweep = sweep::Sweep::new(image, entry, &budget, None);
    sweep.run();
    let result = sweep.finish();

    let mut issues = result.issues;
    if budget.get() == 0 {
        issues.push(DecodeIssue::BudgetExceeded {
            limit: options.budget,
        });
    }

    let spent = options.budget - budget.get();
    let unwind = image.runtime_function(entry);
    cfg::build(image.architecture(), entry, result.commands, unwind, issues)
        .map(|function| (function, spent))
}
