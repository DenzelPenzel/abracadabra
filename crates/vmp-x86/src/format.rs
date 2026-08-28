//! Human-readable disassembly text.
//!
//! Kept here rather than in the CLI so that iced-x86 stays an implementation
//! detail of this crate.

use iced_x86::{Formatter, MasmFormatter};
use vmp_ir::Instruction;

/// Formats instructions in MASM syntax.
///
/// Because instructions are decoded with `ip` set to their RVA, the addresses
/// printed for branch targets and RIP-relative operands are RVAs.
pub struct TextFormatter {
    inner: MasmFormatter,
}

impl TextFormatter {
    pub fn new() -> TextFormatter {
        let mut inner = MasmFormatter::new();
        let options = inner.options_mut();
        options.set_uppercase_hex(false);
        options.set_space_after_operand_separator(true);
        TextFormatter { inner }
    }

    /// Renders one instruction, mnemonic and operands only.
    pub fn format(&mut self, instruction: &Instruction) -> String {
        let mut text = String::new();
        self.inner.format(instruction.raw(), &mut text);
        text
    }
}

impl Default for TextFormatter {
    fn default() -> TextFormatter {
        TextFormatter::new()
    }
}
