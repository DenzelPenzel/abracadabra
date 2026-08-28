use std::collections::TryReserveError;

use super::display_string;

/// A demangled function name and the byte offset of its selector portion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionName {
    full_name: String,
    selector_start: usize,
}

/// A validation error for a parser-produced [`FunctionName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FunctionNameError {
    /// The selector begins beyond the end of the full name.
    SelectorOutOfBounds { selector_start: usize, len: usize },
    /// The selector begins in the middle of a UTF-8 code point.
    SelectorNotCharBoundary { selector_start: usize },
}

impl FunctionName {
    /// Builds a parser result after validating its selector byte offset.
    pub(crate) fn new(
        full_name: impl Into<String>,
        selector_start: usize,
    ) -> Result<Self, FunctionNameError> {
        let full_name = full_name.into();
        if selector_start > full_name.len() {
            return Err(FunctionNameError::SelectorOutOfBounds {
                selector_start,
                len: full_name.len(),
            });
        }
        if !full_name.is_char_boundary(selector_start) {
            return Err(FunctionNameError::SelectorNotCharBoundary { selector_start });
        }

        Ok(Self {
            full_name,
            selector_start,
        })
    }

    /// Returns an empty function name.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            full_name: String::new(),
            selector_start: 0,
        }
    }

    /// Returns a function name that preserves an input no parser recognized.
    pub(crate) fn unchanged(raw: impl Into<String>) -> Self {
        Self {
            full_name: raw.into(),
            selector_start: 0,
        }
    }

    pub(crate) fn try_unchanged(raw: &str) -> Result<Self, TryReserveError> {
        let mut full_name = String::new();
        full_name.try_reserve_exact(raw.len())?;
        full_name.push_str(raw);
        Ok(Self {
            full_name,
            selector_start: 0,
        })
    }

    /// Consumes the result and returns its selector portion without allocating.
    #[must_use]
    pub fn into_name(mut self) -> String {
        self.full_name.drain(..self.selector_start);
        self.full_name
    }

    /// Returns the selector portion of the demangled name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.full_name[self.selector_start..]
    }

    /// Returns the complete demangled representation.
    #[must_use]
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    #[must_use]
    pub fn display_name(&self, show_return_type: bool) -> String {
        let name = if show_return_type {
            self.full_name()
        } else {
            self.name()
        };
        display_string(name)
    }
}
