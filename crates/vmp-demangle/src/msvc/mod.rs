mod flags;
mod parser;
mod state;

use crate::FunctionName;

pub(super) fn demangle(raw: &str) -> Option<FunctionName> {
    parser::demangle(raw, flags::VMP_DEMANGLE_FLAGS).ok()
}
