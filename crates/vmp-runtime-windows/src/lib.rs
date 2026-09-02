//! Embedded Windows x64 VM runtime.

#[cfg(target_arch = "x86_64")]
mod runtime_x64;

#[cfg(target_arch = "x86_64")]
pub use runtime_x64::{execute_raw_gate, RuntimeExecution, RuntimeTrap, MAX_RUNTIME_CODE_SIZE};
