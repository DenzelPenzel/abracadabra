//! The jump left behind at a protected function's original entry.

use vmp_pe::{PeError, PeFile};
use vmp_types::Rva;

/// `E9 rel32` — the only encoding used, because the short form cannot reach an
/// appended section and a stub that sometimes changes size would change what
/// the bytes after it mean.
pub(crate) const STUB_LEN: u32 = 5;

const JMP_NEAR: u8 = 0xe9;
const NOP: u8 = 0x90;

/// A five-byte jump from a function's original entry to its mutated copy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stub {
    from: Rva,
    to: Rva,
    span_len: u32,
}

impl Stub {
    pub(crate) fn new(from: Rva, to: Rva) -> Stub {
        Stub {
            from,
            to,
            span_len: STUB_LEN,
        }
    }

    pub(crate) fn spanning(from: Rva, to: Rva, span_len: u32) -> Stub {
        Stub { from, to, span_len }
    }

    /// Writes the jump over the first [`STUB_LEN`] bytes of the function.
    ///
    /// Only those bytes change. The rest of the original body stays in the
    /// file: overwriting it would gain nothing and would destroy the evidence a
    /// crash dump needs.
    pub(crate) fn write(&self, pe: &PeFile, data: &mut [u8]) -> Result<(), PeError> {
        if self.span_len < STUB_LEN {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the protected entry span is shorter than a near jump",
            });
        }
        let offset = pe.rva_to_offset(self.from)?.get() as usize;
        let span_len =
            usize::try_from(self.span_len).map_err(|_| PeError::UnsupportedRewriteLayout {
                reason: "the protected entry span does not fit the host address width",
            })?;
        let end = offset
            .checked_add(span_len)
            .ok_or(PeError::UnsupportedRewriteLayout {
                reason: "the protected entry span overflows the file address width",
            })?;
        if end > data.len() {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the entry of a protected function is not backed by file bytes",
            });
        }
        let last_rva =
            self.from
                .checked_add(self.span_len - 1)
                .ok_or(PeError::UnsupportedRewriteLayout {
                    reason: "the protected entry span ends beyond the RVA address width",
                })?;
        let last_offset = pe.rva_to_offset(last_rva)?.get() as usize;
        if last_offset != end - 1 {
            return Err(PeError::UnsupportedRewriteLayout {
                reason: "the protected entry span is not contiguous in the file",
            });
        }

        // A near jump is relative to the address after it
        let next = self
            .from
            .checked_add(STUB_LEN)
            .ok_or(PeError::UnsupportedRewriteLayout {
                reason: "a protected function ends at the top of the address space",
            })?;
        let displacement = i64::from(self.to.get()) - i64::from(next.get());
        let displacement =
            i32::try_from(displacement).map_err(|_| PeError::UnsupportedRewriteLayout {
                reason: "the mutated copy is out of reach of a near jump from the original entry",
            })?;

        data[offset..end].fill(NOP);
        data[offset] = JMP_NEAR;
        data[offset + 1..offset + STUB_LEN as usize].copy_from_slice(&displacement.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forward_jump_encodes_its_displacement() {
        // 0x1000 -> 0x2000 is +0x1000 from the address after the jump
        let stub = Stub::new(Rva(0x1000), Rva(0x2000));
        let displacement = i64::from(stub.to.get()) - i64::from(stub.from.get() + STUB_LEN);
        assert_eq!(displacement, 0x0ffb);
    }

    #[test]
    fn a_backward_jump_encodes_a_negative_displacement() {
        let stub = Stub::new(Rva(0x2000), Rva(0x1000));
        let displacement = i64::from(stub.to.get()) - i64::from(stub.from.get() + STUB_LEN);
        assert_eq!(displacement, -0x1005);
    }
}
