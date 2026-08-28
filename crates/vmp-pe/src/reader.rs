//! The crate's single bounds-checked byte-access layer.
//!
//! Every multi-byte read in the crate is little-endian and goes through this
//! module, in one of two modes:
//!
//! - [`Reader`] and [`slice`]/[`slice_mut`] take a `u64` file offset that may
//!   come straight from a header field, so they check the bound and report
//!   [`PeError::Truncated`] when it does not hold.
//! - [`le_u16`]/[`le_u32`]/[`le_u64`] take a `usize` offset into a slice the
//!   caller has *already* bounded, which is the shape every directory parser
//!   uses after resolving its structure against the mapped image.
//!
//! No path here can panic or read past the end of the buffer.

use core::ops::Range;

use crate::error::PeError;

/// Resolves `[offset, offset + size)` against a buffer of `len` bytes.
///
/// Both the addition and the narrowing to `usize` are checked, so an offset
/// taken verbatim from a malformed header cannot wrap into a valid range.
fn checked_range(offset: u64, size: u64, len: usize) -> Result<Range<usize>, PeError> {
    let truncated = || PeError::Truncated {
        offset,
        needed: size,
        available: len as u64,
    };
    let end = offset.checked_add(size).ok_or_else(truncated)?;
    let (Ok(start), Ok(end)) = (usize::try_from(offset), usize::try_from(end)) else {
        return Err(truncated());
    };
    if end > len {
        return Err(truncated());
    }
    Ok(start..end)
}

/// Returns the `size` bytes of `data` at `offset`, or [`PeError::Truncated`].
pub(crate) fn slice(data: &[u8], offset: u64, size: u64) -> Result<&[u8], PeError> {
    let range = checked_range(offset, size, data.len())?;
    data.get(range).ok_or(PeError::Truncated {
        offset,
        needed: size,
        available: data.len() as u64,
    })
}

/// Mutable counterpart of [`slice`].
pub(crate) fn slice_mut(data: &mut [u8], offset: u64, size: u64) -> Result<&mut [u8], PeError> {
    let available = data.len() as u64;
    let range = checked_range(offset, size, data.len())?;
    data.get_mut(range).ok_or(PeError::Truncated {
        offset,
        needed: size,
        available,
    })
}

/// Reads `N` little-endian bytes from a slice the caller has already bounded.
///
/// A read past the end cannot happen — every caller derives `offset` from a
/// length it has just validated — so the fallback exists only to keep the
/// helper total instead of panicking on a logic error. `debug_assert!` makes
/// that invariant something the test suite proves rather than something the
/// reader has to take on trust, while release builds keep the fail-soft value.
fn le_bytes<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    match bytes
        .get(offset..offset.wrapping_add(N))
        .and_then(|slice| slice.try_into().ok())
    {
        Some(array) => array,
        None => {
            debug_assert!(
                false,
                "read of {N} bytes at {offset} is past the {} byte bound the caller established",
                bytes.len()
            );
            [0; N]
        }
    }
}

pub(crate) fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(le_bytes(bytes, offset))
}

pub(crate) fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(le_bytes(bytes, offset))
}

pub(crate) fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(le_bytes(bytes, offset))
}

/// Reads one pointer-width address: eight bytes for PE32+, four for PE32.
pub(crate) fn le_address(bytes: &[u8], offset: usize, is_pe32_plus: bool) -> u64 {
    if is_pe32_plus {
        le_u64(bytes, offset)
    } else {
        u64::from(le_u32(bytes, offset))
    }
}

/// A read-only cursor over the PE bytes.
///
/// Every method takes an absolute offset from the start of the buffer, so the
/// reader can be freely reused for unrelated structures.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data }
    }

    /// Returns the slice `[offset, offset + len)` or `Truncated`.
    pub fn bytes(&self, offset: u64, len: u64) -> Result<&'a [u8], PeError> {
        slice(self.data, offset, len)
    }

    pub fn u16(&self, offset: u64) -> Result<u16, PeError> {
        Ok(le_u16(self.bytes(offset, 2)?, 0))
    }

    pub fn u32(&self, offset: u64) -> Result<u32, PeError> {
        Ok(le_u32(self.bytes(offset, 4)?, 0))
    }

    pub fn u64(&self, offset: u64) -> Result<u64, PeError> {
        Ok(le_u64(self.bytes(offset, 8)?, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian() {
        let data = [0x4d, 0x5a, 0x11, 0x22, 0x33, 0x44];
        let r = Reader::new(&data);
        assert_eq!(r.u16(0).expect("in bounds"), 0x5a4d);
        assert_eq!(r.u32(2).expect("in bounds"), 0x4433_2211);
    }

    #[test]
    fn truncated_read_errors_not_panics() {
        let data = [0x00, 0x01];
        let r = Reader::new(&data);
        assert!(matches!(r.u32(0), Err(PeError::Truncated { .. })));
        assert!(matches!(r.u16(1), Err(PeError::Truncated { .. })));
    }

    #[test]
    fn offset_overflow_is_truncated_not_panic() {
        let data = [0u8; 8];
        let r = Reader::new(&data);
        assert!(matches!(
            r.u64(u64::MAX - 2),
            Err(PeError::Truncated { .. })
        ));
    }

    #[test]
    fn size_overflow_is_truncated_not_panic() {
        let data = [0u8; 8];
        assert!(matches!(
            slice(&data, 4, u64::MAX),
            Err(PeError::Truncated { .. })
        ));
    }

    #[test]
    fn mutable_slice_shares_the_read_bounds() {
        let mut data = [0u8; 8];
        slice_mut(&mut data, 4, 4)
            .expect("in bounds")
            .copy_from_slice(&0x1122_3344u32.to_le_bytes());
        assert_eq!(le_u32(&data, 4), 0x1122_3344);
        assert!(matches!(
            slice_mut(&mut data, 4, 8),
            Err(PeError::Truncated { .. })
        ));
    }

    #[test]
    fn bounded_reads_are_little_endian() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        assert_eq!(le_u16(&data, 0), 0x2211);
        assert_eq!(le_u32(&data, 1), 0x5544_3322);
        assert_eq!(le_u64(&data, 1), 0x9988_7766_5544_3322);
        assert_eq!(le_address(&data, 1, true), 0x9988_7766_5544_3322);
        assert_eq!(le_address(&data, 1, false), 0x5544_3322);
    }

    /// The fallback is unreachable in practice, so this only pins the release
    /// behaviour; in debug the `debug_assert!` fires instead.
    #[test]
    #[cfg(not(debug_assertions))]
    fn out_of_bounds_bounded_read_yields_zero() {
        let data = [0x11, 0x22];
        assert_eq!(le_u32(&data, 0), 0);
        assert_eq!(le_u16(&data, usize::MAX), 0);
    }
}
