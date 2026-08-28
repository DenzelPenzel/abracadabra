use crate::error::ParseFailure;

pub(crate) struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn peek(&self, offset: usize) -> Option<u8> {
        let index = self.position.checked_add(offset)?;
        self.input.get(index).copied()
    }

    pub(crate) fn bytes(&self, start: usize, end: usize) -> Option<&'a [u8]> {
        self.input.get(start..end)
    }

    pub(crate) fn next(&mut self) -> Result<u8, ParseFailure> {
        let byte = self.peek(0).ok_or(ParseFailure::UnexpectedEnd {
            offset: self.position,
        })?;
        self.advance(1)?;
        Ok(byte)
    }

    pub(crate) fn advance(&mut self, amount: usize) -> Result<(), ParseFailure> {
        let next = self.position.checked_add(amount);
        match next {
            Some(next) if next <= self.input.len() => {
                self.position = next;
                Ok(())
            }
            _ => Err(ParseFailure::AdvanceOutOfBounds {
                offset: self.position,
                amount,
                len: self.input.len(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cursor;
    use crate::error::ParseFailure;

    #[test]
    fn positions_and_peek_offsets_are_byte_oriented_and_checked() {
        let cursor = Cursor::new(b"abc");

        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.peek(0), Some(b'a'));
        assert_eq!(cursor.peek(1), Some(b'b'));
        assert_eq!(cursor.peek(usize::MAX), None);
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn next_at_eof_returns_typed_error_without_advancing() {
        let mut cursor = Cursor::new(b"");

        assert_eq!(
            cursor.next(),
            Err(ParseFailure::UnexpectedEnd { offset: 0 })
        );
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn advance_accepts_exact_boundary_and_rejects_one_byte_over_without_movement() {
        let mut cursor = Cursor::new(b"abc");

        assert_eq!(cursor.advance(3), Ok(()));
        assert_eq!(cursor.position(), 3);
        assert_eq!(
            cursor.advance(1),
            Err(ParseFailure::AdvanceOutOfBounds {
                offset: 3,
                amount: 1,
                len: 3,
            })
        );
        assert_eq!(cursor.position(), 3);
    }

    #[test]
    fn advance_rejects_offset_overflow_without_movement() {
        let mut cursor = Cursor::new(b"a");
        cursor.advance(1).expect("exact boundary is valid");

        assert_eq!(
            cursor.advance(usize::MAX),
            Err(ParseFailure::AdvanceOutOfBounds {
                offset: 1,
                amount: usize::MAX,
                len: 1,
            })
        );
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn high_bit_values_are_ordinary_bytes() {
        let mut cursor = Cursor::new(&[0x80, 0xff]);

        assert_eq!(cursor.peek(0), Some(0x80));
        assert_eq!(cursor.next(), Ok(0x80));
        assert_eq!(cursor.next(), Ok(0xff));
        assert_eq!(cursor.position(), 2);
    }
}
