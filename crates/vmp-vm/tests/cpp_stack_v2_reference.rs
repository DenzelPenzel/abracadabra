//! Stage-2 C++ stack pins for the proposed v2, not a production VM or codec
//!
//! Expected arrays are manually pinned address-order bytes from the cited handlers
//! This does not execute C++, calculate arithmetic flags, model POPF privilege rules,
//! choose definedness provenance, or prove native allocation/guest-context relocation
//! Underflow, atomic errors and explicit byte budgets are Rust hardening, not C++ errors

#[derive(Debug, PartialEq, Eq)]
enum StackError {
    Underflow,
    Budget,
    SizeOverflow,
    Allocation,
}

// Address-order live bytes only: prepend means a logical downward SP movement
// This deliberately simple oracle reallocates instead of modeling guest relocation
struct ReferenceStack {
    bytes: Vec<u8>,
    budget: usize,
}

impl ReferenceStack {
    fn new(budget: usize) -> Self {
        Self {
            bytes: Vec::new(),
            budget,
        }
    }

    fn replace(&mut self, consumed: usize, prefix: &[u8]) -> Result<(), StackError> {
        let remaining = self
            .bytes
            .len()
            .checked_sub(consumed)
            .ok_or(StackError::Underflow)?;
        let required = remaining
            .checked_add(prefix.len())
            .ok_or(StackError::SizeOverflow)?;
        if required > self.budget {
            return Err(StackError::Budget);
        }
        let mut next = Vec::new();
        next.try_reserve_exact(required)
            .map_err(|_| StackError::Allocation)?;
        next.extend_from_slice(prefix);
        next.extend_from_slice(&self.bytes[consumed..]);
        self.bytes = next;
        Ok(())
    }

    fn push(&mut self, operand: &[u8]) -> Result<(), StackError> {
        assert!(matches!(operand.len(), 1 | 2 | 4 | 8));
        if operand.len() == 1 {
            self.replace(0, &[operand[0], 0])
        } else {
            self.replace(0, operand)
        }
    }

    fn pop(&mut self, width: usize) -> Result<Vec<u8>, StackError> {
        assert!(matches!(width, 1 | 2 | 4 | 8));
        let storage = width.max(2);
        if self.bytes.len() < storage {
            return Err(StackError::Underflow);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(width)
            .map_err(|_| StackError::Allocation)?;
        result.extend_from_slice(&self.bytes[..width]);
        self.bytes.drain(..storage);
        Ok(result)
    }

    // Output transport only: caller supplies independently pinned result and flags
    fn replace_with_result_flags(
        &mut self,
        consumed: usize,
        result: &[u8],
        flags: [u8; 8],
    ) -> Result<(), StackError> {
        assert!(matches!(result.len(), 1 | 2 | 4 | 8));
        let mut prefix = [0; 16];
        prefix[..8].copy_from_slice(&flags);
        prefix[8..8 + result.len()].copy_from_slice(result);
        self.replace(consumed, &prefix[..8 + result.len().max(2)])
    }

    // The sink records the transported word, not architectural POPF normalization
    fn pop_flags(&mut self, sink: &mut [u8; 8]) -> Result<(), StackError> {
        let word = self.pop(8)?;
        sink.copy_from_slice(&word);
        Ok(())
    }
}

#[test]
fn byte_push_is_zero_padded_word() {
    // files.cc:46-48; intel.cc:28838-28857 and 28907-28915
    let mut stack = ReferenceStack::new(2);
    stack.push(&[0xa5]).expect("byte push");
    assert_eq!(stack.bytes, [0xa5, 0]);
    assert_eq!(stack.pop(2).expect("word read"), [0xa5, 0]);
}

#[test]
fn byte_pop_consumes_word_but_returns_only_low_byte() {
    // intel.cc:28868,28879-28887 reads word, advances two, writes byte
    let mut stack = ReferenceStack::new(4);
    stack.push(&[0xa5, 0x5a, 0xcc, 0xdd]).expect("raw dword");
    assert_eq!(stack.pop(1).expect("byte read"), [0xa5]);
    assert_eq!(stack.bytes, [0xcc, 0xdd]);
}

#[test]
fn downward_push_preserves_address_order_across_growth() {
    // intel.cc:28852-28857 subtracts SP before each little-endian store
    let mut stack = ReferenceStack::new(6);
    stack.push(&[0x11, 0x22]).expect("old word");
    stack.push(&[0x33, 0x44, 0x55, 0x66]).expect("new dword");
    assert_eq!(stack.bytes, [0x33, 0x44, 0x55, 0x66, 0x11, 0x22]);
}

#[test]
fn mixed_width_read_crosses_old_push_boundaries_without_tags() {
    // intel.cc:28879-28885 has no check of the producing handler's width
    let mut stack = ReferenceStack::new(8);
    stack.push(&[1, 2, 3, 4]).expect("dword");
    stack.push(&[5, 6]).expect("word");
    stack.push(&[7, 8]).expect("word");
    assert_eq!(stack.pop(8).expect("qword"), [7, 8, 5, 6, 1, 2, 3, 4]);
    assert!(stack.bytes.is_empty());
}

#[test]
fn qword_can_be_split_into_raw_smaller_reads() {
    let mut stack = ReferenceStack::new(8);
    stack.push(&[1, 2, 3, 4, 5, 6, 7, 8]).expect("qword");
    assert_eq!(stack.pop(2).expect("word"), [1, 2]);
    assert_eq!(stack.pop(4).expect("dword"), [3, 4, 5, 6]);
    assert_eq!(stack.bytes, [7, 8]);
}

#[test]
fn underflow_leaves_live_bytes_unchanged() {
    let mut stack = ReferenceStack::new(2);
    assert_eq!(stack.pop(1), Err(StackError::Underflow));
    stack.push(&[0xa5]).expect("byte");
    assert_eq!(stack.pop(4), Err(StackError::Underflow));
    assert_eq!(stack.bytes, [0xa5, 0]);
}

#[test]
fn explicit_byte_budget_checks_promoted_size_before_mutating() {
    let mut zero = ReferenceStack::new(0);
    assert_eq!(zero.push(&[1]), Err(StackError::Budget));
    assert!(zero.bytes.is_empty());
    let mut one = ReferenceStack::new(1);
    assert_eq!(one.push(&[1]), Err(StackError::Budget));
    let mut exact = ReferenceStack::new(2);
    exact.push(&[1]).expect("exact promoted budget");
    assert_eq!(exact.push(&[2]), Err(StackError::Budget));
    assert_eq!(exact.bytes, [1, 0]);
}

#[test]
fn result_then_qword_flags_are_physical_outputs_not_implicit_apply() {
    // intel.cc:29203-29212: consume two words, result at new SP+8, flags at SP
    // Literal result/flags are supplied transport fixtures, not arithmetic goldens
    let mut stack = ReferenceStack::new(12);
    stack.push(&[0xcc, 0xdd]).expect("older live bytes");
    stack.push(&[1, 0]).expect("operand");
    stack.push(&[2, 0]).expect("operand");
    let flags_sink = [0x02, 0x02, 0, 0, 0, 0, 0, 0];
    stack
        .replace_with_result_flags(4, &[3, 0], [0x06, 0x02, 0, 0, 0, 0, 0, 0])
        .expect("physical outputs");
    assert_eq!(
        stack.bytes,
        [0x06, 0x02, 0, 0, 0, 0, 0, 0, 3, 0, 0xcc, 0xdd]
    );
    assert_eq!(flags_sink, [0x02, 0x02, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn separate_popflags_consumes_qword_and_leaves_result() {
    // intel.cc:29742-29749 and 31250-31251: consume pointer-width then POPF
    let mut stack = ReferenceStack::new(10);
    stack.push(&[3, 0]).expect("result");
    stack.push(&[0x06, 0x02, 0, 0, 0, 0, 0, 0]).expect("flags");
    let mut flags_sink = [0x02, 0x02, 0, 0, 0, 0, 0, 0];
    stack
        .pop_flags(&mut flags_sink)
        .expect("apply transport word");
    assert_eq!(flags_sink, [0x06, 0x02, 0, 0, 0, 0, 0, 0]);
    assert_eq!(stack.bytes, [3, 0]);
    assert_eq!(stack.pop_flags(&mut flags_sink), Err(StackError::Underflow));
    assert_eq!(flags_sink, [0x06, 0x02, 0, 0, 0, 0, 0, 0]);
    assert_eq!(stack.bytes, [3, 0]);
}

#[test]
fn discard_flags_does_not_apply_them() {
    // intel.cc:8738-8740,8760-8761 uses pop regEmpty, not cmPopf
    let mut stack = ReferenceStack::new(10);
    stack.push(&[3, 0]).expect("result");
    stack.push(&[0x06, 0x02, 0, 0, 0, 0, 0, 0]).expect("flags");
    let flags_sink = [0x02, 0x02, 0, 0, 0, 0, 0, 0];
    stack.pop(8).expect("discard qword");
    assert_eq!(stack.bytes, [3, 0]);
    assert_eq!(flags_sink, [0x02, 0x02, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn shl_transport_consumes_word_count_below_value() {
    // intel.cc:29296-29308: value at SP, count after promoted value, net growth six
    let mut stack = ReferenceStack::new(12);
    stack.push(&[1]).expect("promoted count");
    stack.push(&[2, 0, 0, 0]).expect("value");
    assert_eq!(stack.bytes, [2, 0, 0, 0, 1, 0]);
    stack
        .replace_with_result_flags(6, &[4, 0, 0, 0], [0x02, 0x02, 0, 0, 0, 0, 0, 0])
        .expect("supplied SHL output transport");
    assert_eq!(stack.bytes, [0x02, 0x02, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0]);
}

#[test]
fn physical_output_growth_failure_is_atomic() {
    let mut stack = ReferenceStack::new(9);
    stack.push(&[1, 0, 2, 0]).expect("operands");
    assert_eq!(
        stack.replace_with_result_flags(4, &[3, 0], [0; 8]),
        Err(StackError::Budget)
    );
    assert_eq!(stack.bytes, [1, 0, 2, 0]);
    assert_eq!(
        stack.replace_with_result_flags(6, &[3, 0], [0; 8]),
        Err(StackError::Underflow)
    );
    assert_eq!(stack.bytes, [1, 0, 2, 0]);
}
