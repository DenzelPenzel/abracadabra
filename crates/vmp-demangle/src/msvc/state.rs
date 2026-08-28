use crate::error::ParseFailure;
use crate::limits::{MAX_BACKREFERENCES, MAX_OUTPUT_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BudgetReservation {
    next_used: usize,
}

pub(super) struct AttemptBudget {
    used: usize,
    limit: usize,
}

impl AttemptBudget {
    pub(super) fn new() -> Self {
        Self::with_limit(MAX_OUTPUT_BYTES)
    }

    pub(super) fn with_limit(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    #[cfg(test)]
    pub(super) fn with_used_and_limit(used: usize, limit: usize) -> Self {
        Self { used, limit }
    }

    pub(super) fn preflight(&self, additional: usize) -> Result<BudgetReservation, ParseFailure> {
        if additional > MAX_OUTPUT_BYTES {
            return Err(ParseFailure::OutputLimitExceeded {
                attempted: additional,
                limit: MAX_OUTPUT_BYTES,
            });
        }
        let next_used =
            self.used
                .checked_add(additional)
                .ok_or(ParseFailure::OutputLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limit,
                })?;
        if next_used > self.limit {
            return Err(ParseFailure::OutputLimitExceeded {
                attempted: next_used,
                limit: self.limit,
            });
        }
        Ok(BudgetReservation { next_used })
    }

    pub(super) fn commit(&mut self, reservation: BudgetReservation) {
        self.used = reservation.next_used;
    }

    #[cfg(test)]
    pub(super) fn used(&self) -> usize {
        self.used
    }

    pub(super) fn copy_string(&mut self, value: &str) -> Result<String, ParseFailure> {
        let reservation = self.preflight(value.len())?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| ParseFailure::OutputAllocationFailed {
                additional: value.len(),
            })?;
        owned.push_str(value);
        self.commit(reservation);
        Ok(owned)
    }
}

pub(super) struct RefArray {
    start: usize,
    num: usize,
    max: usize,
    slots: Vec<String>,
    limit: usize,
}

#[derive(Debug, Clone, Copy)]
enum InsertTransition {
    Overwrite,
    OverwriteThenAppend,
    Append,
}

impl RefArray {
    pub(super) fn new() -> Self {
        Self::with_limit(MAX_BACKREFERENCES)
    }

    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            start: 0,
            num: 0,
            max: 0,
            slots: Vec::new(),
            limit,
        }
    }

    pub(super) fn push(
        &mut self,
        value: &str,
        budget: &mut AttemptBudget,
    ) -> Result<(), ParseFailure> {
        self.preflight_invariants()?;
        let next_num = self.preflight_capacity(1)?;
        let transition = if self.num < self.max {
            InsertTransition::Overwrite
        } else {
            InsertTransition::Append
        };
        let required_tail = usize::from(next_num > self.max);
        self.slots.try_reserve(required_tail).map_err(|_| {
            ParseFailure::ReferenceAllocationFailed {
                additional: required_tail,
            }
        })?;
        let value = budget.copy_string(value)?;

        match transition {
            InsertTransition::Overwrite => {
                let slots_len = self.slots.len();
                let slot =
                    self.slots
                        .get_mut(self.num)
                        .ok_or(ParseFailure::ReferenceStateCorrupt {
                            index: self.num,
                            slots_len,
                            max: self.max,
                        })?;
                *slot = value;
            }
            InsertTransition::Append => self.slots.push(value),
            InsertTransition::OverwriteThenAppend => {
                return Err(ParseFailure::ReferenceStateCorrupt {
                    index: self.num,
                    slots_len: self.slots.len(),
                    max: self.max,
                });
            }
        }

        self.num = next_num;
        if self.num > self.max {
            self.max = self.num;
        }
        Ok(())
    }

    pub(super) fn replace_last_active(
        &mut self,
        value: &str,
        budget: &mut AttemptBudget,
    ) -> Result<(), ParseFailure> {
        self.preflight_invariants()?;
        if self.start > self.max {
            return Err(ParseFailure::ReferenceStateCorrupt {
                index: self.start,
                slots_len: self.slots.len(),
                max: self.max,
            });
        }
        let index = self
            .num
            .checked_sub(1)
            .ok_or(ParseFailure::ActiveReferenceOutOfRange {
                index: 0,
                num: self.num,
            })?;
        if self.slots.get(index).is_none() {
            return Err(ParseFailure::ActiveReferenceStateCorrupt {
                index,
                num: self.num,
                slots_len: self.slots.len(),
            });
        }

        let reservation = budget.preflight(value.len())?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| ParseFailure::OutputAllocationFailed {
                additional: value.len(),
            })?;
        owned.push_str(value);

        let slots_len = self.slots.len();
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ParseFailure::ActiveReferenceStateCorrupt {
                index,
                num: self.num,
                slots_len,
            })?;
        *slot = owned;
        budget.commit(reservation);
        Ok(())
    }

    pub(super) fn replace_active_owned(
        &mut self,
        index: usize,
        value: String,
    ) -> Result<(), ParseFailure> {
        self.preflight_invariants()?;
        if index >= self.num {
            return Err(ParseFailure::ActiveReferenceOutOfRange {
                index,
                num: self.num,
            });
        }
        let slots_len = self.slots.len();
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ParseFailure::ActiveReferenceStateCorrupt {
                index,
                num: self.num,
                slots_len,
            })?;
        *slot = value;
        Ok(())
    }

    pub(super) fn push_pair(
        &mut self,
        left: &str,
        right: &str,
        budget: &mut AttemptBudget,
    ) -> Result<(), ParseFailure> {
        self.preflight_invariants()?;
        let next_num = self.preflight_capacity(2)?;
        let transition = if next_num <= self.max {
            InsertTransition::Overwrite
        } else if self.max.checked_sub(1) == Some(self.num) {
            InsertTransition::OverwriteThenAppend
        } else {
            InsertTransition::Append
        };
        let required_tail = next_num.saturating_sub(self.max);
        self.slots.try_reserve(required_tail).map_err(|_| {
            ParseFailure::ReferenceAllocationFailed {
                additional: required_tail,
            }
        })?;

        let total_len =
            left.len()
                .checked_add(right.len())
                .ok_or(ParseFailure::OutputLimitExceeded {
                    attempted: usize::MAX,
                    limit: MAX_OUTPUT_BYTES,
                })?;
        let reservation = budget.preflight(total_len)?;
        let mut left_owned = String::new();
        left_owned.try_reserve_exact(left.len()).map_err(|_| {
            ParseFailure::OutputAllocationFailed {
                additional: left.len(),
            }
        })?;
        left_owned.push_str(left);
        let mut right_owned = String::new();
        right_owned.try_reserve_exact(right.len()).map_err(|_| {
            ParseFailure::OutputAllocationFailed {
                additional: right.len(),
            }
        })?;
        right_owned.push_str(right);
        budget.commit(reservation);

        match transition {
            InsertTransition::Overwrite => {
                let slots_len = self.slots.len();
                let pair = self.slots.get_mut(self.num..next_num).ok_or(
                    ParseFailure::ReferenceStateCorrupt {
                        index: self.num,
                        slots_len,
                        max: self.max,
                    },
                )?;
                let [left_slot, right_slot] = pair else {
                    return Err(ParseFailure::ReferenceStateCorrupt {
                        index: self.num,
                        slots_len,
                        max: self.max,
                    });
                };
                *left_slot = left_owned;
                *right_slot = right_owned;
            }
            InsertTransition::OverwriteThenAppend => {
                let slots_len = self.slots.len();
                let left_slot =
                    self.slots
                        .get_mut(self.num)
                        .ok_or(ParseFailure::ReferenceStateCorrupt {
                            index: self.num,
                            slots_len,
                            max: self.max,
                        })?;
                *left_slot = left_owned;
                self.slots.push(right_owned);
            }
            InsertTransition::Append => {
                self.slots.push(left_owned);
                self.slots.push(right_owned);
            }
        }

        self.num = next_num;
        if next_num > self.max {
            self.max = next_num;
        }
        Ok(())
    }

    fn preflight_invariants(&self) -> Result<(), ParseFailure> {
        let slots_len = self.slots.len();
        if self.num > self.max {
            return Err(ParseFailure::ReferenceStateCorrupt {
                index: self.num,
                slots_len,
                max: self.max,
            });
        }
        if self.max != slots_len {
            return Err(ParseFailure::ReferenceStateCorrupt {
                index: self.max,
                slots_len,
                max: self.max,
            });
        }
        Ok(())
    }

    fn preflight_capacity(&self, additional: usize) -> Result<usize, ParseFailure> {
        let next_num =
            self.num
                .checked_add(additional)
                .ok_or(ParseFailure::ReferenceLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limit,
                })?;
        if next_num > self.limit {
            return Err(ParseFailure::ReferenceLimitExceeded {
                attempted: next_num,
                limit: self.limit,
            });
        }
        Ok(next_num)
    }

    pub(super) fn logical_start(&self) -> usize {
        self.start
    }

    pub(super) fn logical_num(&self) -> usize {
        self.num
    }

    pub(super) fn active_absolute_reference(&self, index: usize) -> Result<&str, ParseFailure> {
        if index >= self.num {
            return Err(ParseFailure::ActiveReferenceOutOfRange {
                index,
                num: self.num,
            });
        }
        self.slots
            .get(index)
            .map(String::as_str)
            .ok_or(ParseFailure::ActiveReferenceStateCorrupt {
                index,
                num: self.num,
                slots_len: self.slots.len(),
            })
    }

    pub(super) fn restore_num(&mut self, requested: usize) -> Result<(), ParseFailure> {
        if requested > self.max {
            return Err(ParseFailure::InvalidReferenceRestore {
                requested,
                max: self.max,
            });
        }
        self.num = requested;
        Ok(())
    }

    pub(super) fn set_start(&mut self, requested: usize) -> Result<(), ParseFailure> {
        if requested > self.max {
            return Err(ParseFailure::InvalidReferenceStart {
                requested,
                max: self.max,
            });
        }
        self.start = requested;
        Ok(())
    }

    pub(super) fn increment_start(&mut self) -> Result<(), ParseFailure> {
        let requested = self
            .start
            .checked_add(1)
            .ok_or(ParseFailure::InvalidReferenceStart {
                requested: usize::MAX,
                max: self.max,
            })?;
        self.set_start(requested)
    }

    pub(super) fn reference(&self, index: usize) -> Result<&str, ParseFailure> {
        let absolute =
            self.start
                .checked_add(index)
                .ok_or(ParseFailure::ReferenceIndexOverflow {
                    start: self.start,
                    index,
                })?;
        if absolute >= self.max {
            return Err(ParseFailure::ReferenceOutOfHighWater {
                start: self.start,
                index,
                max: self.max,
            });
        }
        self.slots
            .get(absolute)
            .map(String::as_str)
            .ok_or(ParseFailure::ReferenceStateCorrupt {
                index: absolute,
                slots_len: self.slots.len(),
                max: self.max,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{AttemptBudget, RefArray};
    use crate::error::ParseFailure;

    #[test]
    fn attempt_budget_accepts_exact_limit_rejects_one_over_and_overflow() {
        let mut exact = AttemptBudget::with_limit(3);
        let reservation = exact.preflight(3).expect("exact limit fits");
        exact.commit(reservation);
        assert_eq!(exact.used(), 3);
        assert_eq!(
            exact.preflight(1),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: 4,
                limit: 3,
            })
        );

        let overflowed = AttemptBudget::with_used_and_limit(usize::MAX, usize::MAX);
        assert_eq!(
            overflowed.preflight(1),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: usize::MAX,
                limit: usize::MAX,
            })
        );
    }

    #[test]
    fn fresh_array_has_c_invariants_and_no_reference() {
        let refs = RefArray::new();

        assert_eq!(refs.start, 0);
        assert_eq!(refs.num, 0);
        assert_eq!(refs.max, 0);
        assert!(refs.slots.is_empty());
        assert_eq!(
            refs.reference(0),
            Err(ParseFailure::ReferenceOutOfHighWater {
                start: 0,
                index: 0,
                max: 0,
            })
        );
    }

    #[test]
    fn rollback_preserves_historical_high_water_reference() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");
        refs.push("B", &mut budget).expect("within limit");

        refs.restore_num(1).expect("historical position");

        assert_eq!(refs.num, 1);
        assert_eq!(refs.max, 2);
        assert_eq!(refs.reference(1), Ok("B"));
    }

    #[test]
    fn push_after_rollback_overwrites_slot_without_lowering_high_water() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");
        refs.push("B", &mut budget).expect("within limit");
        refs.restore_num(1).expect("historical position");

        refs.push("C", &mut budget).expect("within limit");

        assert_eq!(refs.num, 2);
        assert_eq!(refs.max, 2);
        assert_eq!(refs.slots.len(), 2);
        assert_eq!(refs.reference(1), Ok("C"));
    }

    #[test]
    fn start_scopes_the_backreference_window() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        for value in ["A", "B", "C"] {
            refs.push(value, &mut budget).expect("within limit");
        }

        refs.set_start(1).expect("inside high water");

        assert_eq!(refs.reference(0), Ok("B"));
        assert_eq!(refs.reference(1), Ok("C"));
    }

    #[test]
    fn increment_start_is_bounded_and_preserves_num_and_high_water() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(2);
        refs.push("A", &mut budget).expect("within limit");
        refs.push("B", &mut budget).expect("within limit");
        let shape = (refs.num, refs.max, refs.slots.clone());

        assert_eq!(refs.increment_start(), Ok(()));
        assert_eq!(refs.start, 1);
        assert_eq!((refs.num, refs.max, refs.slots.clone()), shape);
        assert_eq!(refs.reference(0), Ok("B"));

        refs.increment_start()
            .expect("high-water boundary is valid");
        assert_eq!(
            refs.increment_start(),
            Err(ParseFailure::InvalidReferenceStart {
                requested: 3,
                max: 2,
            })
        );
        assert_eq!(refs.start, 2);
        assert_eq!((refs.num, refs.max, refs.slots), shape);
    }

    #[test]
    fn reference_offset_overflow_is_typed_and_does_not_panic() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");
        refs.set_start(1).expect("high-water boundary is valid");

        assert_eq!(
            refs.reference(usize::MAX),
            Err(ParseFailure::ReferenceIndexOverflow {
                start: 1,
                index: usize::MAX,
            })
        );
    }

    #[test]
    fn reference_beyond_high_water_is_typed() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");

        assert_eq!(
            refs.reference(1),
            Err(ParseFailure::ReferenceOutOfHighWater {
                start: 0,
                index: 1,
                max: 1,
            })
        );
    }

    #[test]
    fn invalid_restore_and_start_leave_state_unchanged() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());

        assert_eq!(
            refs.restore_num(2),
            Err(ParseFailure::InvalidReferenceRestore {
                requested: 2,
                max: 1,
            })
        );
        assert_eq!(
            refs.set_start(2),
            Err(ParseFailure::InvalidReferenceStart {
                requested: 2,
                max: 1,
            })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
    }

    #[test]
    fn capacity_failure_is_atomic() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(1);
        refs.push("A", &mut budget).expect("within limit");
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());

        assert_eq!(
            refs.push("B", &mut budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
        assert_eq!(budget.used(), 1, "rejected value must not be charged");
    }

    #[test]
    fn replace_last_active_preserves_table_shape_and_scope() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(3);
        refs.push("Old", &mut budget).expect("within limit");
        refs.push("Encoded", &mut budget).expect("within limit");
        refs.set_start(1).expect("inside high water");
        let before_shape = (refs.start, refs.num, refs.max, refs.slots.len());

        refs.replace_last_active("Replacement", &mut budget)
            .expect("active slot exists");

        assert_eq!(
            (refs.start, refs.num, refs.max, refs.slots.len()),
            before_shape
        );
        assert_eq!(refs.reference(0), Ok("Replacement"));
        assert_eq!(
            budget.used(),
            "Old".len() + "Encoded".len() + "Replacement".len()
        );
    }

    #[test]
    fn replace_last_active_failures_are_typed_and_atomic() {
        let mut empty = RefArray::with_limit(1);
        let mut budget = AttemptBudget::new();
        assert_eq!(
            empty.replace_last_active("X", &mut budget),
            Err(ParseFailure::ActiveReferenceOutOfRange { index: 0, num: 0 })
        );
        assert_eq!(budget.used(), 0);

        let mut refs = RefArray::with_limit(1);
        refs.push("Encoded", &mut budget).expect("within limit");
        let used = budget.used();
        let mut exhausted = AttemptBudget::with_used_and_limit(used, used);
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());
        assert_eq!(
            refs.replace_last_active("Replacement", &mut exhausted),
            Err(ParseFailure::OutputLimitExceeded {
                attempted: used + "Replacement".len(),
                limit: used,
            })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
        assert_eq!(exhausted.used(), used);
    }

    #[test]
    fn replace_active_owned_preserves_shape_scope_and_charges_exactly_once() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(3);
        refs.push("Existing", &mut budget).expect("within limit");
        refs.push("Class", &mut budget).expect("within limit");
        refs.set_start(1).expect("inside high water");
        let before_shape = (refs.start, refs.num, refs.max, refs.slots.len());
        let used = budget.used();

        let replacement = budget.copy_string("Class").expect("within limit");
        refs.replace_active_owned(0, replacement)
            .expect("active slot exists");

        assert_eq!(
            (refs.start, refs.num, refs.max, refs.slots.len()),
            before_shape
        );
        assert_eq!(refs.active_absolute_reference(0), Ok("Class"));
        assert_eq!(refs.active_absolute_reference(1), Ok("Class"));
        assert_eq!(budget.used(), used + "Class".len());
    }

    #[test]
    fn replace_active_owned_failures_are_typed_atomic_and_uncharged() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(2);
        refs.push("Existing", &mut budget).expect("within limit");
        refs.push("Class", &mut budget).expect("within limit");
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());
        let used = budget.used();

        assert_eq!(
            refs.replace_active_owned(2, String::from("X")),
            Err(ParseFailure::ActiveReferenceOutOfRange { index: 2, num: 2 })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots.clone()), before);
        assert_eq!(budget.used(), used);

        let exhausted = AttemptBudget::with_used_and_limit(used, used);
        assert_eq!(
            refs.replace_active_owned(2, String::from("Y")),
            Err(ParseFailure::ActiveReferenceOutOfRange { index: 2, num: 2 })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
        assert_eq!(exhausted.used(), used);
    }

    #[test]
    fn pair_push_after_rollback_overwrites_both_slots_without_lowering_high_water() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push_pair("A", "B", &mut budget).expect("within limit");
        refs.push_pair("C", "D", &mut budget).expect("within limit");
        refs.restore_num(2).expect("historical pair boundary");

        refs.push_pair("E", "F", &mut budget).expect("within limit");

        assert_eq!(refs.num, 4);
        assert_eq!(refs.max, 4);
        assert_eq!(refs.slots.len(), 4);
        assert_eq!(refs.reference(2), Ok("E"));
        assert_eq!(refs.reference(3), Ok("F"));
    }

    #[test]
    fn pair_push_one_before_high_water_overwrites_then_appends() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        for value in ["A", "B", "C"] {
            refs.push(value, &mut budget).expect("within limit");
        }
        refs.restore_num(2).expect("historical position");

        refs.push_pair("X", "Y", &mut budget).expect("within limit");

        assert_eq!(refs.num, 4);
        assert_eq!(refs.max, 4);
        assert_eq!(refs.slots.len(), 4);
        assert_eq!(refs.reference(2), Ok("X"));
        assert_eq!(refs.reference(3), Ok("Y"));
    }

    #[test]
    fn corrupt_pair_state_is_rejected_without_mutation() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(4);
        refs.push("A", &mut budget).expect("within limit");
        refs.num = 2;
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());

        assert_eq!(
            refs.push_pair("X", "Y", &mut budget),
            Err(ParseFailure::ReferenceStateCorrupt {
                index: 2,
                slots_len: 1,
                max: 1,
            })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
    }

    #[test]
    fn pair_capacity_failure_leaves_exact_state_unchanged() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(2);
        refs.push("A", &mut budget).expect("within limit");
        let before = (refs.start, refs.num, refs.max, refs.slots.clone());

        assert_eq!(
            refs.push_pair("B", "C", &mut budget),
            Err(ParseFailure::ReferenceLimitExceeded {
                attempted: 3,
                limit: 2
            })
        );
        assert_eq!((refs.start, refs.num, refs.max, refs.slots), before);
        assert_eq!(budget.used(), 1, "rejected pair must not be charged");
    }

    #[test]
    fn active_absolute_reference_is_bounded_by_logical_num_not_high_water() {
        let mut budget = AttemptBudget::new();
        let mut refs = RefArray::with_limit(2);
        refs.push("A", &mut budget).expect("within limit");
        refs.push("B", &mut budget).expect("within limit");
        refs.restore_num(1).expect("historical position");

        assert_eq!(refs.logical_num(), 1);
        assert_eq!(refs.active_absolute_reference(0), Ok("A"));
        assert_eq!(
            refs.active_absolute_reference(1),
            Err(ParseFailure::ActiveReferenceOutOfRange { index: 1, num: 1 })
        );
    }

    #[test]
    fn active_absolute_reference_reports_corrupt_slot_context() {
        let mut refs = RefArray::with_limit(1);
        refs.num = 1;
        refs.max = 1;

        assert_eq!(
            refs.active_absolute_reference(0),
            Err(ParseFailure::ActiveReferenceStateCorrupt {
                index: 0,
                num: 1,
                slots_len: 0,
            })
        );
    }
}
