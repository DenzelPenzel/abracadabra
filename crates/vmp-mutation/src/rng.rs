//! The deterministic random source.
//!
//! Mutation has to be reproducible: the same input, the same seed and the same
//! build must produce the same output, or a protected binary cannot be
//! diffed, bisected or reported against. That rules out `rand`, whose
//! generators are explicitly allowed to change their output between versions,
//! so the generator is written out here — SplitMix64, which is four lines and
//! whose constants are fixed by its publication.

/// A seed for one protection run.
///
/// Deriving a per-function stream from it keeps functions independent: adding
/// or removing one function does not change what happens to any other, which
/// is what makes a diff of two protected builds readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seed(u64);

impl Seed {
    pub const fn new(value: u64) -> Seed {
        Seed(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The stream for the function entered at `rva`.
    pub fn for_function(self, rva: u32) -> Rng {
        // Mixing rather than adding so that adjacent entry points, which differ
        // in their low bits only, do not produce correlated streams
        Rng::new(mix(self.0 ^ (u64::from(rva) << 32 | u64::from(rva))))
    }
}

impl Default for Seed {
    /// A fixed value, so that a run without an explicit seed is still
    /// reproducible. Randomness here is a property of the output, not of the
    /// tool: an unseeded run that differed every time could not be tested.
    fn default() -> Seed {
        Seed(0x5645_4D50_524F_5443)
    }
}

/// SplitMix64.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub const fn new(state: u64) -> Rng {
        Rng(state)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0)
    }

    /// A fair coin, the `rand() & 1` of the original.
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// A value in `0..bound`, or `None` when `bound` is zero.
    ///
    /// Uses the full 64-bit word through a widening multiply, so the modulo
    /// bias is below 2^-64 for any bound a mutation could ask for.
    pub fn below(&mut self, bound: usize) -> Option<usize> {
        if bound == 0 {
            return None;
        }
        let value = u128::from(self.next_u64()) * bound as u128;
        Some((value >> 64) as usize)
    }
}

const fn mix(value: u64) -> u64 {
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_and_function_give_the_same_stream() {
        let seed = Seed::new(12345);
        let first: Vec<u64> = (0..8)
            .map(|_| seed.for_function(0x1000).next_u64())
            .collect();
        let mut stream = seed.for_function(0x1000);
        let second: Vec<u64> = (0..8).map(|_| stream.next_u64()).collect();
        assert_eq!(
            first[0], second[0],
            "a fresh stream must restart identically"
        );
        assert!(
            second.windows(2).any(|pair| pair[0] != pair[1]),
            "the stream must advance"
        );
    }

    #[test]
    fn neighbouring_entry_points_get_uncorrelated_streams() {
        let seed = Seed::default();
        let a = seed.for_function(0x1000).next_u64();
        let b = seed.for_function(0x1001).next_u64();
        let c = seed.for_function(0x1002).next_u64();
        assert_ne!(a, b);
        assert_ne!(b, c);
        // Adjacent RVAs must not merely differ in their low bits
        assert!((a ^ b).count_ones() > 16, "streams look correlated");
    }

    #[test]
    fn below_stays_in_range_and_handles_zero() {
        let mut rng = Seed::default().for_function(0x2000);
        assert_eq!(rng.below(0), None);
        assert_eq!(rng.below(1), Some(0));
        for _ in 0..1000 {
            let value = rng.below(7).expect("non-zero bound yields a value");
            assert!(value < 7, "{value} is out of range");
        }
    }

    #[test]
    fn the_coin_is_not_stuck() {
        let mut rng = Seed::default().for_function(0x3000);
        let heads = (0..1000).filter(|_| rng.coin()).count();
        assert!((400..600).contains(&heads), "{heads} heads out of 1000");
    }
}
