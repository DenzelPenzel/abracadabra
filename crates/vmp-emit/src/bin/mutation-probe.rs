//! A small program the mutation gate protects and then runs.
//!
//! `tests/windows_mutation.rs` reads this binary, rewrites its functions, moves
//! the rewritten copies into a new section, and runs the original and the
//! protected build side by side. Their output has to match byte for byte.
//!
//! That comparison only proves something if a mistake would show up in the
//! output, so this program is built to expose both ways a moved function can
//! break:
//!
//! 1. The rewrite changed what the code means. Every function here computes a
//!    number that gets printed, so a bad rewrite prints a different number.
//! 2. The copy's unwind data no longer describes the copy. Running the code
//!    cannot reveal that — only Windows can, and only while it unwinds the
//!    stack. So we panic six frames deep and catch it at the top, which makes
//!    Windows walk those frames and act on the unwind data of each one.
//!
//! Every function is `#[inline(never)]` because the mutator is handed one entry
//! point per `.pdata` entry, and an inlined function has no entry there — it is
//! not a function in the finished binary at all. Without the attribute the
//! optimizer folds `accumulate` and `transform` into `main`, leaving `descend`
//! as the only candidate, and the gate would quietly test one function instead
//! of three.
//!
//! Nothing here may differ between two runs of the same binary — no clocks, no
//! addresses, no environment — because the gate compares the output literally.

use std::hint::black_box;
use std::panic;
use std::process::ExitCode;

/// Adds the values up and folds them into one number.
///
/// Two counters starting at zero plus a loop over them give the compiler plenty
/// of reasons to emit `xor reg, reg`, which is the only instruction the rewrite
/// catalogue changes today. `black_box` is what stops the optimizer from working
/// the answer out at compile time and leaving an empty function behind.
#[inline(never)]
fn accumulate(values: &[u32]) -> u32 {
    let mut total = 0u32;
    let mut parity = 0u32;
    for value in values {
        total = total.wrapping_add(black_box(*value));
        parity ^= value;
    }
    total.wrapping_mul(2).wrapping_add(parity)
}

/// Stirs one number into another, so the printed result depends on the code
/// having survived the move intact.
#[inline(never)]
fn transform(seed: u32) -> u32 {
    let mut value = seed;
    for round in 0..4 {
        value = value.rotate_left(7) ^ black_box(round);
        value = value.wrapping_mul(0x9e37_79b9);
    }
    value
}

/// Calls itself `depth` times and panics at the bottom.
///
/// Every level is one more stack frame Windows has to pop on the way back up,
/// and popping a frame means reading that function's unwind data. `black_box`
/// keeps the recursion from being turned into a loop, which would leave one
/// frame instead of six.
#[inline(never)]
fn descend(depth: u32) -> u32 {
    if depth == 0 {
        panic!("deliberate");
    }
    black_box(descend(depth - 1)).wrapping_add(depth)
}

fn main() -> ExitCode {
    // The gate runs both builds with the same argument and compares the exit
    // code, so echoing the argument back proves it survived the round trip
    let exit_code = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u8>().ok())
        .unwrap_or(0);

    let total = accumulate(&[2, 3, 5, 7, 11, 13]);
    let transformed = transform(black_box(total));

    // A fixed line instead of the standard hook's message, so stderr stays short
    // and says nothing that depends on the toolchain or on a backtrace. It is
    // also a second signal, on the other stream, that the unwind really ran
    panic::set_hook(Box::new(|_| eprintln!("mutation-probe: unwinding")));
    let unwound = panic::catch_unwind(|| descend(black_box(6))).is_err();
    let _ = panic::take_hook();

    // `unwound` is the interesting one: it is false if the panic never happened,
    // and the gate asserts on it so a broken probe cannot pass by testing nothing
    println!("mutation-probe: total={total} transformed={transformed} unwound={unwound}");
    eprintln!("mutation-probe: done");
    ExitCode::from(exit_code)
}
