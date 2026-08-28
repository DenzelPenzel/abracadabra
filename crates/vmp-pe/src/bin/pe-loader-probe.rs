//! Deterministic target program for the Windows loader and execution gate.
//!
//! The gate appends sections to this binary with [`vmp_pe::PeImage`] and then
//! runs the original and the rewritten copy, so the program has to exercise the
//! loader metadata an append-only rewrite must preserve — imports, base
//! relocations, TLS callbacks with a destructor and x64 unwind data — while
//! printing byte-identical output on every run.
//!
//! It is intentionally free of clocks, addresses and environment probes: the
//! gate compares stdout and stderr literally.

use std::cell::RefCell;
use std::panic;
use std::process::ExitCode;

thread_local! {
    /// A thread local holding a value with a destructor makes the linker emit a
    /// TLS directory with callbacks, which the rewrite must keep intact.
    static VISITS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
}

fn visit(values: &[u32]) -> u32 {
    VISITS.with(|visits| {
        let mut visits = visits.borrow_mut();
        visits.extend_from_slice(values);
        visits.iter().sum()
    })
}

fn main() -> ExitCode {
    let exit_code = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u8>().ok())
        .unwrap_or(0);

    let main_total = visit(&[2, 3, 5, 7]);
    // A second thread makes the TLS callbacks run for a thread attach as well
    let worker_total = std::thread::spawn(|| visit(&[11, 13])).join().unwrap_or(0);

    // Unwinding across a catch boundary walks the exception directory on x64
    panic::set_hook(Box::new(|_| eprintln!("loader-probe: unwinding")));
    let unwound = panic::catch_unwind(|| -> u32 { panic!("deliberate") }).is_err();
    let _ = panic::take_hook();

    println!("loader-probe: main={main_total} worker={worker_total} unwound={unwound}");
    eprintln!("loader-probe: done");
    ExitCode::from(exit_code)
}
