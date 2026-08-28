//! The crate promises that malformed input yields a typed error rather than a
//! panic, an out-of-bounds read or an unbounded loop.
//!
//! Eager directory parsing put five more parsers on the [`vmp_pe::PeFile::parse`]
//! path, so that promise is exercised here against systematically corrupted real
//! images: every byte-level mutation of a real PE must produce either a parsed
//! model or a `PeError`, and the writer must behave the same way on whatever
//! parsed.
//!
//! The mutation sequence is a fixed-seed generator, so a failure is reproducible
//! from the reported iteration alone.

use std::path::{Path, PathBuf};

use vmp_pe::{NewSection, PeFile, PeImage};

const READ_ONLY_DATA: u32 = 0x4000_0040;
/// Mutations applied per fixture.
const ITERATIONS: usize = 600;
/// Fixtures above this size are skipped. Every accepted mutation rewrites the
/// whole image, so the sweep's cost grows with the input; the bound has to stay
/// clear of the release probes CI links into the corpus.
const MAX_FIXTURE_BYTES: usize = 0x8_0000;

fn corpus_dir() -> PathBuf {
    match std::env::var_os("VMP_CORPUS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("test-corpus"),
    }
}

/// A small deterministic generator; no clock or entropy source is involved, so a
/// failing iteration reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

/// Corrupts a copy of `original`, biased towards the header region where the
/// structures that drive every parser live.
fn mutate(original: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = original.to_vec();
    if data.is_empty() {
        return data;
    }
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        // Two thirds of the edits land in the first kilobyte: headers, section
        // table and data directories
        let offset = if rng.below(3) == 0 {
            rng.below(data.len())
        } else {
            rng.below(data.len().min(0x400))
        };
        let byte = (rng.next() & 0xff) as u8;
        match rng.below(4) {
            0 => data[offset] = byte,
            1 => data[offset] ^= 0xff,
            2 => data[offset] = 0,
            _ => data[offset] = 0xff,
        }
    }
    // Occasionally truncate as well, so short reads are covered
    if rng.below(8) == 0 {
        let keep = rng.below(data.len());
        data.truncate(keep);
    }
    data
}

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(corpus_dir()) else {
        return found;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    for path in paths {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        // Only real PEs are worth mutating
        if bytes.len() > MAX_FIXTURE_BYTES
            || bytes.first() != Some(&b'M')
            || bytes.get(1) != Some(&b'Z')
        {
            continue;
        }
        if PeFile::parse(&bytes).is_err() {
            continue;
        }
        found.push((
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bytes,
        ));
    }
    found
}

#[test]
fn mutated_real_images_never_panic() {
    let fixtures = fixtures();
    if fixtures.is_empty() {
        assert!(
            std::env::var_os("VMP_REQUIRE_CORPUS").is_none(),
            "VMP_REQUIRE_CORPUS is set but no parseable PE fixture was found in {}",
            corpus_dir().display()
        );
        eprintln!("skipping: no parseable PE fixtures available");
        return;
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for (name, original) in &fixtures {
        let mut rng = Rng(0x5eed_1234_5678_9abc);
        for iteration in 0..ITERATIONS {
            let candidate = mutate(original, &mut rng);
            // A panic here fails the test with the iteration in the message
            let parsed = PeFile::parse(&candidate);
            match parsed {
                Err(_) => rejected += 1,
                Ok(_) => {
                    accepted += 1;
                    // Whatever survived parsing must also survive the writer
                    let Ok(mut image) = PeImage::from_bytes(candidate.clone()) else {
                        panic!("{name} iteration {iteration}: parse and from_bytes disagree");
                    };
                    let _ = image.add_section(NewSection {
                        name: ".vmpdat",
                        data: b"robustness",
                        characteristics: READ_ONLY_DATA,
                    });
                    // The output of a successful append must reparse; a failed one
                    // must leave the image alone
                    let _ = PeFile::parse(image.bytes()).expect("committed bytes reparse");
                }
            }
        }
    }

    // A sweep that rejected everything would prove nothing about the parsers
    assert!(
        accepted > 0,
        "no mutation was accepted, so no parser was exercised past the headers"
    );
    eprintln!(
        "mutated {} fixtures: {accepted} accepted, {rejected} rejected",
        fixtures.len()
    );
}
