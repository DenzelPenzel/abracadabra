use std::path::PathBuf;

use vmp_compiler::{protect_mutation, Error, MutationRequest, Seed, SymbolSelection};
use vmp_pe::PeFile;
use vmp_types::Rva;

fn fixture() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vmp-pe/test-corpus/win64-app-msvc-amd64");
    std::fs::read(path).expect("the required PE fixture is readable")
}

fn symbol_fixture() -> (Vec<u8>, Vec<u8>) {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus");
    (
        std::fs::read(corpus.join("foo.exe")).expect("the symbol PE fixture is readable"),
        std::fs::read(corpus.join("foo.pdb")).expect("the PDB fixture is readable"),
    )
}

fn apple_map(image: &[u8], symbols: &[(&str, Rva)]) -> String {
    let pe = PeFile::parse(image).expect("the MAP target image parses");
    let mut map = String::from("# Address Size File Name\n");
    for (name, rva) in symbols {
        let va = pe.optional.image_base.get() + u64::from(rva.get());
        map.push_str(&format!("0x{va:016x} 0x10 [  1] {name}\n"));
    }
    map
}

fn protectable_entries(image: &[u8]) -> Vec<Rva> {
    protect_mutation(MutationRequest {
        image: image.to_vec(),
        rvas: Vec::new(),
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(19),
    })
    .expect("the symbol fixture exception sweep succeeds")
    .outcome
    .protected
    .into_iter()
    .map(|protected| protected.original)
    .collect()
}

#[test]
fn an_explicit_rva_request_returns_the_rewritten_image_and_outcome() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus");
    let input = std::fs::read(corpus.join("foo.exe")).expect("the symbol PE fixture is readable");

    let product = protect_mutation(MutationRequest {
        image: input.clone(),
        rvas: vec![vmp_types::Rva(0x6560)],
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(7),
    })
    .expect("the compiler protects at least one fixture function");

    assert_ne!(product.image, input);
    assert!(!product.outcome.protected.is_empty());
    assert_eq!(product.seed, Seed::new(7));
    PeFile::parse(&product.image).expect("the compiler output reparses");
}

#[test]
fn an_image_without_sdk_markers_defaults_to_exception_entries() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus");
    let input = std::fs::read(corpus.join("foo.exe")).expect("the symbol PE fixture is readable");

    let product = protect_mutation(MutationRequest {
        image: input,
        rvas: Vec::new(),
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(9),
    })
    .expect("the compiler sweeps exception entries when SDK markers are absent");

    assert!(!product.outcome.protected.is_empty());
}

#[test]
fn an_empty_selector_automatically_protects_sdk_markers() {
    let mut input = fixture();
    let pe = PeFile::parse(&input).expect("the required PE fixture parses");
    let unwind_rva = pe
        .exception_table
        .as_ref()
        .expect("the required PE fixture has exception data")
        .functions()
        .find(|function| function.begin.get() == 0x1000)
        .expect("the SDK marker function has a runtime entry")
        .unwind_info;
    let unwind_offset = pe
        .rva_to_offset(unwind_rva)
        .expect("the SDK unwind info is file-backed")
        .get() as usize;
    let begin_offset = pe
        .rva_to_offset(vmp_types::Rva(0x1027))
        .expect("the SDK Begin site is file-backed")
        .get() as usize;
    let end_offset = pe
        .rva_to_offset(vmp_types::Rva(0x103f))
        .expect("the SDK End site is file-backed")
        .get() as usize;
    input[unwind_offset] &= 0x07;
    input[begin_offset..begin_offset + 18].copy_from_slice(b"\xeb\x10VMProtect begin\x02");
    input[end_offset..end_offset + 16].copy_from_slice(b"\xeb\x0eVMProtect end\0");

    let product = protect_mutation(MutationRequest {
        image: input.clone(),
        rvas: Vec::new(),
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(11),
    })
    .expect("the compiler automatically selects the fixture SDK markers");

    assert_ne!(product.image, input);
    assert!(!product.outcome.protected.is_empty());
    assert!(product.outcome.skipped.is_empty());
    PeFile::parse(&product.image).expect("the compiler SDK output reparses");
}

#[test]
fn a_symbol_request_is_resolved_and_protected_inside_the_compiler() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus");
    let input = std::fs::read(corpus.join("foo.exe")).expect("the symbol PE fixture is readable");
    let pdb = std::fs::read(corpus.join("foo.pdb")).expect("the PDB fixture is readable");

    let product = protect_mutation(MutationRequest {
        image: input,
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "main".to_owned(),
            occurrence: None,
        }),
        map: None,
        pdb: Some(pdb),
        seed: Seed::new(13),
    })
    .expect("the compiler resolves and protects main");

    assert_eq!(product.outcome.protected.len(), 1);
    assert_eq!(product.outcome.protected[0].original.get(), 0x6560);
    assert!(product.outcome.skipped.is_empty());
}

#[test]
fn compiler_symbol_errors_are_frontend_neutral() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-symbols/test-corpus");
    let input = std::fs::read(corpus.join("foo.exe")).expect("the symbol PE fixture is readable");
    let pdb = std::fs::read(corpus.join("foo.pdb")).expect("the PDB fixture is readable");

    let error = protect_mutation(MutationRequest {
        image: input,
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "__missing_compiler_symbol__".to_owned(),
            occurrence: None,
        }),
        map: None,
        pdb: Some(pdb),
        seed: Seed::new(17),
    })
    .expect_err("the missing symbol must return a typed compiler error");

    assert!(!error.to_string().contains("--symbol"));
    assert!(!error.to_string().contains("--symbol-index"));
}

#[test]
fn an_ambiguous_symbol_requires_an_explicit_occurrence() {
    let (input, _) = symbol_fixture();
    let entries = protectable_entries(&input);
    assert!(
        entries.len() >= 2,
        "the required fixture has two protectable functions"
    );
    let map = apple_map(
        &input,
        &[("Duplicate", entries[0]), ("Duplicate", entries[1])],
    );

    let error = protect_mutation(MutationRequest {
        image: input,
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "Duplicate".to_owned(),
            occurrence: None,
        }),
        map: Some(map),
        pdb: None,
        seed: Seed::new(23),
    })
    .expect_err("an ambiguous symbol must not select every occurrence implicitly");

    assert!(matches!(
        &error,
        Error::AmbiguousSymbol {
            matches: 2,
            last: 1,
            ..
        }
    ));
    assert!(!error.to_string().contains("--symbol"));
}

#[test]
fn symbol_occurrence_is_zero_based_and_range_checked() {
    let (input, _) = symbol_fixture();
    let entries = protectable_entries(&input);
    assert!(
        entries.len() >= 2,
        "the required fixture has two protectable functions"
    );
    let map = apple_map(
        &input,
        &[("Duplicate", entries[0]), ("Duplicate", entries[1])],
    );
    let request = |occurrence| MutationRequest {
        image: input.clone(),
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "Duplicate".to_owned(),
            occurrence: Some(occurrence),
        }),
        map: Some(map.clone()),
        pdb: None,
        seed: Seed::new(29),
    };

    let second = protect_mutation(request(1)).expect("occurrence one selects the second symbol");
    assert_eq!(second.outcome.protected.len(), 1);
    assert_eq!(second.outcome.protected[0].original, entries[1]);
    assert!(matches!(
        protect_mutation(request(2)),
        Err(Error::Resolve(_))
    ));
}

#[test]
fn map_precedes_pdb_and_cross_selector_duplicates_are_removed() {
    let (input, pdb) = symbol_fixture();
    let entry = protectable_entries(&input)[0];
    let map = apple_map(&input, &[("MapOnlyAlias", entry)]);

    let product = protect_mutation(MutationRequest {
        image: input,
        rvas: vec![entry],
        symbol: Some(SymbolSelection {
            name: "MapOnlyAlias".to_owned(),
            occurrence: None,
        }),
        map: Some(map),
        pdb: Some(pdb),
        seed: Seed::new(31),
    })
    .expect("the MAP alias wins and resolves to the explicit RVA");

    assert_eq!(product.outcome.protected.len(), 1);
    assert_eq!(product.outcome.protected[0].original, entry);
}

#[test]
fn symbol_validation_rejects_non_executable_and_non_entry_addresses() {
    let (input, pdb) = symbol_fixture();
    let pe = PeFile::parse(&input).expect("the symbol PE fixture parses");
    let main = Rva(0x6560);
    let map = apple_map(&input, &[("InsideFunction", Rva(main.get() + 1))]);
    let non_entry = protect_mutation(MutationRequest {
        image: input.clone(),
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "InsideFunction".to_owned(),
            occurrence: None,
        }),
        map: Some(map),
        pdb: None,
        seed: Seed::new(37),
    });
    assert!(matches!(
        non_entry,
        Err(Error::SymbolNotFunctionEntry { .. })
    ));

    let text_index = pe
        .sections
        .iter()
        .position(|section| {
            let size = if section.virtual_size == 0 {
                section.size_of_raw_data
            } else {
                section.virtual_size
            };
            section.virtual_address.get() <= main.get()
                && section
                    .virtual_address
                    .get()
                    .checked_add(size)
                    .is_some_and(|end| main.get() < end)
        })
        .expect("main belongs to a section");
    let section_table = usize::try_from(pe.dos.e_lfanew).expect("e_lfanew fits")
        + 4
        + 20
        + usize::from(pe.coff.size_of_optional_header);
    let characteristics = section_table + text_index * 40 + 36;
    let mut non_executable_image = input;
    let current = u32::from_le_bytes(
        non_executable_image[characteristics..characteristics + 4]
            .try_into()
            .expect("section characteristics are four bytes"),
    );
    non_executable_image[characteristics..characteristics + 4]
        .copy_from_slice(&(current & !0x2000_0000).to_le_bytes());
    let non_executable = protect_mutation(MutationRequest {
        image: non_executable_image,
        rvas: Vec::new(),
        symbol: Some(SymbolSelection {
            name: "main".to_owned(),
            occurrence: None,
        }),
        map: None,
        pdb: Some(pdb),
        seed: Seed::new(41),
    });
    assert!(matches!(non_executable, Err(Error::Resolve(_))));
}

#[test]
fn mixed_explicit_selection_returns_no_partial_product() {
    let (input, _) = symbol_fixture();
    let sweep = protect_mutation(MutationRequest {
        image: input.clone(),
        rvas: Vec::new(),
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(43),
    })
    .expect("the required exception sweep succeeds");
    let protected = sweep.outcome.protected[0].original;
    let skipped = sweep.outcome.skipped[0].rva;

    let result = protect_mutation(MutationRequest {
        image: input,
        rvas: vec![protected, skipped],
        symbol: None,
        map: None,
        pdb: None,
        seed: Seed::new(43),
    });

    assert!(matches!(
        result,
        Err(Error::ExplicitSelectionFailed {
            skipped: 1,
            requested: 2,
            ..
        })
    ));
}
