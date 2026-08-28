//! C++-compatible function-symbol discovery and selection.

use std::collections::{HashMap, HashSet};

use thiserror::Error;
use vmp_pe::{ExportTarget, ImportTarget, PeError, PeFile};
use vmp_types::Rva;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Code,
    Data,
    Export,
    Import,
    EntryPoint,
}

impl SymbolKind {
    fn is_code(self) -> bool {
        matches!(self, Self::Code | Self::Export | Self::EntryPoint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSource {
    Map,
    Pdb,
    Coff,
    Export,
    Import,
    EntryPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub raw_name: Option<String>,
    pub rva: Rva,
    pub kind: SymbolKind,
    pub source: SymbolSource,
}

impl Symbol {
    pub fn new(name: impl Into<String>, rva: Rva, kind: SymbolKind, source: SymbolSource) -> Self {
        Self {
            name: name.into(),
            raw_name: None,
            rva,
            kind,
            source,
        }
    }

    pub fn from_raw(raw: &str, rva: Rva, kind: SymbolKind, source: SymbolSource) -> Self {
        let name = demangle_name(raw).name;
        let raw_name = (name != raw).then(|| raw.to_string());
        Self {
            name,
            raw_name,
            rva,
            kind,
            source,
        }
    }

    fn try_new(
        name: &str,
        rva: Rva,
        kind: SymbolKind,
        source: SymbolSource,
    ) -> Result<Self, std::collections::TryReserveError> {
        let mut retained = String::new();
        retained.try_reserve_exact(name.len())?;
        retained.push_str(name);
        Ok(Self {
            name: retained,
            raw_name: None,
            rva,
            kind,
            source,
        })
    }

    fn try_from_raw(
        raw: &str,
        rva: Rva,
        kind: SymbolKind,
        source: SymbolSource,
    ) -> Result<Self, std::collections::TryReserveError> {
        let name = vmp_demangle::try_demangle_name(raw)?.into_name();
        let raw_name = if name == raw {
            None
        } else {
            let mut retained = String::new();
            retained.try_reserve_exact(raw.len())?;
            retained.push_str(raw);
            Some(retained)
        };
        Ok(Self {
            name,
            raw_name,
            rva,
            kind,
            source,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangledName {
    pub name: String,
}

pub fn demangle_name(raw: &str) -> DemangledName {
    DemangledName {
        name: vmp_demangle::demangle_name(raw).name().to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    All(String),
    Occurrence { name: String, index: usize },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("symbol `{name}` was not found")]
    NotFound { name: String },
    #[error("symbol `{name}` has {matches} match(es), but none is code")]
    NotCode { name: String, matches: usize },
    #[error(
        "symbol `{name}` has {available} code occurrence(s), so index {index} is out of range"
    )]
    OccurrenceOutOfRange {
        name: String,
        index: usize,
        available: usize,
    },
    #[error("allocation failed while resolving symbol")]
    Allocation,
}

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error(transparent)]
    Pe(#[from] PeError),
    #[error("{symbol_source:?} symbol name is not valid UTF-8")]
    InvalidSymbolEncoding { symbol_source: SymbolSource },
    #[error("{symbol_source:?} symbol address overflows the RVA space")]
    AddressOverflow { symbol_source: SymbolSource },
    #[error("malformed MAP at line {line}: {reason}")]
    MapSyntax { line: usize, reason: &'static str },
    #[error("symbol resource limit exceeded: {resource}")]
    ResourceLimit { resource: &'static str },
    #[error("allocation failed while retaining {context}")]
    Allocation { context: &'static str },
    #[error("PDB parsing failed: {0}")]
    Pdb(#[from] vmp_pdb::Error),
    #[error("the PE image has no RSDS CodeView identity")]
    MissingCodeViewIdentity,
    #[error("the PDB GUID does not match the PE RSDS GUID")]
    PdbIdentityMismatch,
}

fn try_resolve_name(name: &str) -> Result<String, ResolveError> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(name.len())
        .map_err(|_| ResolveError::Allocation)?;
    retained.push_str(name);
    Ok(retained)
}

#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    symbols: Vec<Symbol>,
}

impl SymbolIndex {
    pub fn from_symbols(symbols: impl IntoIterator<Item = Symbol>) -> Self {
        Self {
            symbols: symbols.into_iter().collect(),
        }
    }

    fn from_vec(symbols: Vec<Symbol>) -> Self {
        Self { symbols }
    }

    fn apply_native(existing: &mut Symbol, source: SymbolSource) {
        match source {
            SymbolSource::Export if existing.kind == SymbolKind::Code => {
                existing.kind = SymbolKind::Export;
            }
            SymbolSource::Import => existing.kind = SymbolKind::Import,
            SymbolSource::EntryPoint | SymbolSource::Export => {}
            SymbolSource::Map | SymbolSource::Pdb | SymbolSource::Coff => {}
        }
    }

    fn merge_native_batch(&mut self, mut native: Vec<Symbol>) -> Result<(), SymbolError> {
        let batch_bytes = self
            .symbols
            .len()
            .checked_mul(std::mem::size_of::<(u32, usize)>())
            .and_then(|bytes| {
                native
                    .len()
                    .checked_mul(std::mem::size_of::<(u32, usize)>() + std::mem::size_of::<usize>())
                    .and_then(|native_bytes| bytes.checked_add(native_bytes))
            })
            .ok_or(SymbolError::ResourceLimit {
                resource: "native merge working bytes",
            })?;
        let native_name_bytes = native.iter().try_fold(0usize, |used, symbol| {
            symbol
                .name
                .len()
                .checked_add(symbol.raw_name.as_ref().map_or(0, String::len))
                .and_then(|bytes| used.checked_add(bytes))
                .ok_or(SymbolError::ResourceLimit {
                    resource: "PE-native owned bytes",
                })
        })?;
        let peak_bytes = native
            .capacity()
            .checked_mul(std::mem::size_of::<Symbol>())
            .and_then(|bytes| bytes.checked_add(native_name_bytes))
            .and_then(|bytes| bytes.checked_add(batch_bytes))
            .ok_or(SymbolError::ResourceLimit {
                resource: "PE-native owned bytes",
            })?;
        if peak_bytes > NATIVE_OWNED_BYTES {
            return Err(SymbolError::ResourceLimit {
                resource: "PE-native owned bytes",
            });
        }
        let mut external_order = Vec::new();
        external_order
            .try_reserve_exact(self.symbols.len())
            .map_err(|_| SymbolError::Allocation {
                context: "native RVA index",
            })?;
        external_order.extend(
            self.symbols
                .iter()
                .enumerate()
                .map(|(position, symbol)| (symbol.rva.get(), position)),
        );
        external_order.sort_unstable();

        let mut native_order = Vec::new();
        native_order
            .try_reserve_exact(native.len())
            .map_err(|_| SymbolError::Allocation {
                context: "native RVA index",
            })?;
        native_order.extend(
            native
                .iter()
                .enumerate()
                .map(|(position, symbol)| (symbol.rva.get(), position)),
        );
        native_order.sort_unstable();

        let mut retained_positions = Vec::new();
        retained_positions
            .try_reserve_exact(native.len())
            .map_err(|_| SymbolError::Allocation {
                context: "native merge positions",
            })?;
        let mut cursor = 0usize;
        while cursor < native_order.len() {
            let first_entry =
                native_order
                    .get(cursor)
                    .copied()
                    .ok_or(SymbolError::ResourceLimit {
                        resource: "native symbol positions",
                    })?;
            let rva = first_entry.0;
            let remaining = native_order
                .get(cursor..)
                .ok_or(SymbolError::ResourceLimit {
                    resource: "native symbol positions",
                })?;
            let group_end = remaining
                .partition_point(|entry| entry.0 == rva)
                .checked_add(cursor)
                .ok_or(SymbolError::ResourceLimit {
                    resource: "native symbol positions",
                })?;
            let group = native_order
                .get(cursor..group_end)
                .ok_or(SymbolError::ResourceLimit {
                    resource: "native symbol positions",
                })?;
            let external_start = external_order.partition_point(|entry| entry.0 < rva);
            if let Some(&(_, external_position)) = external_order
                .get(external_start)
                .filter(|entry| entry.0 == rva)
            {
                let existing =
                    self.symbols
                        .get_mut(external_position)
                        .ok_or(SymbolError::ResourceLimit {
                            resource: "native external positions",
                        })?;
                for &(_, native_position) in group {
                    let source = native
                        .get(native_position)
                        .map(|symbol| symbol.source)
                        .ok_or(SymbolError::ResourceLimit {
                            resource: "native symbol positions",
                        })?;
                    Self::apply_native(existing, source);
                }
            } else {
                let first_position = first_entry.1;
                let rest = group.get(1..).ok_or(SymbolError::ResourceLimit {
                    resource: "native symbol positions",
                })?;
                for &(_, native_position) in rest {
                    let incoming_source = native
                        .get(native_position)
                        .map(|symbol| symbol.source)
                        .ok_or(SymbolError::ResourceLimit {
                        resource: "native symbol positions",
                    })?;
                    let first =
                        native
                            .get_mut(first_position)
                            .ok_or(SymbolError::ResourceLimit {
                                resource: "native symbol positions",
                            })?;
                    Self::apply_native(first, incoming_source);
                }
                retained_positions.push(first_position);
            }
            cursor = group_end;
        }
        retained_positions.sort_unstable();
        let output_count = self
            .symbols
            .len()
            .checked_add(retained_positions.len())
            .ok_or(SymbolError::ResourceLimit {
                resource: "native merged symbols",
            })?;
        let output_allocation = output_count
            .checked_mul(std::mem::size_of::<Symbol>())
            .ok_or(SymbolError::ResourceLimit {
                resource: "native merged symbols",
            })?;
        let merge_peak =
            peak_bytes
                .checked_add(output_allocation)
                .ok_or(SymbolError::ResourceLimit {
                    resource: "PE-native owned bytes",
                })?;
        if merge_peak > NATIVE_OWNED_BYTES {
            return Err(SymbolError::ResourceLimit {
                resource: "PE-native owned bytes",
            });
        }
        self.symbols
            .try_reserve_exact(retained_positions.len())
            .map_err(|_| SymbolError::Allocation {
                context: "native symbol index",
            })?;
        let mut retained = retained_positions.into_iter().peekable();
        for (position, symbol) in native.into_iter().enumerate() {
            if retained.peek().copied() == Some(position) {
                retained.next();
                self.symbols.push(symbol);
            }
        }
        Ok(())
    }

    pub fn resolve_code(&self, selector: &Selector) -> Result<Vec<Rva>, ResolveError> {
        let (name, occurrence) = match selector {
            Selector::All(name) => (name, None),
            Selector::Occurrence { name, index } => (name, Some(*index)),
        };
        let matching_count = self
            .symbols
            .iter()
            .filter(|symbol| symbol.name == *name)
            .count();
        if matching_count == 0 {
            return Err(ResolveError::NotFound {
                name: try_resolve_name(name)?,
            });
        }
        let code_count = self
            .symbols
            .iter()
            .filter(|symbol| symbol.name == *name && symbol.kind.is_code())
            .count();
        if code_count == 0 {
            return Err(ResolveError::NotCode {
                name: try_resolve_name(name)?,
                matches: matching_count,
            });
        }
        match occurrence {
            Some(index) => {
                let Some(rva) = self
                    .symbols
                    .iter()
                    .filter(|symbol| symbol.name == *name && symbol.kind.is_code())
                    .nth(index)
                    .map(|symbol| symbol.rva)
                else {
                    return Err(ResolveError::OccurrenceOutOfRange {
                        name: try_resolve_name(name)?,
                        index,
                        available: code_count,
                    });
                };
                let mut result = Vec::new();
                result
                    .try_reserve_exact(1)
                    .map_err(|_| ResolveError::Allocation)?;
                result.push(rva);
                Ok(result)
            }
            None => {
                let mut result = Vec::new();
                result
                    .try_reserve_exact(code_count)
                    .map_err(|_| ResolveError::Allocation)?;
                result.extend(
                    self.symbols
                        .iter()
                        .filter(|symbol| symbol.name == *name && symbol.kind.is_code())
                        .map(|symbol| symbol.rva),
                );
                Ok(result)
            }
        }
    }
}

fn load_primary_coff(pe: &PeFile, image: &[u8]) -> Result<SymbolIndex, SymbolError> {
    let mut index = SymbolIndex::default();
    let mut retained_names = 0usize;
    for symbol in pe.coff_symbols(image)? {
        let section_index = usize::from(symbol.section)
            .checked_sub(1)
            .ok_or(SymbolError::Pe(PeError::MalformedCoffSymbolTable {
                reason: "symbol section index is out of range",
            }))?;
        let section = pe.sections.get(section_index).ok_or(SymbolError::Pe(
            PeError::MalformedCoffSymbolTable {
                reason: "symbol section index is out of range",
            },
        ))?;
        let rva = section.virtual_address.checked_add(symbol.value).ok_or(
            SymbolError::AddressOverflow {
                symbol_source: SymbolSource::Coff,
            },
        )?;
        if pe.section_at(rva).is_none() {
            continue;
        }
        let name =
            String::from_utf8(symbol.raw_name).map_err(|_| SymbolError::InvalidSymbolEncoding {
                symbol_source: SymbolSource::Coff,
            })?;
        let headroom = name
            .len()
            .checked_add(vmp_demangle::MAX_DEMANGLED_NAME_BYTES)
            .ok_or(SymbolError::ResourceLimit {
                resource: "COFF name bytes",
            })?;
        prepare_native_slot(&mut index.symbols, retained_names, headroom)?;
        let retained = Symbol::try_from_raw(
            &name,
            rva,
            if section.permissions.execute {
                SymbolKind::Code
            } else {
                SymbolKind::Data
            },
            SymbolSource::Coff,
        )
        .map_err(|_| SymbolError::Allocation {
            context: "COFF symbol",
        })?;
        commit_native(&mut index.symbols, &mut retained_names, retained)?;
    }
    Ok(index)
}

const NATIVE_SYMBOL_LIMIT: usize = 262_144;
const NATIVE_NAME_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_OWNED_BYTES: usize = 48 * 1024 * 1024;

fn prepare_native_slot(
    native: &mut Vec<Symbol>,
    retained_names: usize,
    allocation_headroom: usize,
) -> Result<(), SymbolError> {
    if native.len() >= NATIVE_SYMBOL_LIMIT {
        return Err(SymbolError::ResourceLimit {
            resource: "PE-native symbols",
        });
    }
    let attempted =
        retained_names
            .checked_add(allocation_headroom)
            .ok_or(SymbolError::ResourceLimit {
                resource: "PE-native name bytes",
            })?;
    if attempted > NATIVE_NAME_BYTES {
        return Err(SymbolError::ResourceLimit {
            resource: "PE-native name bytes",
        });
    }
    let owned_headroom = native
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(std::mem::size_of::<Symbol>()))
        .and_then(|metadata| metadata.checked_add(attempted))
        .ok_or(SymbolError::ResourceLimit {
            resource: "PE-native owned bytes",
        })?;
    if owned_headroom > NATIVE_OWNED_BYTES {
        return Err(SymbolError::ResourceLimit {
            resource: "PE-native owned bytes",
        });
    }
    native.try_reserve(1).map_err(|_| SymbolError::Allocation {
        context: "PE-native symbols",
    })
}

fn commit_native(
    native: &mut Vec<Symbol>,
    retained_names: &mut usize,
    symbol: Symbol,
) -> Result<(), SymbolError> {
    let bytes = symbol
        .name
        .len()
        .checked_add(symbol.raw_name.as_ref().map_or(0, String::len))
        .and_then(|bytes| retained_names.checked_add(bytes))
        .ok_or(SymbolError::ResourceLimit {
            resource: "PE-native name bytes",
        })?;
    if bytes > NATIVE_NAME_BYTES {
        return Err(SymbolError::ResourceLimit {
            resource: "PE-native name bytes",
        });
    }
    *retained_names = bytes;
    native.push(symbol);
    Ok(())
}

fn try_import_symbol_name(library: &str, target: &ImportTarget) -> Result<String, SymbolError> {
    let target_bytes = match target {
        ImportTarget::Name { name, .. } => name.len(),
        ImportTarget::Ordinal(_) => 13,
    };
    let total = library
        .len()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(target_bytes))
        .ok_or(SymbolError::ResourceLimit {
            resource: "PE-native name bytes",
        })?;
    let mut result = String::new();
    result
        .try_reserve_exact(total)
        .map_err(|_| SymbolError::Allocation {
            context: "import symbol name",
        })?;
    result.push_str(library);
    result.push('!');
    match target {
        ImportTarget::Name { name, .. } => result.push_str(name),
        ImportTarget::Ordinal(ordinal) => {
            result.push_str("Ordinal: ");
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            for shift in [12, 8, 4, 0] {
                let digit = HEX
                    .get(usize::from((ordinal >> shift) & 0xf))
                    .copied()
                    .ok_or(SymbolError::ResourceLimit {
                        resource: "ordinal formatting",
                    })?;
                result.push(char::from(digit));
            }
        }
    }
    Ok(result)
}

fn merge_pe_native(pe: &PeFile, index: &mut SymbolIndex) -> Result<(), SymbolError> {
    let mut native = Vec::new();
    let mut retained_names = 0usize;
    if let Some(exports) = &pe.exports {
        for export in &exports.entries {
            let (Some(name), ExportTarget::Code(rva)) = (&export.name, &export.target) else {
                continue;
            };
            let Some(section) = pe.section_at(*rva) else {
                continue;
            };
            let headroom = name
                .len()
                .checked_add(vmp_demangle::MAX_DEMANGLED_NAME_BYTES)
                .ok_or(SymbolError::ResourceLimit {
                    resource: "PE-native name bytes",
                })?;
            prepare_native_slot(&mut native, retained_names, headroom)?;
            let symbol = Symbol::try_from_raw(
                name,
                *rva,
                if section.permissions.execute {
                    SymbolKind::Export
                } else {
                    SymbolKind::Data
                },
                SymbolSource::Export,
            )
            .map_err(|_| SymbolError::Allocation {
                context: "export symbol",
            })?;
            commit_native(&mut native, &mut retained_names, symbol)?;
        }
    }

    if let Some(imports) = &pe.imports {
        for library in &imports.descriptors {
            for function in &library.functions {
                let target_bytes = match &function.target {
                    ImportTarget::Name { name, .. } => name.len(),
                    ImportTarget::Ordinal(_) => 13,
                };
                let name_bytes = library
                    .name
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(target_bytes))
                    .ok_or(SymbolError::ResourceLimit {
                        resource: "PE-native name bytes",
                    })?;
                prepare_native_slot(&mut native, retained_names, name_bytes)?;
                let name = try_import_symbol_name(&library.name, &function.target)?;
                commit_native(
                    &mut native,
                    &mut retained_names,
                    Symbol {
                        name,
                        raw_name: None,
                        rva: function.thunk_rva,
                        kind: SymbolKind::Import,
                        source: SymbolSource::Import,
                    },
                )?;
            }
        }
    }

    let entry = pe.optional.entry_point;
    if entry.get() != 0 {
        if let Some(section) = pe.section_at(entry) {
            prepare_native_slot(&mut native, retained_names, "EntryPoint".len())?;
            let symbol = Symbol::try_new(
                "EntryPoint",
                entry,
                if section.permissions.execute {
                    SymbolKind::EntryPoint
                } else {
                    SymbolKind::Data
                },
                SymbolSource::EntryPoint,
            )
            .map_err(|_| SymbolError::Allocation {
                context: "entry-point symbol",
            })?;
            commit_native(&mut native, &mut retained_names, symbol)?;
        }
    }
    index.merge_native_batch(native)
}

/// Loads the first selected external source, then merges PE-native names.
pub fn load_symbols(
    pe: &PeFile,
    image: &[u8],
    map: Option<&str>,
    pdb: Option<&[u8]>,
) -> Result<SymbolIndex, SymbolError> {
    let mut index = if let Some(map) = map {
        SymbolIndex::from_vec(parse_map(pe, map)?)
    } else if let Some(pdb) = pdb {
        match parse_pdb(pe, image, pdb) {
            Ok(symbols) => SymbolIndex::from_vec(symbols),
            Err(SymbolError::Pdb(_)) => load_primary_coff(pe, image)?,
            Err(error) => return Err(error),
        }
    } else {
        load_primary_coff(pe, image)?
    };
    merge_pe_native(pe, &mut index)?;
    Ok(index)
}

/// Loads the embedded COFF table followed by PE-native names.
pub fn load_without_sidecars(pe: &PeFile, image: &[u8]) -> Result<SymbolIndex, SymbolError> {
    load_symbols(pe, image, None, None)
}

/// Maximum bytes read from an automatic MAP or PDB sidecar.
pub const MAX_SIDECAR_INPUT_BYTES: usize = 64 * 1024 * 1024;

const PDB_PARSER_OWNED_BYTES: usize = 32 * 1024 * 1024;
const PDB_SELECTOR_OWNED_BYTES: usize = 64 * 1024 * 1024;
const PDB_DEDUP_ENTRY_BYTES: usize = 128;

const PDB_LIMITS: PdbLimits = PdbLimits {
    input_bytes: MAX_SIDECAR_INPUT_BYTES,
    symbols: 262_144,
    retained_name_bytes: 64 * 1024 * 1024,
};

#[derive(Clone, Copy)]
struct PdbLimits {
    input_bytes: usize,
    symbols: usize,
    retained_name_bytes: usize,
}

#[derive(Default)]
struct PdbBudget {
    retained_name_bytes: usize,
    total_owned_bytes: usize,
}

fn parser_limits(limits: PdbLimits) -> vmp_pdb::Limits {
    let mut parser = vmp_pdb::Limits::production();
    parser.input_bytes = limits.input_bytes;
    parser.symbols = limits.symbols;
    parser.retained_name_bytes = limits.retained_name_bytes;
    parser.total_owned_bytes = PDB_PARSER_OWNED_BYTES;
    parser
}

fn map_pdb_error(error: vmp_pdb::Error) -> SymbolError {
    match error {
        vmp_pdb::Error::ResourceLimit { resource } => SymbolError::ResourceLimit { resource },
        vmp_pdb::Error::Allocation => SymbolError::Allocation {
            context: "PDB parser",
        },
        error => SymbolError::Pdb(error),
    }
}

fn append_pdb_symbols(
    pe: &PeFile,
    input: impl IntoIterator<Item = vmp_pdb::Symbol>,
    seen: &mut HashSet<(String, u32)>,
    symbols: &mut Vec<Symbol>,
    budget: &mut PdbBudget,
    limits: PdbLimits,
) -> Result<(), SymbolError> {
    for raw_symbol in input {
        let rva = Rva(raw_symbol.rva);
        let Some(section) = pe.section_at(rva) else {
            continue;
        };
        let key = (raw_symbol.name, rva.get());
        if seen.contains(&key) {
            continue;
        }
        if symbols.len() >= limits.symbols {
            return Err(SymbolError::ResourceLimit {
                resource: "PDB symbols",
            });
        }
        let metadata_bytes = std::mem::size_of::<Symbol>()
            .checked_add(PDB_DEDUP_ENTRY_BYTES)
            .ok_or(SymbolError::ResourceLimit {
                resource: "PDB selector owned bytes",
            })?;
        let allocation_headroom = metadata_bytes
            .checked_add(vmp_demangle::MAX_DEMANGLED_NAME_BYTES)
            .and_then(|bytes| bytes.checked_add(key.0.len()))
            .and_then(|bytes| budget.total_owned_bytes.checked_add(bytes))
            .ok_or(SymbolError::ResourceLimit {
                resource: "PDB selector owned bytes",
            })?;
        if allocation_headroom > PDB_SELECTOR_OWNED_BYTES {
            return Err(SymbolError::ResourceLimit {
                resource: "PDB selector owned bytes",
            });
        }
        let retained_headroom = budget
            .retained_name_bytes
            .checked_add(vmp_demangle::MAX_DEMANGLED_NAME_BYTES)
            .and_then(|bytes| bytes.checked_add(key.0.len()))
            .ok_or(SymbolError::ResourceLimit {
                resource: "PDB retained name bytes",
            })?;
        if retained_headroom > limits.retained_name_bytes {
            return Err(SymbolError::ResourceLimit {
                resource: "PDB retained name bytes",
            });
        }
        seen.try_reserve(1).map_err(|_| SymbolError::Allocation {
            context: "PDB duplicate table",
        })?;
        symbols
            .try_reserve(1)
            .map_err(|_| SymbolError::Allocation {
                context: "PDB symbol table",
            })?;
        let symbol = Symbol::try_from_raw(
            &key.0,
            rva,
            if section.permissions.execute {
                SymbolKind::Code
            } else {
                SymbolKind::Data
            },
            SymbolSource::Pdb,
        )
        .map_err(|_| SymbolError::Allocation {
            context: "PDB symbol name",
        })?;
        let retained = key
            .0
            .len()
            .checked_add(symbol.name.len())
            .and_then(|bytes| bytes.checked_add(symbol.raw_name.as_ref().map_or(0, String::len)))
            .and_then(|bytes| budget.retained_name_bytes.checked_add(bytes))
            .ok_or(SymbolError::ResourceLimit {
                resource: "PDB retained name bytes",
            })?;
        if retained > limits.retained_name_bytes {
            return Err(SymbolError::ResourceLimit {
                resource: "PDB retained name bytes",
            });
        }
        let owned = budget
            .total_owned_bytes
            .checked_add(metadata_bytes)
            .and_then(|bytes| bytes.checked_add(symbol.name.len()))
            .and_then(|bytes| bytes.checked_add(symbol.raw_name.as_ref().map_or(0, String::len)))
            .ok_or(SymbolError::ResourceLimit {
                resource: "PDB selector owned bytes",
            })?;
        if owned > PDB_SELECTOR_OWNED_BYTES {
            return Err(SymbolError::ResourceLimit {
                resource: "PDB selector owned bytes",
            });
        }
        budget.retained_name_bytes = retained;
        budget.total_owned_bytes = owned;
        seen.insert(key);
        symbols.push(symbol);
    }
    Ok(())
}

pub fn parse_pdb(pe: &PeFile, image: &[u8], data: &[u8]) -> Result<Vec<Symbol>, SymbolError> {
    parse_pdb_with_limits(pe, image, data, PDB_LIMITS)
}

fn parse_pdb_with_limits(
    pe: &PeFile,
    image: &[u8],
    data: &[u8],
    limits: PdbLimits,
) -> Result<Vec<Symbol>, SymbolError> {
    let database = vmp_pdb::Database::parse(data, parser_limits(limits)).map_err(map_pdb_error)?;
    let information = database.identity().map_err(map_pdb_error)?;
    let image_identity = pe
        .codeview_pdb_identity(image)?
        .ok_or(SymbolError::MissingCodeViewIdentity)?;
    if information.guid.data1 != image_identity.guid.data1
        || information.guid.data2 != image_identity.guid.data2
        || information.guid.data3 != image_identity.guid.data3
        || information.guid.data4 != image_identity.guid.data4
    {
        return Err(SymbolError::PdbIdentityMismatch);
    }
    // The C++ reference compares the GUID only. In valid linker output the PDB
    // age can be newer than the age recorded in the image.
    let parsed = database
        .symbols(parser_limits(limits))
        .map_err(map_pdb_error)?;
    let mut symbols = Vec::new();
    let mut seen = HashSet::<(String, u32)>::new();
    let mut budget = PdbBudget::default();
    append_pdb_symbols(
        pe,
        parsed.global,
        &mut seen,
        &mut symbols,
        &mut budget,
        limits,
    )?;
    append_pdb_symbols(
        pe,
        parsed.modules,
        &mut seen,
        &mut symbols,
        &mut budget,
        limits,
    )?;
    Ok(symbols)
}

const MAP_LIMITS: MapLimits = MapLimits {
    input_bytes: MAX_SIDECAR_INPUT_BYTES,
    rows: 2_000_000,
    sections: 65_536,
    symbols: 262_144,
    retained_name_bytes: 64 * 1024 * 1024,
};

#[derive(Clone, Copy)]
struct MapLimits {
    input_bytes: usize,
    rows: usize,
    sections: usize,
    symbols: usize,
    retained_name_bytes: usize,
}

#[derive(Default)]
struct MapBudget {
    rows: usize,
    retained_name_bytes: usize,
}

fn map_word(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    let word = input.get(..end)?;
    let rest = input.get(end..)?.trim_start();
    (!word.is_empty()).then_some((word, rest))
}

fn map_segment_offset(input: &str) -> Option<(u32, u64)> {
    let (segment, offset) = input.split_once(':')?;
    Some((
        u32::from_str_radix(segment, 16).ok()?,
        u64::from_str_radix(offset, 16).ok()?,
    ))
}

fn map_symbol_at_va(
    pe: &PeFile,
    symbols: &mut Vec<Symbol>,
    budget: &mut MapBudget,
    limits: MapLimits,
    va: u64,
    name: &str,
) -> Result<(), SymbolError> {
    let Some(raw_rva) = va
        .checked_sub(pe.optional.image_base.get())
        .and_then(|value| u32::try_from(value).ok())
    else {
        return Ok(());
    };
    let rva = Rva(raw_rva);
    let Some(section) = pe.section_at(rva) else {
        return Ok(());
    };
    if symbols.len() >= limits.symbols {
        return Err(SymbolError::ResourceLimit {
            resource: "MAP symbols",
        });
    }
    symbols
        .try_reserve(1)
        .map_err(|_| SymbolError::Allocation {
            context: "MAP symbol table",
        })?;
    let symbol = Symbol::try_from_raw(
        name,
        rva,
        if section.permissions.execute {
            SymbolKind::Code
        } else {
            SymbolKind::Data
        },
        SymbolSource::Map,
    )
    .map_err(|_| SymbolError::Allocation {
        context: "MAP symbol name",
    })?;
    let retained = symbol
        .name
        .len()
        .checked_add(symbol.raw_name.as_ref().map_or(0, String::len))
        .and_then(|bytes| budget.retained_name_bytes.checked_add(bytes))
        .ok_or(SymbolError::ResourceLimit {
            resource: "MAP retained name bytes",
        })?;
    if retained > limits.retained_name_bytes {
        return Err(SymbolError::ResourceLimit {
            resource: "MAP retained name bytes",
        });
    }
    budget.retained_name_bytes = retained;
    symbols.push(symbol);
    Ok(())
}

fn map_absolute_symbol(
    pe: &PeFile,
    symbols: &mut Vec<Symbol>,
    budget: &mut MapBudget,
    limits: MapLimits,
    address: &str,
    name: &str,
) -> Result<(), SymbolError> {
    let Ok(va) = u64::from_str_radix(
        address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
            .unwrap_or(address),
        16,
    ) else {
        return Ok(());
    };
    map_symbol_at_va(pe, symbols, budget, limits, va, name)
}

fn pe_map_segment_base(pe: &PeFile, segment: u32) -> Option<u64> {
    if segment == 0 {
        return Some(0);
    }
    let index = usize::try_from(segment.checked_sub(1)?).ok()?;
    let section = pe.sections.get(index)?;
    pe.optional
        .image_base
        .get()
        .checked_add(u64::from(section.virtual_address.get()))
}

pub fn parse_map(pe: &PeFile, map: &str) -> Result<Vec<Symbol>, SymbolError> {
    parse_map_with_limits(pe, map, MAP_LIMITS)
}

fn parse_map_with_limits(
    pe: &PeFile,
    map: &str,
    limits: MapLimits,
) -> Result<Vec<Symbol>, SymbolError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Begin,
        Sections,
        Delphi,
        Vc,
        Apple,
        Gcc,
        Bcb,
        StaticSymbols,
    }

    if map.len() > limits.input_bytes {
        return Err(SymbolError::ResourceLimit {
            resource: "MAP input bytes",
        });
    }

    let mut symbols = Vec::new();
    // Delphi MAP symbol rows contain only `segment:offset`, so retain the
    // preceding section table as `MAP segment number -> section-start VA`.
    // The first valid row for a segment wins, matching the legacy parser.
    // Section-table offsets are normalized below because some producers emit
    // a segment-relative offset while others already emit an absolute VA;
    // Delphi symbol VAs are then computed as `sections[segment] + offset`.
    let mut sections = HashMap::<u32, u64>::new();
    let mut budget = MapBudget::default();
    let mut state = State::Begin;
    for line in map.lines() {
        if budget.rows >= limits.rows {
            return Err(SymbolError::ResourceLimit {
                resource: "MAP rows",
            });
        }
        budget.rows += 1;

        let trimmed = line.trim();
        let is_delphi_header = trimmed
            .split_whitespace()
            .eq(["Address", "Publics", "by", "Value"]);

        if state == State::Begin && trimmed.starts_with("Start") {
            state = State::Sections;
            continue;
        }
        if state == State::Sections
            && trimmed.split_whitespace().eq([
                "Address",
                "Publics",
                "by",
                "Value",
                "Rva+Base",
                "Lib:Object",
            ])
        {
            state = State::Vc;
            continue;
        }
        if state == State::Sections && is_delphi_header {
            state = State::Delphi;
            continue;
        }
        if state == State::Sections
            && trimmed
                .split_whitespace()
                .eq(["Address", "Publics", "by", "Name"])
        {
            state = State::Bcb;
            continue;
        }
        if state == State::Bcb {
            if is_delphi_header {
                state = State::Delphi;
            }
            continue;
        }
        if trimmed
            .split_whitespace()
            .eq(["#", "Address", "Size", "File", "Name"])
        {
            state = State::Apple;
            continue;
        }
        if trimmed.starts_with("Linker script and memory map") {
            state = State::Gcc;
            continue;
        }
        if state == State::Vc && trimmed.starts_with("Static symbols") {
            state = State::StaticSymbols;
            continue;
        }

        match state {
            State::Begin | State::Bcb => {}
            State::Sections => {
                let mut columns = trimmed.split_whitespace();
                let (Some(location), Some(_size), Some(_name), Some(_class)) = (
                    columns.next(),
                    columns.next(),
                    columns.next(),
                    columns.next(),
                ) else {
                    continue;
                };
                if columns.next().is_some() {
                    continue;
                }
                let Some((segment, offset)) = map_segment_offset(location) else {
                    continue;
                };
                let Some(segment_base) = pe_map_segment_base(pe, segment) else {
                    continue;
                };
                let address = if offset < segment_base {
                    let Some(address) = offset.checked_add(segment_base) else {
                        continue;
                    };
                    address
                } else {
                    offset
                };
                if !sections.contains_key(&segment) {
                    if sections.len() >= limits.sections {
                        return Err(SymbolError::ResourceLimit {
                            resource: "MAP sections",
                        });
                    }
                    sections
                        .try_reserve(1)
                        .map_err(|_| SymbolError::Allocation {
                            context: "MAP section table",
                        })?;
                    sections.insert(segment, address);
                }
            }
            State::Delphi => {
                let Some((location, name)) = map_word(trimmed) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let Some((segment, offset)) = map_segment_offset(location) else {
                    continue;
                };
                let Some(va) = sections
                    .get(&segment)
                    .and_then(|base| base.checked_add(offset))
                else {
                    continue;
                };
                map_symbol_at_va(pe, &mut symbols, &mut budget, limits, va, name)?;
            }
            State::Vc | State::StaticSymbols => {
                let mut columns = trimmed.split_whitespace();
                let (Some(location), Some(name), Some(address)) =
                    (columns.next(), columns.next(), columns.next())
                else {
                    continue;
                };
                if !location.contains(':') {
                    continue;
                }
                map_absolute_symbol(pe, &mut symbols, &mut budget, limits, address, name)?;
            }
            State::Apple => {
                let Some((address, rest)) = map_word(trimmed) else {
                    continue;
                };
                let Some((_size, rest)) = map_word(rest) else {
                    continue;
                };
                if !rest.starts_with('[') {
                    continue;
                }
                let Some(close) = rest.find(']') else {
                    continue;
                };
                let Some(name) = rest.get(close + 1..).map(str::trim_start) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                map_absolute_symbol(pe, &mut symbols, &mut budget, limits, address, name)?;
            }
            State::Gcc => {
                let Some((address, name)) = map_word(trimmed) else {
                    continue;
                };
                if name.is_empty()
                    || name.starts_with("0x")
                    || name.contains(" = ")
                    || name.starts_with("PROVIDE (")
                {
                    continue;
                }
                map_absolute_symbol(pe, &mut symbols, &mut budget, limits, address, name)?;
            }
        }
    }
    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vmp_pe::PeFile;
    use vmp_types::Rva;

    #[test]
    fn batch_native_merge_preserves_first_name_source_order_and_kind_updates() {
        let mut symbols = SymbolIndex::from_symbols(vec![Symbol::new(
            "External",
            Rva(0x1000),
            SymbolKind::Code,
            SymbolSource::Pdb,
        )]);
        symbols
            .merge_native_batch(vec![
                Symbol::new(
                    "FirstNative",
                    Rva(0x3000),
                    SymbolKind::Export,
                    SymbolSource::Export,
                ),
                Symbol::new(
                    "ExternalExport",
                    Rva(0x1000),
                    SymbolKind::Export,
                    SymbolSource::Export,
                ),
                Symbol::new(
                    "SecondNative",
                    Rva(0x2000),
                    SymbolKind::EntryPoint,
                    SymbolSource::EntryPoint,
                ),
                Symbol::new(
                    "FirstNativeImport",
                    Rva(0x3000),
                    SymbolKind::Import,
                    SymbolSource::Import,
                ),
            ])
            .expect("small batch must allocate");
        assert_eq!(
            symbols
                .symbols
                .iter()
                .map(|symbol| (&*symbol.name, symbol.rva, symbol.kind))
                .collect::<Vec<_>>(),
            vec![
                ("External", Rva(0x1000), SymbolKind::Export),
                ("FirstNative", Rva(0x3000), SymbolKind::Import),
                ("SecondNative", Rva(0x2000), SymbolKind::EntryPoint),
            ]
        );
    }

    #[test]
    fn import_symbol_names_are_built_exactly_without_format_allocation() {
        assert_eq!(
            try_import_symbol_name(
                "KERNEL32.dll",
                &ImportTarget::Name {
                    hint: 0,
                    name: "ExitProcess".to_string(),
                },
            )
            .expect("small import name must allocate"),
            "KERNEL32.dll!ExitProcess"
        );
        assert_eq!(
            try_import_symbol_name("x", &ImportTarget::Ordinal(0x1a2b))
                .expect("small ordinal must allocate"),
            "x!Ordinal: 1A2B"
        );
    }

    #[test]
    fn selectors_follow_cpp_code_only_occurrence_order() {
        let symbols = SymbolIndex::from_symbols([
            Symbol::new("Overload", Rva(0x1000), SymbolKind::Code, SymbolSource::Map),
            Symbol::new("Overload", Rva(0x2000), SymbolKind::Data, SymbolSource::Map),
            Symbol::new("Overload", Rva(0x3000), SymbolKind::Code, SymbolSource::Map),
        ]);

        assert_eq!(
            symbols.resolve_code(&Selector::All("Overload".to_string())),
            Ok(vec![Rva(0x1000), Rva(0x3000)])
        );
        assert_eq!(
            symbols.resolve_code(&Selector::Occurrence {
                name: "Overload".to_string(),
                index: 1,
            }),
            Ok(vec![Rva(0x3000)])
        );
    }

    #[test]
    fn external_aliases_survive_but_a_native_alias_at_the_same_address_does_not() {
        let mut symbols = SymbolIndex::from_symbols([
            Symbol::new("First", Rva(0x1000), SymbolKind::Code, SymbolSource::Coff),
            Symbol::new("Alias", Rva(0x1000), SymbolKind::Code, SymbolSource::Coff),
        ]);

        symbols
            .merge_native_batch(vec![Symbol::new(
                "ExportName",
                Rva(0x1000),
                SymbolKind::Export,
                SymbolSource::Export,
            )])
            .expect("small test merge must allocate");

        assert_eq!(
            symbols.resolve_code(&Selector::All("First".to_string())),
            Ok(vec![Rva(0x1000)])
        );
        assert_eq!(
            symbols.resolve_code(&Selector::All("Alias".to_string())),
            Ok(vec![Rva(0x1000)])
        );
        assert_eq!(
            symbols.resolve_code(&Selector::All("ExportName".to_string())),
            Err(ResolveError::NotFound {
                name: "ExportName".to_string(),
            })
        );
    }

    #[test]
    fn native_symbols_match_cpp_export_import_and_entrypoint_rules() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");
        let symbols = load_without_sidecars(&pe, &image).expect("native symbols must load");

        assert_eq!(
            symbols.resolve_code(&Selector::All("EntryPoint".to_string())),
            Ok(vec![Rva(0x1000)])
        );
        assert!(matches!(
            symbols.resolve_code(&Selector::All("kernel32.dll!ExitProcess".to_string())),
            Err(ResolveError::NotCode { matches: 1, .. })
        ));

        let image = std::fs::read(corpus.join("win32-dll-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");
        let symbols = load_without_sidecars(&pe, &image).expect("native symbols must load");
        assert_eq!(
            symbols.resolve_code(&Selector::All("SE_DllLoaded".to_string())),
            Err(ResolveError::NotFound {
                name: "SE_DllLoaded".to_string(),
            })
        );
    }

    #[test]
    fn symbol_names_use_the_complete_reference_dispatcher() {
        for (raw, expected) in [
            ("_Z1fv", "f()"),
            ("@foo$qi", "foo(int)"),
            ("plain::symbol", "plain::symbol"),
        ] {
            assert_eq!(demangle_name(raw).name, expected, "raw={raw}");
        }
    }

    #[test]
    fn msvc_selector_name_matches_the_cpp_golden() {
        assert_eq!(
            demangle_name("?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ").name,
            "CDaoWorkspace::InitWorkspacesCollection(void)"
        );
    }

    #[test]
    fn a_symbol_preserves_its_decorated_spelling() {
        let raw = "?InitWorkspacesCollection@CDaoWorkspace@@IAEXXZ";
        let symbol = Symbol::from_raw(raw, Rva(0x1000), SymbolKind::Code, SymbolSource::Coff);

        assert_eq!(symbol.name, "CDaoWorkspace::InitWorkspacesCollection(void)");
        assert_eq!(symbol.raw_name.as_deref(), Some(raw));
    }

    #[test]
    fn pdb_resource_limits_reject_before_retaining_symbols() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-corpus");
        let image = std::fs::read(corpus.join("foo.exe")).expect("required PE fixture must exist");
        let pdb = std::fs::read(corpus.join("foo.pdb")).expect("required PDB fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture PE must parse");
        let limits = PdbLimits {
            input_bytes: pdb.len() - 1,
            symbols: 1,
            retained_name_bytes: 1,
        };
        assert!(matches!(
            parse_pdb_with_limits(&pe, &image, &pdb, limits),
            Err(SymbolError::ResourceLimit {
                resource: "PDB input bytes"
            })
        ));
        assert!(matches!(
            parse_pdb_with_limits(
                &pe,
                &image,
                &pdb,
                PdbLimits {
                    input_bytes: pdb.len(),
                    symbols: 0,
                    retained_name_bytes: usize::MAX,
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "PDB symbols"
            })
        ));
        assert!(matches!(
            parse_pdb_with_limits(
                &pe,
                &image,
                &pdb,
                PdbLimits {
                    input_bytes: pdb.len(),
                    symbols: usize::MAX,
                    retained_name_bytes: 0,
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "PDB retained name bytes"
            })
        ));
    }

    #[test]
    fn sidecar_loader_preserves_cpp_source_selection_stops() {
        let pe_corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let mut image = std::fs::read(pe_corpus.join("win32-app-test1-i386"))
            .expect("required PE fixture must exist");
        let nt = u32::from_le_bytes(
            image[0x3c..0x40]
                .try_into()
                .expect("fixture DOS header has e_lfanew"),
        ) as usize;
        let coff_header = nt + 4;
        let table_offset = u32::try_from(image.len()).expect("fixture is below 4 GiB");
        image[coff_header + 8..coff_header + 12].copy_from_slice(&table_offset.to_le_bytes());
        image[coff_header + 12..coff_header + 16].copy_from_slice(&1u32.to_le_bytes());
        let mut record = [0u8; 18];
        record[..8].copy_from_slice(b"CoffOnly");
        record[8..12].copy_from_slice(&0x10u32.to_le_bytes());
        record[12..14].copy_from_slice(&1i16.to_le_bytes());
        record[16] = 2; // IMAGE_SYM_CLASS_EXTERNAL
        image.extend_from_slice(&record);
        image.extend_from_slice(&4u32.to_le_bytes());
        let pe = PeFile::parse(&image).expect("fixture with embedded COFF must parse");

        let coff = load_symbols(&pe, &image, None, None).expect("COFF fallback must load");
        assert!(coff
            .symbols
            .iter()
            .any(|symbol| symbol.source == SymbolSource::Coff));

        let map = load_symbols(
            &pe,
            &image,
            Some("readable but unrecognized"),
            Some(b"bad pdb"),
        )
        .expect("a readable MAP selects the MAP source even when empty");
        assert!(!map
            .symbols
            .iter()
            .any(|symbol| matches!(symbol.source, SymbolSource::Pdb | SymbolSource::Coff)));

        let fallback = load_symbols(&pe, &image, None, Some(b"bad pdb"))
            .expect("an unparseable PDB falls through to embedded COFF");
        assert!(fallback
            .symbols
            .iter()
            .any(|symbol| symbol.source == SymbolSource::Coff));
    }

    #[test]
    fn pdb_symbols_require_matching_guid_but_allow_legacy_age_drift() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-corpus");
        let image = std::fs::read(corpus.join("foo.exe")).expect("required PE fixture must exist");
        let pdb = std::fs::read(corpus.join("foo.pdb")).expect("required PDB fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture PE must parse");

        let symbols = SymbolIndex::from_symbols(
            parse_pdb(&pe, &image, &pdb).expect("matching GUID must select the PDB"),
        );
        assert_eq!(
            symbols.resolve_code(&Selector::All("main".to_string())),
            Ok(vec![Rva(0x6560)])
        );

        let mut wrong_image = image.clone();
        let rsds = wrong_image
            .windows(4)
            .position(|window| window == b"RSDS")
            .expect("fixture must contain RSDS");
        wrong_image[rsds + 4] ^= 1;
        let wrong_pe = PeFile::parse(&wrong_image).expect("GUID mutation preserves PE structure");
        assert!(matches!(
            parse_pdb(&wrong_pe, &wrong_image, &pdb),
            Err(SymbolError::PdbIdentityMismatch)
        ));
    }

    #[test]
    fn parses_apple_and_gcc_map_dialects_with_cpp_filters() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");

        let apple = "\
# Address Size File Name
\
0x00401010 0x10 [  1] _Z1fv
";
        let symbols = parse_map(&pe, apple).expect("Apple MAP must parse");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "f()");
        assert_eq!(symbols[0].raw_name.as_deref(), Some("_Z1fv"));
        assert_eq!(symbols[0].rva, Rva(0x1010));

        let gcc = "\
Linker script and memory map
\
0x00401020 _Z3foov
\
0x00401030 0x20
\
0x00401040 ignored = .
\
0x00401050 PROVIDE (ignored = .)
";
        let symbols = parse_map(&pe, gcc).expect("GCC MAP must parse");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "foo()");
        assert_eq!(symbols[0].raw_name.as_deref(), Some("_Z3foov"));
        assert_eq!(symbols[0].rva, Rva(0x1020));
    }

    #[test]
    fn parses_delphi_and_bcb_segment_relative_symbols() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");

        let delphi = "\
Start         Length     Name                   Class
\
0001:00000000 00001000H .text                  CODE
\
Address         Publics by Value
\
0001:00000010 _Z1fv
";
        let symbols = parse_map(&pe, delphi).expect("Delphi MAP must parse");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "f()");
        assert_eq!(symbols[0].rva, Rva(0x1010));

        let bcb = "\
Start         Length     Name                   Class
\
0001:00000000 00001000H .text                  CODE
\
Address         Publics by Name
\
0001:00000010 ignored_name_order_row
\
Address         Publics by Value
\
0001:00000020 @foo$qi
";
        let symbols = parse_map(&pe, bcb).expect("BCB MAP must parse");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "foo(int)");
        assert_eq!(symbols[0].rva, Rva(0x1020));
    }

    #[test]
    fn map_resource_limits_reject_before_retaining_symbols() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");
        let limits = MapLimits {
            input_bytes: 4,
            rows: 8,
            sections: 1,
            symbols: 1,
            retained_name_bytes: 1,
        };
        assert!(matches!(
            parse_map_with_limits(&pe, "12345", limits),
            Err(SymbolError::ResourceLimit {
                resource: "MAP input bytes"
            })
        ));

        let map = "\
Linker script and memory map
\
0x00401020 _Z3foov
";
        assert!(matches!(
            parse_map_with_limits(
                &pe,
                map,
                MapLimits {
                    input_bytes: map.len(),
                    ..limits
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "MAP retained name bytes"
            })
        ));

        assert!(matches!(
            parse_map_with_limits(
                &pe,
                "first\nsecond",
                MapLimits {
                    input_bytes: 12,
                    rows: 1,
                    ..limits
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "MAP rows"
            })
        ));

        let section_map = "Start Length Name Class\n0001:00000000 10H .text CODE";
        assert!(matches!(
            parse_map_with_limits(
                &pe,
                section_map,
                MapLimits {
                    input_bytes: section_map.len(),
                    rows: 2,
                    sections: 0,
                    ..limits
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "MAP sections"
            })
        ));

        assert!(matches!(
            parse_map_with_limits(
                &pe,
                map,
                MapLimits {
                    input_bytes: map.len(),
                    symbols: 0,
                    retained_name_bytes: usize::MAX,
                    ..limits
                }
            ),
            Err(SymbolError::ResourceLimit {
                resource: "MAP symbols"
            })
        ));
    }

    #[test]
    fn malformed_map_rows_are_skipped_without_aborting_later_symbols() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");
        let map = "\
Start Length Name Class
\
0001:00000000 00001000H .text CODE
\
Address Publics by Value Rva+Base Lib:Object
\
0001:00000010 BadAddress not-hex f test.obj
\
0001:00000020 GoodAddress 00401020 f test.obj
";

        let symbols = parse_map(&pe, map).expect("bad MAP rows must be skipped");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "GoodAddress");
        assert_eq!(symbols[0].rva, Rva(0x1020));
    }

    #[test]
    fn parses_msvc_publics_and_static_symbols() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vmp-pe/test-corpus");
        let image = std::fs::read(corpus.join("win32-app-test1-i386"))
            .expect("checked-in PE corpus fixture must exist");
        let pe = PeFile::parse(&image).expect("fixture must parse");
        let map = "\
 Start         Length     Name                   Class\n\
 0001:00000000 00001000H .text                  CODE\n\
 Address         Publics by Value              Rva+Base       Lib:Object\n\
 0001:00000010 MapPublic                       00401010 f test.obj\n\
 Static symbols\n\
 0001:00000020 MapStatic                       00401020 f test.obj\n";

        let symbols = SymbolIndex::from_symbols(parse_map(&pe, map).expect("MAP must parse"));
        assert_eq!(
            symbols.resolve_code(&Selector::All("MapPublic".to_string())),
            Ok(vec![Rva(0x1010)])
        );
        assert_eq!(
            symbols.resolve_code(&Selector::All("MapStatic".to_string())),
            Ok(vec![Rva(0x1020)])
        );
    }
}
