//! SDK API marker discovery in executable instruction streams.

use std::collections::{HashMap, HashSet, VecDeque};

use iced_x86::{
    Code, Encoder, FlowControl, Instruction, InstructionInfoFactory, OpAccess, OpKind, Register,
};
use vmp_ir::{DecodeIssue, EdgeTarget, Function};
use vmp_pe::exports::ExportTarget;
use vmp_pe::markers::{MarkerCompilationType, MAX_SDK_MARKERS};
use vmp_types::{Architecture, Rva};

use crate::decode::{decode_at, import_thunk_target, memory_import_thunk_target, near_branch_rva};
use crate::{decode_function_with_spent, DecodeOptions, Image};

const MAX_DISCOVERY_FUNCTIONS: usize = 4_096;
const MAX_DISCOVERY_INSTRUCTIONS: usize = crate::DEFAULT_BUDGET;

/// SDK begin or end call discovered in native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMarker {
    Begin {
        /// The register load belonging to a `mov [IAT]` + `call reg` marker.
        load_rva: Option<Rva>,
        call_rva: Rva,
        next_rva: Rva,
        /// RVA of the first-argument string recovered from RCX on MS x64.
        name_rva: Option<Rva>,
        /// Instruction whose operand produced `name_rva`.
        name_reference_rva: Option<Rva>,
        compilation_type: MarkerCompilationType,
        lock_to_key: bool,
    },
    End {
        /// The register load belonging to a `mov [IAT]` + `call reg` marker.
        load_rva: Option<Rva>,
        call_rva: Rva,
        next_rva: Rva,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SdkApi {
    IsProtected,
    DecryptStringA,
    DecryptStringW,
    FreeString,
}

/// One decoded call to a runtime-free SDK API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SdkApiCall {
    pub api: SdkApi,
    /// The register load belonging to a `mov [IAT]` + `call reg` form.
    pub load_rva: Option<Rva>,
    pub call_rva: Rva,
    pub next_rva: Rva,
    /// Whether the SDK transfer does not return to `next_rva`.
    pub tail_call: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApiMarkerError {
    #[error("SDK API marker count exceeds the limit of {limit}")]
    TooManyMarkers { limit: usize },
    #[error("SDK marker discovery function count exceeds the limit of {limit}")]
    TooManyFunctions { limit: usize },
    #[error("SDK marker discovery instruction count exceeds the limit of {limit}")]
    TooManyInstructions { limit: usize },
    #[error("contradictory SDK marker observations at call {call_rva}")]
    AmbiguousObservation { call_rva: Rva },
    #[error("memory allocation failed while discovering SDK API markers")]
    AllocationFailed,
    #[error("SDK API marker RVA overflows the image coordinate space")]
    RvaOverflow,
    #[error("register reaching-definition analysis did not converge for function at {entry}")]
    DataflowLimit { entry: Rva },
    #[error("function at {entry} could not be decoded while scanning SDK markers: {reason}")]
    Decode { entry: Rva, reason: String },
}

/// Finds direct, one-thunk, and exact register-loaded SDK calls.
pub fn discover_direct_api_markers(image: Image<'_>) -> Result<Vec<ApiMarker>, ApiMarkerError> {
    discover_direct_api_markers_with_limit(image, MAX_SDK_MARKERS)
}

fn discover_direct_api_markers_with_limit(
    image: Image<'_>,
    marker_limit: usize,
) -> Result<Vec<ApiMarker>, ApiMarkerError> {
    let roots = discovery_roots(&image)?;
    let recursive = image.architecture() == Architecture::X86;
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    for root in roots {
        enqueue_function(&mut queue, &mut queued, root, MAX_DISCOVERY_FUNCTIONS)?;
    }
    let mut markers = HashMap::new();
    let mut decoded_instructions = 0usize;
    let mut function_count = 0usize;

    while let Some(entry) = queue.pop_front() {
        if function_count == MAX_DISCOVERY_FUNCTIONS {
            return Err(ApiMarkerError::TooManyFunctions {
                limit: MAX_DISCOVERY_FUNCTIONS,
            });
        }
        function_count += 1;
        let remaining = MAX_DISCOVERY_INSTRUCTIONS
            .checked_sub(decoded_instructions)
            .ok_or(ApiMarkerError::TooManyInstructions {
                limit: MAX_DISCOVERY_INSTRUCTIONS,
            })?;
        if remaining == 0 {
            return Err(ApiMarkerError::TooManyInstructions {
                limit: MAX_DISCOVERY_INSTRUCTIONS,
            });
        }
        let (function, spent) =
            decode_function_with_spent(image, entry, DecodeOptions { budget: remaining }).map_err(
                |error| ApiMarkerError::Decode {
                    entry,
                    reason: error.to_string(),
                },
            )?;
        charge_decode_work(
            &function,
            spent,
            &mut decoded_instructions,
            MAX_DISCOVERY_INSTRUCTIONS,
        )?;

        if recursive {
            for instruction in function.instructions() {
                let raw = instruction.raw();
                if !is_recursive_pe32_call(raw) {
                    continue;
                }
                let Some(target) = near_branch_rva(raw) else {
                    continue;
                };
                if image.is_executable(target) {
                    enqueue_function(&mut queue, &mut queued, target, MAX_DISCOVERY_FUNCTIONS)?;
                }
            }
        }

        for marker in markers_in_function(&image, &function)? {
            retain_marker_observation(&mut markers, marker, marker_limit)?;
        }
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(markers.len())
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    output.extend(markers.into_values());
    output.sort_unstable_by_key(|marker| marker_call_rva(*marker));
    Ok(output)
}

fn charge_decode_work(
    function: &Function,
    spent: usize,
    total: &mut usize,
    limit: usize,
) -> Result<(), ApiMarkerError> {
    if function
        .issues
        .iter()
        .any(|issue| matches!(issue, DecodeIssue::BudgetExceeded { .. }))
    {
        return Err(ApiMarkerError::TooManyInstructions { limit });
    }
    let next = total
        .checked_add(spent)
        .filter(|next| *next <= limit)
        .ok_or(ApiMarkerError::TooManyInstructions { limit })?;
    *total = next;
    Ok(())
}

fn retain_marker_observation(
    markers: &mut HashMap<Rva, ApiMarker>,
    marker: ApiMarker,
    limit: usize,
) -> Result<bool, ApiMarkerError> {
    let call_rva = marker_call_rva(marker);
    match markers.get(&call_rva) {
        Some(existing) if *existing == marker => return Ok(false),
        Some(_) => return Err(ApiMarkerError::AmbiguousObservation { call_rva }),
        None => {}
    }
    if markers.len() == limit {
        return Err(ApiMarkerError::TooManyMarkers { limit });
    }
    markers
        .try_reserve(1)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    markers.insert(call_rva, marker);
    Ok(true)
}

fn enqueue_function(
    queue: &mut VecDeque<Rva>,
    queued: &mut HashSet<Rva>,
    entry: Rva,
    limit: usize,
) -> Result<bool, ApiMarkerError> {
    if queued.contains(&entry) {
        return Ok(false);
    }
    if queued.len() == limit {
        return Err(ApiMarkerError::TooManyFunctions { limit });
    }
    queue
        .try_reserve(1)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    queued
        .try_reserve(1)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    queued.insert(entry);
    queue.push_back(entry);
    Ok(true)
}

fn discovery_roots(image: &Image<'_>) -> Result<Vec<Rva>, ApiMarkerError> {
    let mut roots = Vec::new();
    if image.architecture() == Architecture::X64 {
        if let Some(runtime_functions) = image.pe().exception_table.as_ref() {
            let count = runtime_functions.functions().count();
            if count > MAX_DISCOVERY_FUNCTIONS {
                return Err(ApiMarkerError::TooManyFunctions {
                    limit: MAX_DISCOVERY_FUNCTIONS,
                });
            }
            roots
                .try_reserve_exact(count)
                .map_err(|_| ApiMarkerError::AllocationFailed)?;
            for runtime in runtime_functions.functions() {
                roots.push(runtime.begin);
            }
            roots.sort_unstable();
            roots.dedup();
            return Ok(roots);
        }
    }

    let mut push_root = |root: Rva| -> Result<(), ApiMarkerError> {
        if roots.len() == MAX_DISCOVERY_FUNCTIONS {
            return Err(ApiMarkerError::TooManyFunctions {
                limit: MAX_DISCOVERY_FUNCTIONS,
            });
        }
        roots
            .try_reserve(1)
            .map_err(|_| ApiMarkerError::AllocationFailed)?;
        roots.push(root);
        Ok(())
    };
    let entry = image.pe().entry_point();
    if image.is_executable(entry) {
        push_root(entry)?;
    }
    if let Some(exports) = image.pe().exports.as_ref() {
        for export in &exports.entries {
            if let ExportTarget::Code(target) = export.target {
                if image.is_executable(target) {
                    push_root(target)?;
                }
            }
        }
    }
    if let Some(tls) = image.pe().tls.as_ref() {
        for &callback in &tls.callbacks {
            if image.is_executable(callback) {
                push_root(callback)?;
            }
        }
    }
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    load_rva: Rva,
    thunk_rva: Rva,
}

type RegisterState = [Option<Known>; 16];

fn markers_in_function(
    image: &Image<'_>,
    function: &Function,
) -> Result<Vec<ApiMarker>, ApiMarkerError> {
    let states = reaching_definitions(image, function)?;
    let mut markers = Vec::new();
    let mut factory = InstructionInfoFactory::new();
    for block in &function.blocks {
        let Some(mut state) = states.get(block.id.index()).copied().flatten() else {
            continue;
        };
        for instruction in &block.instructions {
            let raw = instruction.raw();
            let rva = instruction.rva().ok_or(ApiMarkerError::RvaOverflow)?;
            if let Some(register) =
                exact_register_call(function.architecture, raw, instruction.bytes())
            {
                if let Some(known) = state[family_index(register)] {
                    if let Some(marker) = marker_for_thunk(
                        image,
                        known.thunk_rva,
                        Some(known.load_rva),
                        rva,
                        instruction.next_rva().ok_or(ApiMarkerError::RvaOverflow)?,
                        begin_name_rva(image, function, rva),
                    ) {
                        markers
                            .try_reserve(1)
                            .map_err(|_| ApiMarkerError::AllocationFailed)?;
                        markers.push(marker);
                    }
                }
            } else if let Some(thunk) = called_import_thunk(image, raw, instruction.bytes()) {
                if let Some(marker) = marker_for_thunk(
                    image,
                    thunk,
                    None,
                    rva,
                    instruction.next_rva().ok_or(ApiMarkerError::RvaOverflow)?,
                    begin_name_rva(image, function, rva),
                ) {
                    markers
                        .try_reserve(1)
                        .map_err(|_| ApiMarkerError::AllocationFailed)?;
                    markers.push(marker);
                }
            }
            transfer(
                image,
                function.architecture,
                raw,
                instruction.bytes(),
                rva,
                &mut state,
                &mut factory,
            );
        }
    }
    Ok(markers)
}

/// Finds runtime-free SDK API calls inside one already decoded function.
/// Direct-IAT, import-thunk and register-loaded forms share marker discovery's
/// bounded reaching-definition analysis.
pub fn discover_sdk_api_calls(
    image: Image<'_>,
    function: &Function,
) -> Result<Vec<SdkApiCall>, ApiMarkerError> {
    let states = reaching_definitions(&image, function)?;
    let mut calls = Vec::new();
    let mut factory = InstructionInfoFactory::new();
    for block in &function.blocks {
        let Some(mut state) = states.get(block.id.index()).copied().flatten() else {
            continue;
        };
        for instruction in &block.instructions {
            let raw = instruction.raw();
            let rva = instruction.rva().ok_or(ApiMarkerError::RvaOverflow)?;
            let found = if let Some((register, tail_call)) =
                exact_register_sdk_transfer(function.architecture, raw, instruction.bytes())
            {
                state[family_index(register)].and_then(|known| {
                    sdk_api_for_thunk(&image, known.thunk_rva).and_then(|api| {
                        Some(SdkApiCall {
                            api,
                            load_rva: Some(known.load_rva),
                            call_rva: rva,
                            next_rva: instruction.next_rva()?,
                            tail_call,
                        })
                    })
                })
            } else {
                sdk_import_transfer_thunk(&image, raw, instruction.bytes()).and_then(
                    |(thunk, tail_call)| {
                        sdk_api_for_thunk(&image, thunk).and_then(|api| {
                            Some(SdkApiCall {
                                api,
                                load_rva: None,
                                call_rva: rva,
                                next_rva: instruction.next_rva()?,
                                tail_call,
                            })
                        })
                    },
                )
            };
            if let Some(call) = found {
                calls
                    .try_reserve(1)
                    .map_err(|_| ApiMarkerError::AllocationFailed)?;
                calls.push(call);
            }
            transfer(
                &image,
                function.architecture,
                raw,
                instruction.bytes(),
                rva,
                &mut state,
                &mut factory,
            );
        }
    }
    calls.sort_unstable_by_key(|call| call.call_rva);
    calls.dedup();
    Ok(calls)
}

fn sdk_api_for_thunk(image: &Image<'_>, thunk_rva: Rva) -> Option<SdkApi> {
    let (library, import_name) = image.import_thunk(thunk_rva)?;
    if !is_sdk_library(image.architecture(), library) {
        return None;
    }
    let crate::ImportName::Name(import_name) = import_name else {
        return None;
    };
    match import_name {
        "VMProtectIsProtected" => Some(SdkApi::IsProtected),
        "VMProtectDecryptStringA" => Some(SdkApi::DecryptStringA),
        "VMProtectDecryptStringW" => Some(SdkApi::DecryptStringW),
        "VMProtectFreeString" => Some(SdkApi::FreeString),
        _ => None,
    }
}

fn marker_for_thunk(
    image: &Image<'_>,
    thunk_rva: Rva,
    load_rva: Option<Rva>,
    call_rva: Rva,
    next_rva: Rva,
    name: Option<(Rva, Rva)>,
) -> Option<ApiMarker> {
    let (library, import_name) = image.import_thunk(thunk_rva)?;
    if !is_sdk_library(image.architecture(), library) {
        return None;
    }
    let crate::ImportName::Name(import_name) = import_name else {
        return None;
    };
    match begin_policy(import_name) {
        Some((compilation_type, lock_to_key)) => {
            let (name_reference_rva, name_rva) = name.map_or((None, None), |(reference, name)| {
                (Some(reference), Some(name))
            });
            Some(ApiMarker::Begin {
                load_rva,
                call_rva,
                next_rva,
                name_rva,
                name_reference_rva,
                compilation_type,
                lock_to_key,
            })
        }
        None if import_name == "VMProtectEnd" => Some(ApiMarker::End {
            load_rva,
            call_rva,
            next_rva,
        }),
        None => None,
    }
}

fn begin_name_rva(image: &Image<'_>, function: &Function, call_rva: Rva) -> Option<(Rva, Rva)> {
    if function.architecture != Architecture::X64 {
        return None;
    }
    let block = function.blocks.iter().find(|block| {
        block
            .instructions
            .iter()
            .any(|instruction| instruction.rva() == Some(call_rva))
    })?;
    let call_index = block
        .instructions
        .iter()
        .position(|instruction| instruction.rva() == Some(call_rva))?;
    let mut register = Register::RCX;
    let mut factory = InstructionInfoFactory::new();
    for instruction in block.instructions[..call_index].iter().rev() {
        let raw = instruction.raw();
        if raw.flow_control() != FlowControl::Next {
            return None;
        }
        let writes_register = factory.info(raw).used_registers().iter().any(|used| {
            used.register().full_register() == register.full_register()
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        });
        if !writes_register {
            continue;
        }
        if raw.code() == Code::Lea_r64_m
            && raw.op0_kind() == OpKind::Register
            && raw.op0_register().full_register() == register.full_register()
            && raw.op1_kind() == OpKind::Memory
            && raw.is_ip_rel_memory_operand()
        {
            let rva = Rva(u32::try_from(raw.ip_rel_memory_address()).ok()?);
            return image.is_mapped(rva).then_some((instruction.rva()?, rva));
        }
        if matches!(raw.code(), Code::Mov_r64_rm64 | Code::Mov_r32_rm32)
            && raw.op0_kind() == OpKind::Register
            && raw.op0_register().full_register() == register.full_register()
        {
            if raw.op1_kind() != OpKind::Register {
                return None;
            }
            register = raw.op1_register().full_register();
            continue;
        }
        if matches!(raw.code(), Code::Mov_r64_imm64 | Code::Mov_r32_imm32)
            && raw.op0_kind() == OpKind::Register
            && raw.op0_register().full_register() == register.full_register()
        {
            let value = if raw.code() == Code::Mov_r64_imm64 {
                raw.immediate64()
            } else {
                u64::from(raw.immediate32())
            };
            let relative = value.checked_sub(image.image_base().get()).unwrap_or(value);
            let rva = Rva(u32::try_from(relative).ok()?);
            return image.is_mapped(rva).then_some((instruction.rva()?, rva));
        }
        return None;
    }
    None
}

fn marker_call_rva(marker: ApiMarker) -> Rva {
    match marker {
        ApiMarker::Begin { call_rva, .. } | ApiMarker::End { call_rva, .. } => call_rva,
    }
}

fn is_recursive_pe32_call(instruction: &Instruction) -> bool {
    matches!(instruction.code(), Code::Call_rel16 | Code::Call_rel32_32)
}

fn reaching_definitions(
    image: &Image<'_>,
    function: &Function,
) -> Result<Vec<Option<RegisterState>>, ApiMarkerError> {
    let block_count = function.blocks.len();
    let mut reachable = Vec::new();
    reachable
        .try_reserve_exact(block_count)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    reachable.resize(block_count, false);
    let mut reachability_queue = VecDeque::new();
    reachability_queue
        .try_reserve(block_count)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    reachable[function.entry_block.index()] = true;
    reachability_queue.push_back(function.entry_block);
    while let Some(id) = reachability_queue.pop_front() {
        let Some(block) = function.blocks.get(id.index()) else {
            continue;
        };
        for successor in &block.successors {
            let EdgeTarget::Block(target) = successor.target else {
                continue;
            };
            let Some(is_reachable) = reachable.get_mut(target.index()) else {
                continue;
            };
            if !*is_reachable {
                *is_reachable = true;
                reachability_queue.push_back(target);
            }
        }
    }

    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    incoming
        .try_reserve_exact(function.blocks.len())
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    outgoing
        .try_reserve_exact(function.blocks.len())
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    incoming.resize(block_count, None);
    outgoing.resize(block_count, None);
    let unknown = [None; 16];
    let limit = block_count.saturating_mul(34).max(1);
    let mut factory = InstructionInfoFactory::new();
    let mut worklist = VecDeque::new();
    worklist
        .try_reserve(block_count)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    let mut scheduled = Vec::new();
    scheduled
        .try_reserve_exact(block_count)
        .map_err(|_| ApiMarkerError::AllocationFailed)?;
    scheduled.resize(block_count, false);
    worklist.push_back(function.entry_block);
    scheduled[function.entry_block.index()] = true;
    let mut iterations = 0usize;

    while let Some(id) = worklist.pop_front() {
        scheduled[id.index()] = false;
        iterations += 1;
        if iterations > limit {
            return Err(ApiMarkerError::DataflowLimit {
                entry: function.entry,
            });
        }
        let Some(block) = function.blocks.get(id.index()) else {
            continue;
        };
        let merged = if id == function.entry_block {
            unknown
        } else {
            let mut predecessor_states = block.predecessors.iter().filter_map(|predecessor| {
                reachable
                    .get(predecessor.index())
                    .copied()
                    .unwrap_or(false)
                    .then(|| outgoing.get(predecessor.index()).copied().flatten())
                    .flatten()
            });
            let Some(first) = predecessor_states.next() else {
                continue;
            };
            predecessor_states.fold(first, merge_states)
        };
        incoming[id.index()] = Some(merged);
        let mut state = merged;
        for instruction in &block.instructions {
            let Some(rva) = instruction.rva() else {
                continue;
            };
            transfer(
                image,
                function.architecture,
                instruction.raw(),
                instruction.bytes(),
                rva,
                &mut state,
                &mut factory,
            );
        }
        if outgoing[id.index()] == Some(state) {
            continue;
        }
        outgoing[id.index()] = Some(state);
        for successor in &block.successors {
            if let EdgeTarget::Block(target) = successor.target {
                if reachable.get(target.index()) == Some(&true)
                    && scheduled.get(target.index()) == Some(&false)
                {
                    worklist.push_back(target);
                    scheduled[target.index()] = true;
                }
            }
        }
    }
    Ok(incoming)
}

fn merge_states(mut left: RegisterState, right: RegisterState) -> RegisterState {
    for (left, right) in left.iter_mut().zip(right) {
        if *left != right {
            *left = None;
        }
    }
    left
}

fn transfer(
    image: &Image<'_>,
    architecture: Architecture,
    raw: &Instruction,
    bytes: &[u8],
    rva: Rva,
    state: &mut RegisterState,
    factory: &mut InstructionInfoFactory,
) {
    let info = factory.info(raw);
    for used in info.used_registers() {
        if used.register().is_gpr()
            && matches!(
                used.access(),
                OpAccess::Read
                    | OpAccess::CondRead
                    | OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        {
            state[family_index(used.register())] = None;
        }
    }
    if let Some((register, thunk_rva)) = exact_iat_load(image, architecture, raw, bytes) {
        state[family_index(register)] = Some(Known {
            load_rva: rva,
            thunk_rva,
        });
    }
    if matches!(
        raw.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        *state = [None; 16];
    }
}

fn exact_iat_load(
    image: &Image<'_>,
    architecture: Architecture,
    raw: &Instruction,
    bytes: &[u8],
) -> Option<(Register, Rva)> {
    let valid_code = match architecture {
        Architecture::X86 => matches!(raw.code(), Code::Mov_r32_rm32 | Code::Mov_EAX_moffs32),
        Architecture::X64 => raw.code() == Code::Mov_r64_rm64,
    };
    if !valid_code
        || raw.op_count() != 2
        || raw.op0_kind() != OpKind::Register
        || raw.op1_kind() != OpKind::Memory
        || raw.flow_control() != FlowControl::Next
        || has_carried_prefix(raw)
        || !has_canonical_encoding(architecture, raw, bytes)
    {
        return None;
    }
    let register = raw.op0_register();
    let exact_width = match architecture {
        Architecture::X86 => register.size() == 4 && register.full_register32() == register,
        Architecture::X64 => register.size() == 8 && register.full_register() == register,
    };
    if !exact_width || matches!(register.full_register(), Register::RSP) {
        return None;
    }
    memory_import_thunk_target(image, raw, 1).map(|thunk| (register, thunk))
}

fn exact_register_call(
    architecture: Architecture,
    raw: &Instruction,
    bytes: &[u8],
) -> Option<Register> {
    exact_register_sdk_transfer(architecture, raw, bytes)
        .and_then(|(register, tail_call)| (!tail_call).then_some(register))
}

fn exact_register_sdk_transfer(
    architecture: Architecture,
    raw: &Instruction,
    bytes: &[u8],
) -> Option<(Register, bool)> {
    let tail_call = match (architecture, raw.code()) {
        (Architecture::X86, Code::Call_rm32) | (Architecture::X64, Code::Call_rm64) => false,
        (Architecture::X86, Code::Jmp_rm32) | (Architecture::X64, Code::Jmp_rm64) => true,
        _ => return None,
    };
    if raw.op_count() != 1
        || raw.op0_kind() != OpKind::Register
        || has_carried_prefix(raw)
        || !has_canonical_encoding(architecture, raw, bytes)
    {
        return None;
    }
    let register = raw.op0_register();
    let exact_width = match architecture {
        Architecture::X86 => register.size() == 4 && register.full_register32() == register,
        Architecture::X64 => register.size() == 8 && register.full_register() == register,
    };
    (exact_width && register.full_register() != Register::RSP).then_some((register, tail_call))
}

fn has_carried_prefix(raw: &Instruction) -> bool {
    raw.has_lock_prefix()
        || raw.has_rep_prefix()
        || raw.has_repne_prefix()
        || raw.segment_prefix() != Register::None
}

fn has_canonical_encoding(architecture: Architecture, raw: &Instruction, bytes: &[u8]) -> bool {
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    };
    let mut encoder = Encoder::new(bitness);
    encoder.encode(raw, raw.ip()).is_ok() && encoder.take_buffer() == bytes
}

fn family_index(register: Register) -> usize {
    match register.full_register() {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => 4,
    }
}

fn called_import_thunk(image: &Image<'_>, call: &Instruction, bytes: &[u8]) -> Option<Rva> {
    if has_carried_prefix(call) || !has_canonical_encoding(image.architecture(), call, bytes) {
        return None;
    }
    match call.code() {
        Code::Call_rm32 | Code::Call_rm64 => import_thunk_target(image, call),
        Code::Call_rel32_32 | Code::Call_rel32_64 => {
            let target = near_branch_rva(call)?;
            if !image.is_executable(target) {
                return None;
            }
            let bytes = image.bytes_from(target)?;
            let decoded = decode_at(image.bitness(), bytes, target)?;
            let thunk = decoded.raw;
            if !matches!(thunk.code(), Code::Jmp_rm32 | Code::Jmp_rm64)
                || has_carried_prefix(&thunk)
                || !has_canonical_encoding(image.architecture(), &thunk, &bytes[..decoded.len])
            {
                return None;
            }
            import_thunk_target(image, &thunk)
        }
        _ => None,
    }
}

fn sdk_import_transfer_thunk(
    image: &Image<'_>,
    transfer: &Instruction,
    bytes: &[u8],
) -> Option<(Rva, bool)> {
    if let Some(thunk) = called_import_thunk(image, transfer, bytes) {
        return Some((thunk, false));
    }
    if has_carried_prefix(transfer)
        || !has_canonical_encoding(image.architecture(), transfer, bytes)
    {
        return None;
    }
    let thunk = match transfer.code() {
        Code::Jmp_rm32 | Code::Jmp_rm64 => import_thunk_target(image, transfer),
        Code::Jmp_rel32_32 | Code::Jmp_rel32_64 => {
            let target = near_branch_rva(transfer)?;
            if !image.is_executable(target) {
                return None;
            }
            let target_bytes = image.bytes_from(target)?;
            let decoded = decode_at(image.bitness(), target_bytes, target)?;
            let thunk = decoded.raw;
            if !matches!(thunk.code(), Code::Jmp_rm32 | Code::Jmp_rm64)
                || has_carried_prefix(&thunk)
                || !has_canonical_encoding(
                    image.architecture(),
                    &thunk,
                    &target_bytes[..decoded.len],
                )
            {
                return None;
            }
            import_thunk_target(image, &thunk)
        }
        _ => None,
    }?;
    Some((thunk, true))
}

fn is_sdk_library(architecture: Architecture, name: &str) -> bool {
    let (sdk, ddk) = match architecture {
        Architecture::X86 => ("VMProtectSDK32.dll", "VMProtectDDK32.sys"),
        Architecture::X64 => ("VMProtectSDK64.dll", "VMProtectDDK64.sys"),
    };
    name.eq_ignore_ascii_case(sdk) || name.eq_ignore_ascii_case(ddk)
}

fn begin_policy(name: &str) -> Option<(MarkerCompilationType, bool)> {
    match name {
        "VMProtectBegin" => Some((MarkerCompilationType::Default, false)),
        "VMProtectBeginVirtualization" => Some((MarkerCompilationType::Virtualization, false)),
        "VMProtectBeginMutation" => Some((MarkerCompilationType::Mutation, false)),
        "VMProtectBeginUltra" => Some((MarkerCompilationType::Ultra, false)),
        "VMProtectBeginVirtualizationLockByKey" => {
            Some((MarkerCompilationType::Virtualization, true))
        }
        "VMProtectBeginUltraLockByKey" => Some((MarkerCompilationType::Ultra, true)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use vmp_ir::{BasicBlock, BlockId, CompileStage, Edge, EdgeKind, EdgeTarget, Terminator};
    use vmp_pe::{ImportTarget, PeFile};

    fn required_fixture() -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vmp-pe")
            .join("test-corpus")
            .join("win64-app-msvc-amd64");
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()))
    }

    fn required_x86_fixture() -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vmp-pe")
            .join("test-corpus")
            .join("win32-app-test1-i386");
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()))
    }

    fn fixture_with_x64_register_begin(use_64_bit_load: bool) -> (Vec<u8>, Rva, Rva) {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let thunk_rva = pe
            .imports
            .as_ref()
            .expect("fixture must have imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK64.dll")
            .expect("fixture must import the x64 SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("fixture must import the Begin marker");
        let load_rva = Rva(0x1033);
        let load_len = if use_64_bit_load { 7 } else { 6 };
        let call_rva = load_rva.checked_add(load_len).expect("test RVA fits");
        let displacement = i64::from(thunk_rva.get()) - i64::from(call_rva.get());
        let displacement = i32::try_from(displacement)
            .expect("fixture RIP displacement fits")
            .to_le_bytes();
        let offset = pe
            .rva_to_offset(load_rva)
            .expect("Begin site must be file-backed")
            .get() as usize;
        let mut bytes = Vec::new();
        if use_64_bit_load {
            bytes.push(0x48);
        }
        bytes.extend_from_slice(&[0x8b, 0x05]);
        bytes.extend_from_slice(&displacement);
        bytes.extend_from_slice(&[0xff, 0xd0]);
        data[offset..offset + bytes.len()].copy_from_slice(&bytes);
        (
            data,
            call_rva,
            call_rva.checked_add(2).expect("test RVA fits"),
        )
    }

    fn fixture_with_rel32_begin_target(target_instruction: &[u8]) -> Vec<u8> {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let begin_call = pe
            .rva_to_offset(Rva(0x1033))
            .expect("Begin call must be file-backed")
            .get() as usize;
        let target = pe
            .rva_to_offset(Rva(0x1210))
            .expect("runtime-function gap must be file-backed")
            .get() as usize;

        // 0x1210 is an executable gap between runtime functions 0x1205 and
        // 0x1230. The rel32 is 0x1210 - 0x1038 = 0x1d8.
        data[begin_call..begin_call + 6].copy_from_slice(&[0xe8, 0xd8, 0x01, 0x00, 0x00, 0x90]);
        data[target..target + target_instruction.len()].copy_from_slice(target_instruction);
        data
    }

    fn x86_fixture_with_thunk(opcode: u8) -> (Vec<u8>, Rva, Rva) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vmp-pe")
            .join("test-corpus")
            .join("win32-app-test1-i386");
        let mut data = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("required fixture {}: {error}", path.display()));
        let pe = PeFile::parse(&data).expect("required x86 fixture must parse");
        let iat_rva = pe
            .imports
            .as_ref()
            .expect("fixture must have imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK32.dll")
            .expect("fixture must import the x86 SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("fixture must import the Begin marker");
        let target_rva = Rva(0x1200);
        let target_offset = pe
            .rva_to_offset(target_rva)
            .expect("x86 thunk target must be file-backed")
            .get() as usize;
        let iat_va = pe
            .optional
            .image_base
            .get()
            .checked_add(u64::from(iat_rva.get()))
            .and_then(|value| u32::try_from(value).ok())
            .expect("fixture IAT VA must fit PE32")
            .to_le_bytes();
        data[target_offset..target_offset + 6]
            .copy_from_slice(&[0xff, opcode, iat_va[0], iat_va[1], iat_va[2], iat_va[3]]);
        (data, target_rva, iat_rva)
    }

    fn x86_rel32_call(target_rva: Rva) -> vmp_ir::Instruction {
        let call_rva = Rva(0x1000);
        let displacement = i64::from(target_rva.get()) - i64::from(call_rva.get() + 5);
        let displacement = i32::try_from(displacement).expect("fixture rel32 must fit");
        let mut bytes = [0xe8, 0, 0, 0, 0];
        bytes[1..].copy_from_slice(&displacement.to_le_bytes());
        let decoded = decode_at(32, &bytes, call_rva).expect("fixture rel32 call must decode");
        vmp_ir::Instruction::decoded(call_rva, decoded.raw, &bytes[..decoded.len])
    }

    fn ir_instruction(bitness: u32, rva: u32, bytes: &[u8]) -> vmp_ir::Instruction {
        let decoded = decode_at(bitness, bytes, Rva(rva)).expect("test instruction must decode");
        vmp_ir::Instruction::decoded(Rva(rva), decoded.raw, &bytes[..decoded.len])
    }

    fn dataflow_block(
        id: u32,
        rva: u32,
        instructions: Vec<vmp_ir::Instruction>,
        successors: &[u32],
        predecessors: &[u32],
    ) -> BasicBlock {
        let end = instructions
            .last()
            .and_then(vmp_ir::Instruction::next_rva)
            .unwrap_or(Rva(rva));
        BasicBlock {
            id: BlockId(id),
            start: Rva(rva),
            end,
            instructions,
            terminator: Terminator::Jump,
            successors: successors
                .iter()
                .map(|id| Edge::new(EdgeKind::Jump, EdgeTarget::Block(BlockId(*id))))
                .collect(),
            predecessors: predecessors.iter().copied().map(BlockId).collect(),
        }
    }

    fn dataflow_function(blocks: Vec<BasicBlock>) -> Function {
        Function {
            architecture: Architecture::X64,
            entry: blocks[0].start,
            blocks,
            entry_block: BlockId(0),
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    #[test]
    fn reaching_definitions_converges_over_a_reachable_self_loop() {
        let (data, _, _) = fixture_with_x64_register_begin(true);
        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let image = Image::new(&pe, &data);
        let offset = pe
            .rva_to_offset(Rva(0x1033))
            .expect("load must be file-backed")
            .get() as usize;
        let load = ir_instruction(64, 0x1033, &data[offset..offset + 7]);
        let function = dataflow_function(vec![
            dataflow_block(0, 0x1033, vec![load], &[1], &[]),
            dataflow_block(
                1,
                0x1040,
                vec![ir_instruction(64, 0x1040, &[0x90])],
                &[1, 2],
                &[0, 1],
            ),
            dataflow_block(2, 0x1050, vec![], &[], &[1]),
        ]);

        let incoming = reaching_definitions(&image, &function)
            .expect("a finite conservative lattice must converge over loops");
        assert_eq!(
            incoming[2].expect("exit is reachable")[0]
                .expect("load must reach the exit")
                .load_rva,
            Rva(0x1033)
        );
    }

    #[test]
    fn reaching_definitions_ignores_an_unreachable_predecessor() {
        let (data, _, _) = fixture_with_x64_register_begin(true);
        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let image = Image::new(&pe, &data);
        let offset = pe
            .rva_to_offset(Rva(0x1033))
            .expect("load must be file-backed")
            .get() as usize;
        let load = ir_instruction(64, 0x1033, &data[offset..offset + 7]);
        let function = dataflow_function(vec![
            dataflow_block(0, 0x1033, vec![load], &[1], &[]),
            dataflow_block(1, 0x1040, vec![], &[], &[0, 2]),
            dataflow_block(
                2,
                0x1050,
                vec![ir_instruction(64, 0x1050, &[0x48, 0x31, 0xc0])],
                &[1],
                &[],
            ),
        ]);

        let incoming = reaching_definitions(&image, &function).expect("analysis must converge");
        assert_eq!(
            incoming[1].expect("join is reachable")[0]
                .expect("reachable definition must survive the join")
                .load_rva,
            Rva(0x1033)
        );
        assert_eq!(incoming[2], None);
    }

    #[test]
    fn x86_roots_ignore_an_exception_table_and_keep_the_entry() {
        let data = required_x86_fixture();
        let mut pe = PeFile::parse(&data).expect("required x86 fixture must parse");
        pe.exception_table = Some(Default::default());
        let image = Image::new(&pe, &data);

        assert!(discovery_roots(&image)
            .expect("root collection must succeed")
            .contains(&pe.entry_point()));
    }

    #[test]
    fn decode_budget_issue_is_a_discovery_instruction_limit_error() {
        let mut function = dataflow_function(vec![dataflow_block(0, 0x1000, vec![], &[], &[])]);
        function
            .issues
            .push(vmp_ir::DecodeIssue::BudgetExceeded { limit: 8 });
        let mut total = 0;
        assert_eq!(
            charge_decode_work(&function, 8, &mut total, 64),
            Err(ApiMarkerError::TooManyInstructions { limit: 64 })
        );
        assert_eq!(total, 0);
    }

    #[test]
    fn decoder_reports_actual_budget_spent() {
        let data = required_x86_fixture();
        let pe = PeFile::parse(&data).expect("required x86 fixture must parse");
        let image = Image::new(&pe, &data);
        let (function, spent) = crate::decode_function_with_spent(
            image,
            pe.entry_point(),
            DecodeOptions { budget: 64 },
        )
        .expect("entry function must decode");
        assert!(spent >= function.instruction_count());
        assert!(spent <= 64);
    }

    #[test]
    fn pe32_recursion_accepts_an_operand_size_call_rel16() {
        let call = decode_at(32, &[0x66, 0xe8, 0xfc, 0x00], Rva(0x1000))
            .expect("PE32 rel16 call must decode")
            .raw;
        assert_eq!(call.code(), Code::Call_rel16);
        assert!(is_recursive_pe32_call(&call));
        assert_eq!(near_branch_rva(&call), Some(Rva(0x1100)));
    }

    #[test]
    fn pe32_entry_recurses_through_rel16_to_a_marker_helper() {
        let mut data = required_x86_fixture();
        let pe = PeFile::parse(&data).expect("required x86 fixture must parse");
        let thunk_rva = pe
            .imports
            .as_ref()
            .expect("fixture must have imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK32.dll")
            .expect("fixture must import the x86 SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("fixture must import the Begin marker");
        let thunk_va = u32::try_from(pe.optional.image_base.get() + u64::from(thunk_rva.get()))
            .expect("PE32 thunk VA must fit")
            .to_le_bytes();
        let entry_offset = pe
            .rva_to_offset(Rva(0x1000))
            .expect("entry must be file-backed")
            .get() as usize;
        data[entry_offset..entry_offset + 5].copy_from_slice(&[0x66, 0xe8, 0xfc, 0x00, 0xc3]);
        let helper_offset = pe
            .rva_to_offset(Rva(0x1100))
            .expect("helper must be file-backed")
            .get() as usize;
        data[helper_offset..helper_offset + 7].copy_from_slice(&[
            0xff,
            0x15,
            thunk_va[0],
            thunk_va[1],
            thunk_va[2],
            thunk_va[3],
            0xc3,
        ]);

        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("recursive discovery must succeed");
        assert!(markers.contains(&ApiMarker::Begin {
            load_rva: None,
            call_rva: Rva(0x1100),
            next_rva: Rva(0x1106),
            name_rva: None,
            name_reference_rva: None,
            compilation_type: MarkerCompilationType::Default,
            lock_to_key: false,
        }));
    }

    #[test]
    fn contradictory_observations_at_one_call_are_ambiguous() {
        let mut markers = HashMap::new();
        let first = ApiMarker::End {
            load_rva: None,
            call_rva: Rva(0x1234),
            next_rva: Rva(0x1236),
        };
        let contradictory = ApiMarker::Begin {
            load_rva: None,
            call_rva: Rva(0x1234),
            next_rva: Rva(0x1239),
            name_rva: None,
            name_reference_rva: None,
            compilation_type: MarkerCompilationType::Default,
            lock_to_key: false,
        };
        retain_marker_observation(&mut markers, first, 2)
            .expect("first observation must be retained");
        assert_eq!(
            retain_marker_observation(&mut markers, contradictory, 2),
            Err(ApiMarkerError::AmbiguousObservation {
                call_rva: Rva(0x1234)
            })
        );
    }

    #[test]
    fn bounded_enqueue_rejects_before_retaining_one_over_limit() {
        let mut queue = VecDeque::new();
        let mut queued = HashSet::new();
        assert!(enqueue_function(&mut queue, &mut queued, Rva(1), 1).expect("first entry must fit"));
        assert_eq!(
            enqueue_function(&mut queue, &mut queued, Rva(2), 1),
            Err(ApiMarkerError::TooManyFunctions { limit: 1 })
        );
        assert_eq!(queue.into_iter().collect::<Vec<_>>(), vec![Rva(1)]);
        assert_eq!(queued.into_iter().collect::<Vec<_>>(), vec![Rva(1)]);
    }

    #[test]
    fn sdk_library_matching_is_exact_and_ascii_case_insensitive() {
        use vmp_types::Architecture;
        for accepted in ["VMProtectSDK32.dll", "vmprotectddk32.SYS"] {
            assert!(is_sdk_library(Architecture::X86, accepted));
            assert!(!is_sdk_library(Architecture::X64, accepted));
        }
        for accepted in ["vmprotectsdk64.DLL", "VMProtectDDK64.sys"] {
            assert!(is_sdk_library(Architecture::X64, accepted));
            assert!(!is_sdk_library(Architecture::X86, accepted));
        }
        for rejected in [
            "xVMProtectSDK64.dll",
            "VMProtectSDK64.dll.bak",
            "VMProtectSDK.dll",
            "VMProtectSDK64.sys",
        ] {
            assert!(!is_sdk_library(Architecture::X64, rejected));
        }
    }

    #[test]
    fn begin_policy_matches_the_cpp_sdk_table() {
        assert_eq!(
            begin_policy("VMProtectBegin"),
            Some((MarkerCompilationType::Default, false))
        );
        assert_eq!(
            begin_policy("VMProtectBeginVirtualization"),
            Some((MarkerCompilationType::Virtualization, false))
        );
        assert_eq!(
            begin_policy("VMProtectBeginMutation"),
            Some((MarkerCompilationType::Mutation, false))
        );
        assert_eq!(
            begin_policy("VMProtectBeginUltra"),
            Some((MarkerCompilationType::Ultra, false))
        );
        assert_eq!(
            begin_policy("VMProtectBeginVirtualizationLockByKey"),
            Some((MarkerCompilationType::Virtualization, true))
        );
        assert_eq!(
            begin_policy("VMProtectBeginUltraLockByKey"),
            Some((MarkerCompilationType::Ultra, true))
        );
        assert_eq!(begin_policy("VMProtectBeginMutationLockByKey"), None);
        assert_eq!(begin_policy("VMProtectEnd"), None);
    }

    #[test]
    fn direct_marker_limit_accepts_exact_and_rejects_one_over() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        assert_eq!(
            discover_direct_api_markers_with_limit(image, 3)
                .expect("exact corpus marker count must fit")
                .len(),
            3
        );
        assert_eq!(
            discover_direct_api_markers_with_limit(image, 2),
            Err(ApiMarkerError::TooManyMarkers { limit: 2 })
        );
    }

    #[test]
    fn matches_cpp_api_marker_addresses_in_the_x64_corpus() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let markers = discover_direct_api_markers(image).expect("SDK API markers must scan");
        assert_eq!(
            markers,
            vec![
                ApiMarker::Begin {
                    load_rva: None,
                    call_rva: Rva(0x1033),
                    next_rva: Rva(0x1039),
                    name_rva: Some(Rva(0x72c8)),
                    name_reference_rva: Some(Rva(0x1027)),
                    compilation_type: MarkerCompilationType::Default,
                    lock_to_key: false,
                },
                ApiMarker::End {
                    load_rva: None,
                    call_rva: Rva(0x10f9),
                    next_rva: Rva(0x10ff),
                },
                ApiMarker::End {
                    load_rva: None,
                    call_rva: Rva(0x1143),
                    next_rva: Rva(0x1149),
                },
            ]
        );
        let ApiMarker::Begin {
            name_rva: Some(name_rva),
            ..
        } = markers[0]
        else {
            panic!("the first corpus marker must be a named Begin")
        };
        assert_eq!(image.utf8_c_string(name_rva, 11), Some("Test marker"));
        assert_eq!(
            image.utf8_c_string(name_rva, 10),
            None,
            "the terminator lies one byte beyond the bounded payload"
        );
    }

    #[test]
    fn recovers_a_begin_name_from_mov_rcx_imm64() {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let offset = pe
            .rva_to_offset(Rva(0x1027))
            .expect("name producer is file-backed")
            .get() as usize;
        let value = pe
            .optional
            .image_base
            .get()
            .checked_add(u64::from(0x72c8_u32))
            .expect("fixture name VA fits");
        data[offset..offset + 2].copy_from_slice(&[0x48, 0xb9]);
        data[offset + 2..offset + 10].copy_from_slice(&value.to_le_bytes());
        data[offset + 10..offset + 12].fill(0x90);
        let pe = PeFile::parse(&data).expect("adapted fixture reparses");
        let markers =
            discover_direct_api_markers(Image::new(&pe, &data)).expect("immediate producer scans");
        assert!(markers.contains(&ApiMarker::Begin {
            load_rva: None,
            call_rva: Rva(0x1033),
            next_rva: Rva(0x1039),
            name_rva: Some(Rva(0x72c8)),
            name_reference_rva: Some(Rva(0x1027)),
            compilation_type: MarkerCompilationType::Default,
            lock_to_key: false,
        }));
    }

    #[test]
    fn recovers_a_begin_name_from_mov_ecx_imm32() {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let offset = pe
            .rva_to_offset(Rva(0x1027))
            .expect("name producer is file-backed")
            .get() as usize;
        data[offset] = 0xb9;
        data[offset + 1..offset + 5].copy_from_slice(&0x72c8_u32.to_le_bytes());
        data[offset + 5..offset + 12].fill(0x90);
        let pe = PeFile::parse(&data).expect("adapted fixture reparses");
        let markers =
            discover_direct_api_markers(Image::new(&pe, &data)).expect("immediate producer scans");
        assert!(markers.contains(&ApiMarker::Begin {
            load_rva: None,
            call_rva: Rva(0x1033),
            next_rva: Rva(0x1039),
            name_rva: Some(Rva(0x72c8)),
            name_reference_rva: Some(Rva(0x1027)),
            compilation_type: MarkerCompilationType::Default,
            lock_to_key: false,
        }));
    }

    #[test]
    fn discovers_cpp_identity_decrypt_calls_in_the_x64_corpus() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let function = crate::decode_function(image, Rva(0x1000)).expect("marker function decodes");
        assert_eq!(
            discover_sdk_api_calls(image, &function).expect("SDK API calls must scan"),
            vec![
                SdkApiCall {
                    api: SdkApi::DecryptStringA,
                    load_rva: None,
                    call_rva: Rva(0x10da),
                    next_rva: Rva(0x10e0),
                    tail_call: false,
                },
                SdkApiCall {
                    api: SdkApi::DecryptStringA,
                    load_rva: None,
                    call_rva: Rva(0x110d),
                    next_rva: Rva(0x1113),
                    tail_call: false,
                },
            ]
        );
    }

    #[test]
    fn discovers_a_direct_iat_tail_jump_to_a_runtime_free_sdk_api() {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let offset = pe
            .rva_to_offset(Rva(0x10da))
            .expect("decrypt call is file-backed")
            .get() as usize;
        assert_eq!(&data[offset..offset + 2], &[0xff, 0x15]);
        data[offset + 1] = 0x25;
        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let image = Image::new(&pe, &data);
        let function = crate::decode_function(image, Rva(0x1000)).expect("marker function decodes");
        assert!(discover_sdk_api_calls(image, &function)
            .expect("SDK API transfers must scan")
            .contains(&SdkApiCall {
                api: SdkApi::DecryptStringA,
                load_rva: None,
                call_rva: Rva(0x10da),
                next_rva: Rva(0x10e0),
                tail_call: true,
            }));
    }

    #[test]
    fn discovers_x64_mov_iat_then_call_same_full_register() {
        let (data, call_rva, next_rva) = fixture_with_x64_register_begin(true);
        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("bounded x64 discovery must succeed");
        assert!(markers.contains(&ApiMarker::Begin {
            load_rva: Some(Rva(0x1033)),
            call_rva,
            next_rva,
            name_rva: Some(Rva(0x72c8)),
            name_reference_rva: Some(Rva(0x1027)),
            compilation_type: MarkerCompilationType::Default,
            lock_to_key: false,
        }));
    }

    #[test]
    fn rejects_a_32_bit_iat_load_in_x64_code() {
        let (data, call_rva, _) = fixture_with_x64_register_begin(false);
        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("bounded x64 discovery must succeed");
        assert!(markers
            .iter()
            .all(|marker| marker_call_rva(*marker) != call_rva));
    }

    #[test]
    fn rejects_a_redundant_rex_prefix_on_a_register_call() {
        let bytes = [0x40, 0xff, 0xd0];
        let call = decode_at(64, &bytes, Rva(0x1000))
            .expect("redundantly prefixed call must decode")
            .raw;
        assert_eq!(call.code(), Code::Call_rm64);
        assert_eq!(exact_register_call(Architecture::X64, &call, &bytes), None);
    }

    #[test]
    fn rejects_a_same_length_noncanonical_rex_prefix_on_a_register_call() {
        let bytes = [0x49, 0xff, 0xd0];
        let call = decode_at(64, &bytes, Rva(0x1000))
            .expect("same-length noncanonical call must decode")
            .raw;
        assert_eq!(call.code(), Code::Call_rm64);
        assert_eq!(call.op0_register(), Register::R8);
        assert_eq!(exact_register_call(Architecture::X64, &call, &bytes), None);
    }

    #[test]
    fn register_marker_requires_the_unclobbered_same_full_register() {
        let (base, original_call, _) = fixture_with_x64_register_begin(true);
        let cases: &[(&str, &[u8])] = &[
            ("wrong register", &[0xff, 0xd1]),
            ("intervening read", &[0x48, 0x89, 0xc1, 0xff, 0xd0]),
            ("partial write", &[0xb0, 0x00, 0xff, 0xd0]),
            ("full write", &[0x48, 0x31, 0xc0, 0xff, 0xd0]),
            ("conditional write", &[0x48, 0x0f, 0x44, 0xc1, 0xff, 0xd0]),
            ("call barrier", &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0]),
            ("memory-indirect call", &[0xff, 0x10]),
            ("register jump", &[0xff, 0xe0]),
        ];
        for &(name, replacement) in cases {
            let mut data = base.clone();
            let pe = PeFile::parse(&data).expect("required fixture must parse");
            let offset = pe
                .rva_to_offset(original_call)
                .expect("adapted call site must be file-backed")
                .get() as usize;
            data[offset..offset + replacement.len()].copy_from_slice(replacement);
            let pe = PeFile::parse(&data).expect("adapted fixture must parse");
            let markers = discover_direct_api_markers(Image::new(&pe, &data))
                .unwrap_or_else(|error| panic!("{name}: discovery failed: {error}"));
            assert!(
                markers.iter().all(|marker| !matches!(
                    marker,
                    ApiMarker::Begin {
                        load_rva: Some(Rva(0x1033)),
                        ..
                    }
                )),
                "{name} retained a register marker: {markers:?}"
            );
        }
    }

    #[test]
    fn discovers_x86_mov_iat_then_call_register_from_the_entry_root() {
        let mut data = required_x86_fixture();
        let pe = PeFile::parse(&data).expect("required x86 fixture must parse");
        let thunk_rva = pe
            .imports
            .as_ref()
            .expect("fixture must have imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK32.dll")
            .expect("fixture must import the x86 SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("fixture must import the Begin marker");
        let thunk_va = pe
            .optional
            .image_base
            .get()
            .checked_add(u64::from(thunk_rva.get()))
            .and_then(|value| u32::try_from(value).ok())
            .expect("PE32 thunk VA must fit")
            .to_le_bytes();
        let offset = pe
            .rva_to_offset(Rva(0x1000))
            .expect("entry must be file-backed")
            .get() as usize;
        data[offset..offset + 7].copy_from_slice(&[
            0xa1,
            thunk_va[0],
            thunk_va[1],
            thunk_va[2],
            thunk_va[3],
            0xff,
            0xd0,
        ]);

        let pe = PeFile::parse(&data).expect("adapted fixture must parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("bounded PE32 discovery must succeed");
        assert!(
            markers.contains(&ApiMarker::Begin {
                load_rva: Some(Rva(0x1000)),
                call_rva: Rva(0x1005),
                next_rva: Rva(0x1007),
                name_rva: None,
                name_reference_rva: None,
                compilation_type: MarkerCompilationType::Default,
                lock_to_key: false,
            }),
            "markers: {markers:?}"
        );
    }

    #[test]
    fn resolves_a_rel32_call_through_an_import_jump_thunk() {
        // `jmp [Begin IAT]`, where 0x7210 - 0x1216 = 0x5ffa.
        let data = fixture_with_rel32_begin_target(&[0xff, 0x25, 0xfa, 0x5f, 0x00, 0x00]);
        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert_eq!(
            markers.first(),
            Some(&ApiMarker::Begin {
                load_rva: None,
                call_rva: Rva(0x1033),
                next_rva: Rva(0x1038),
                name_rva: Some(Rva(0x72c8)),
                name_reference_rva: Some(Rva(0x1027)),
                compilation_type: MarkerCompilationType::Default,
                lock_to_key: false,
            })
        );
    }

    #[test]
    fn resolves_an_x86_rel32_call_through_an_absolute_iat_thunk() {
        let (data, target_rva, iat_rva) = x86_fixture_with_thunk(0x25);
        let pe = PeFile::parse(&data).expect("adapted x86 fixture must parse");
        let image = Image::new(&pe, &data);
        let call = x86_rel32_call(target_rva);
        assert_eq!(
            called_import_thunk(&image, call.raw(), call.bytes()),
            Some(iat_rva)
        );
    }

    #[test]
    fn rejects_a_segment_prefixed_direct_iat_call() {
        let data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let image = Image::new(&pe, &data);
        let thunk_rva = pe
            .imports
            .as_ref()
            .expect("fixture must have imports")
            .descriptors
            .iter()
            .find(|library| library.name == "VMProtectSDK64.dll")
            .expect("fixture must import the x64 SDK")
            .functions
            .iter()
            .find_map(|function| match &function.target {
                ImportTarget::Name { name, .. } if name == "VMProtectBegin" => {
                    Some(function.thunk_rva)
                }
                _ => None,
            })
            .expect("fixture must import the Begin marker");
        let call_rva = Rva(0x1033);
        let next_rva = call_rva.checked_add(7).expect("test RVA fits");
        let displacement = i64::from(thunk_rva.get()) - i64::from(next_rva.get());
        let displacement = i32::try_from(displacement)
            .expect("fixture RIP displacement fits")
            .to_le_bytes();
        let bytes = [
            0x64,
            0xff,
            0x15,
            displacement[0],
            displacement[1],
            displacement[2],
            displacement[3],
        ];
        let call = decode_at(64, &bytes, call_rva)
            .expect("segment-prefixed direct call must decode")
            .raw;

        assert_eq!(called_import_thunk(&image, &call, &bytes), None);
    }

    #[test]
    fn rejects_a_segment_prefixed_import_jump_thunk() {
        // `fs:jmp [Begin IAT]`; the nominal RIP-relative address is
        // the IAT slot, but FS changes the CPU's effective address.
        let data = fixture_with_rel32_begin_target(&[0x64, 0xff, 0x25, 0xf9, 0x5f, 0x00, 0x00]);
        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert!(markers
            .iter()
            .all(|marker| marker_call_rva(*marker) != Rva(0x1033)));
    }

    #[test]
    fn rejects_an_x86_far_jump_through_the_absolute_iat_address() {
        let (data, target_rva, _) = x86_fixture_with_thunk(0x2d);
        let pe = PeFile::parse(&data).expect("adapted x86 fixture must parse");
        let image = Image::new(&pe, &data);
        let call = x86_rel32_call(target_rva);
        assert_eq!(called_import_thunk(&image, call.raw(), call.bytes()), None);
    }

    #[test]
    fn does_not_follow_a_rel32_target_that_calls_the_import() {
        // `call [Begin IAT]` at the rel32 target is another call frame,
        // not the one-instruction tail-jump thunk recognized by this slice.
        let data = fixture_with_rel32_begin_target(&[0xff, 0x15, 0xfa, 0x5f, 0x00, 0x00]);
        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert!(markers.iter().all(|marker| match marker {
            ApiMarker::Begin { call_rva, .. } | ApiMarker::End { call_rva, .. } => {
                *call_rva != Rva(0x1033)
            }
        }));
    }

    #[test]
    fn does_not_accept_a_far_jump_as_an_import_thunk() {
        // FF /5 reads a far pointer from memory. An IAT slot contains only the
        // near target pointer expected by FF /4, so this is not a linker thunk.
        let data = fixture_with_rel32_begin_target(&[0xff, 0x2d, 0xfa, 0x5f, 0x00, 0x00]);
        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert!(markers.iter().all(|marker| match marker {
            ApiMarker::Begin { call_rva, .. } | ApiMarker::End { call_rva, .. } => {
                *call_rva != Rva(0x1033)
            }
        }));
    }

    #[test]
    fn does_not_accept_a_far_call_as_a_direct_iat_marker() {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let begin_call = pe
            .rva_to_offset(Rva(0x1033))
            .expect("Begin call must be file-backed")
            .get() as usize;
        // Change near FF /2 to far FF /3 without changing its IAT address.
        data[begin_call + 1] = 0x1d;

        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert!(markers.iter().all(|marker| match marker {
            ApiMarker::Begin { call_rva, .. } | ApiMarker::End { call_rva, .. } => {
                *call_rva != Rva(0x1033)
            }
        }));
    }

    #[test]
    fn does_not_treat_ff15_inside_an_instruction_as_a_marker_call() {
        let mut data = required_fixture();
        let pe = PeFile::parse(&data).expect("required fixture must parse");
        let offset = pe
            .rva_to_offset(Rva(0x1031))
            .expect("fixture instruction is file-backed")
            .get() as usize;
        // mov eax, 0060d815h embeds FF 15 at 0x1032. Interpreted from that
        // interior byte, the following displacement names the real Begin IAT
        // slot at 0x7210, so a byte scanner reports a convincing false marker.
        data[offset..offset + 8].copy_from_slice(&[0xb8, 0xff, 0x15, 0xd8, 0x61, 0x00, 0x00, 0x90]);
        let pe = PeFile::parse(&data).expect("adapted fixture must still parse");
        let markers = discover_direct_api_markers(Image::new(&pe, &data))
            .expect("instruction-aware marker discovery must succeed");
        assert!(
            markers.iter().all(|marker| match marker {
                ApiMarker::Begin { call_rva, .. } | ApiMarker::End { call_rva, .. } => {
                    *call_rva != Rva(0x1032)
                }
            }),
            "interior FF 15 bytes were accepted as an instruction boundary: {markers:?}"
        );
    }
}
