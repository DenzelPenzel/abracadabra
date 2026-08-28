//! Recognition of the trailing code an x64 unwinder reads back at run time.
//!
//! The Windows x64 unwind data describes the prologue and nothing else:
//! version 1 `UNWIND_INFO`, which is what compilers emit, has no record of
//! where the epilogues are. The unwinder finds them by *reading the code*.
//! From the x64 ABI: "To determine if the `RIP` is within an epilog, the code
//! stream from `RIP` onward is examined. If that code stream matches the
//! trailing portion of a legitimate epilog, it's in an epilog."
//!
//! The legal forms are pinned down for exactly that reason: "It must consist of
//! either an `add RSP,constant` or `lea RSP,constant[FPReg]`, followed by a
//! series of zero or more 8-byte register pops and a `return` or a `jmp`. […]
//! No other code can appear."
//!
//! So anything a transform puts between those instructions makes the run
//! unrecognisable. An unwind that lands on the inserted instruction then falls
//! through to the full unwind codes — which describe a stack that has already
//! been partly restored — and reconstructs the caller from the wrong `RSP`.
//!
//! # Why this keys on the stack pointer instead of on the pattern
//!
//! Matching the ABI pattern literally is the cheapest option and the most
//! dangerous one. Its failure mode is *under*-recognition: any legal form the
//! matcher does not anticipate is left unprotected, and that is precisely what
//! corrupts a binary. Over-recognition only costs insertion sites.
//!
//! What actually has to hold is narrower than "this is an epilogue" — no
//! insertion at a point where `RSP` has already moved away from what the unwind
//! codes describe — and that is decidable without a pattern. Every instruction
//! that can begin a legal epilogue writes `RSP`: the stack adjustment does, and
//! so does every `pop`. Taking the maximal trailing run of `RSP` writers
//! therefore cannot miss a stack adjustment, whatever encoding it arrives in.
//!
//! The terminator is included in the run whether or not it writes `RSP`, which
//! is what covers a tail call through the import table: `jmp [rip+N]` leaves
//! the stack alone, but the `pop` before it does not.
//!
//! A lone `ret` is deliberately *not* reported. Inserting immediately before it
//! is safe — the unwinder reads the inserted instruction, fails to match, and
//! applies the full unwind codes, which are correct there because nothing has
//! touched the stack yet.
//!
//! # A call is not a stack adjustment
//!
//! `call` writes `RSP` — it pushes a return address — but by the time the next
//! instruction runs the callee has taken it back off, so `RSP` again agrees
//! with the unwind codes and there is nothing to protect. The question this
//! module asks is therefore "does this instruction leave `RSP` changed", not
//! "does it write `RSP`", and a call is the one instruction where those differ.
//!
//! # Runs are joined across block boundaries
//!
//! An epilogue can be split between blocks, because a shared epilogue is
//! reached by branching into the middle of one, and a branch target always
//! starts a block. Two ranges that meet end-to-begin therefore describe one
//! epilogue, and left separate they would leave the address between them
//! belonging to neither — the one spot inside the epilogue an insertion could
//! still reach. They are merged.
//!
//! # Scope
//!
//! This over-approximates the epilogue and never under-approximates it, so a
//! reported range is "at least the epilogue" rather than "exactly" it. The
//! remaining over-approximation is a `push` in the body of a function, which
//! does leave `RSP` changed but only in a function with a frame pointer, where
//! unwinding goes through the frame register and would have been fine.

use iced_x86::{
    FlowControl, Instruction as RawInstruction, InstructionInfoFactory, OpAccess, Register,
};
use vmp_ir::Function;
use vmp_types::Rva;

/// A run of instructions at the end of a block that must be reproduced exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epilogue {
    /// RVA of the first instruction of the run.
    pub begin: Rva,
    /// RVA one past the last instruction of the run, which is the end of its
    /// block.
    pub end: Rva,
}

/// Finds every trailing run whose layout the unwinder depends on.
///
/// Meant for a freshly decoded function: the answer is expressed in the
/// addresses of the input image, so a block whose instructions no longer carry
/// one is skipped rather than guessed at.
pub fn epilogues(function: &Function) -> Vec<Epilogue> {
    let mut factory = InstructionInfoFactory::new();
    let mut found = Vec::new();

    for block in &function.blocks {
        let Some(last) = block.instructions.len().checked_sub(1) else {
            continue;
        };

        let mut start = last;
        while start > 0 && changes_stack_pointer(&mut factory, block.instructions[start - 1].raw())
        {
            start -= 1;
        }

        // A run of one is just the terminator, and freezing that buys nothing
        if start == last {
            continue;
        }
        let Some(begin) = block.instructions[start].rva() else {
            continue;
        };

        found.push(Epilogue {
            begin,
            end: block.end,
        });
    }

    join(found)
}

/// Merges ranges that meet, so that a split epilogue is one range.
fn join(mut ranges: Vec<Epilogue>) -> Vec<Epilogue> {
    ranges.sort();

    let mut joined: Vec<Epilogue> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match joined.last_mut() {
            Some(previous) if previous.end >= range.begin => {
                previous.end = previous.end.max(range.end);
            }
            _ => joined.push(range),
        }
    }
    joined
}

/// Whether the instruction leaves `RSP` holding something other than what it
/// held before.
///
/// A `call` writes `RSP` and is still excluded: the callee pops the return
/// address, so the instruction after the call sees the stack pointer the unwind
/// codes describe.
fn changes_stack_pointer(
    factory: &mut InstructionInfoFactory,
    instruction: &RawInstruction,
) -> bool {
    if matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    ) {
        return false;
    }
    factory
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used| used.register().full_register() == Register::RSP && writes(used.access()))
}

/// Whether the access can leave the register holding something new.
///
/// A conditional write counts: "might have moved the stack pointer" is the
/// answer that keeps the range wide enough.
fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions};
    use vmp_ir::{BasicBlock, BlockId, CompileStage, Instruction, Terminator};
    use vmp_types::Architecture;

    use super::*;

    fn decode_run(rva: u32, bytes: &[u8]) -> Vec<Instruction> {
        decode_run_at(64, rva, bytes)
    }

    fn decode_run_at(bitness: u32, rva: u32, bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(bitness, bytes, u64::from(rva), DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let raw = decoder.decode();
            let offset = usize::try_from(raw.ip() - u64::from(rva)).expect("run fits in memory");
            let at = u32::try_from(raw.ip()).expect("test addresses are small");
            instructions.push(Instruction::decoded(
                Rva(at),
                raw,
                &bytes[offset..offset + raw.len()],
            ));
        }
        instructions
    }

    fn block(id: u32, rva: u32, bytes: &[u8], terminator: Terminator) -> BasicBlock {
        let instructions = decode_run(rva, bytes);
        let end = instructions
            .last()
            .and_then(|last| last.next_rva())
            .unwrap_or(Rva(rva));
        BasicBlock {
            id: BlockId(id),
            start: Rva(rva),
            end,
            instructions,
            terminator,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    fn function(blocks: Vec<BasicBlock>) -> Function {
        let entry = blocks.first().expect("at least one block").start;
        let entry_block = blocks.first().expect("at least one block").id;
        Function {
            architecture: Architecture::X64,
            entry,
            blocks,
            entry_block,
            unwind: None,
            issues: Vec::new(),
            stage: CompileStage::Decoded,
        }
    }

    fn single(bytes: &[u8], terminator: Terminator) -> Vec<Epilogue> {
        epilogues(&function(vec![block(0, 0x1000, bytes, terminator)]))
    }

    /// The same shape as [`single`], decoded and reported as 32-bit code.
    fn single_x86(bytes: &[u8], terminator: Terminator) -> Vec<Epilogue> {
        let instructions = decode_run_at(32, 0x1000, bytes);
        let end = instructions
            .last()
            .and_then(|last| last.next_rva())
            .unwrap_or(Rva(0x1000));
        let mut function = function(vec![BasicBlock {
            id: BlockId(0),
            start: Rva(0x1000),
            end,
            instructions,
            terminator,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }]);
        function.architecture = Architecture::X86;
        epilogues(&function)
    }

    #[test]
    fn the_canonical_epilogue_is_covered_from_the_stack_adjustment() {
        // mov eax, 1 / add rsp, 0x20 / pop rbx / ret
        let found = single(
            &[
                0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
            ],
            Terminator::Return,
        );
        assert_eq!(
            found,
            vec![Epilogue {
                // `add rsp, 0x20`, not the `mov` before it
                begin: Rva(0x1005),
                end: Rva(0x100b),
            }]
        );
    }

    #[test]
    fn a_frame_pointer_epilogue_is_recognised_through_lea() {
        // lea rsp, [rbp-0x10] / pop rbp / ret
        let found = single(&[0x48, 0x8d, 0x65, 0xf0, 0x5d, 0xc3], Terminator::Return);
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1006),
            }]
        );
    }

    #[test]
    fn a_lone_ret_is_left_alone() {
        // mov eax, 1 / ret — nothing has touched the stack, so the full unwind
        // codes stay correct right up to the `ret`
        let found = single(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3], Terminator::Return);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_import_tail_call_is_covered_although_the_jump_leaves_rsp_alone() {
        // pop rbx / jmp qword ptr [rip+0x2000]
        let found = single(
            &[0x5b, 0xff, 0x25, 0x00, 0x20, 0x00, 0x00],
            Terminator::ImportTailCall,
        );
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1007),
            }],
            "the pop moved the stack, so the jump must not be separated from it"
        );
    }

    #[test]
    fn a_stack_adjustment_before_an_internal_jump_is_covered_too() {
        // add rsp, 0x20 / jmp +0 — a shared epilogue reached by a branch still
        // leaves RSP where the unwind codes do not expect it
        let found = single(&[0x48, 0x83, 0xc4, 0x20, 0xeb, 0x00], Terminator::Jump);
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1006),
            }]
        );
    }

    #[test]
    fn an_ordinary_block_reports_nothing() {
        // cmp eax, ebx / jne +0
        let found = single(&[0x39, 0xd8, 0x75, 0x00], Terminator::Conditional);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_run_stops_at_the_first_instruction_that_leaves_rsp_alone() {
        // pop rbx / mov eax, 1 / pop rbp / ret — the `mov` breaks the run, so
        // only the tail from `pop rbp` is reported
        let found = single(
            &[0x5b, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3],
            Terminator::Return,
        );
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1006),
                end: Rva(0x1008),
            }]
        );
    }

    #[test]
    fn every_block_of_a_function_is_examined() {
        let found = epilogues(&function(vec![
            block(
                0,
                0x1000,
                &[0x39, 0xd8, 0x75, 0x00],
                Terminator::Conditional,
            ),
            block(
                1,
                0x1004,
                &[0x48, 0x83, 0xc4, 0x20, 0xc3],
                Terminator::Return,
            ),
            block(
                2,
                0x1010,
                &[0x48, 0x83, 0xc4, 0x10, 0xc3],
                Terminator::Return,
            ),
        ]));
        assert_eq!(
            found,
            vec![
                Epilogue {
                    begin: Rva(0x1004),
                    end: Rva(0x1009),
                },
                Epilogue {
                    begin: Rva(0x1010),
                    end: Rva(0x1015),
                },
            ]
        );
    }

    /// x86 has no `.pdata` and so no scanning unwinder, but the register file
    /// it decodes into is narrower and the answer must not silently change with
    /// it: iced reports `ESP` where the 64-bit decoder reports `RSP`.
    #[test]
    fn the_narrow_stack_pointer_is_recognised_too() {
        // add esp, 0x20 / pop ebx / ret
        let found = single_x86(&[0x83, 0xc4, 0x20, 0x5b, 0xc3], Terminator::Return);
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1005),
            }]
        );
    }

    #[test]
    fn a_call_does_not_start_a_run() {
        // call +0 / jmp +0 — the callee pops the return address back off, so
        // RSP still agrees with the unwind codes at the jump
        let found = single(
            &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x00],
            Terminator::Jump,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_epilogue_split_by_a_branch_target_is_reported_as_one_range() {
        // A shared epilogue: something branches to 0x1005, which splits
        //   add rsp, 0x20 / pop rbx | pop rbp / ret
        // Reported separately, the address 0x1005 would be interior to neither
        // range, and an insertion there would land in the middle of the run.
        let found = epilogues(&function(vec![
            block(
                0,
                0x1000,
                &[0x48, 0x83, 0xc4, 0x20, 0x5b],
                Terminator::FallThrough,
            ),
            block(1, 0x1005, &[0x5d, 0xc3], Terminator::Return),
        ]));
        assert_eq!(
            found,
            vec![Epilogue {
                begin: Rva(0x1000),
                end: Rva(0x1007),
            }]
        );
    }
}
