//! The linear sweep and its worklist.
//!
//! This is a port of `BaseFunction::ReadFromFile` (`core/processors.cc:1707`)
//! and `BaseFunction::GetNextAddress` (`core/processors.cc:1567`), including
//! the speculative sub-disassembly that classifies an ambiguous `jmp` as either
//! an in-function branch or a tail call.
//!
//! Two things are added on purpose. Traversal runs against a shared instruction
//! budget, because a fail-closed tool must not be made to spin on a hostile
//! input; and an unresolved indirect jump is recorded as an issue instead of
//! silently truncating the path.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ops::Bound;

use vmp_ir::{DecodeIssue, Instruction};
use vmp_types::Rva;

use crate::decode::{self, FlowKind, IssueKind, LinkKind};
use crate::image::Image;
use crate::refs;

/// One decoded instruction plus its traversal state.
pub(crate) struct Command {
    pub insn: Instruction,
    pub flow: FlowKind,
    pub link: Option<Link>,
}

impl Command {
    pub(crate) fn next_rva(&self) -> Option<Rva> {
        self.insn.next_rva()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link {
    pub kind: LinkKind,
    pub to: Rva,
}

#[derive(Debug, Clone, Copy)]
struct LinkEntry {
    from: Rva,
    to: Rva,
    kind: LinkKind,
    parsed: bool,
}

/// The result of sweeping one function.
pub(crate) struct SweepResult {
    pub commands: BTreeMap<Rva, Command>,
    pub issues: Vec<DecodeIssue>,
}

pub(crate) struct Sweep<'img, 'ctx> {
    image: Image<'img>,
    entry: Rva,
    commands: BTreeMap<Rva, Command>,
    links: Vec<LinkEntry>,
    issues: Vec<DecodeIssue>,
    budget: &'ctx Cell<usize>,
    /// The entry of the function this probe was spawned from, when this
    /// traversal is a probe. A probe follows every deferred `jmp` directly,
    /// which is what keeps probe recursion one level deep — exactly the effect
    /// of the `parent()` checks in the original.
    probe_of: Option<Rva>,
}

impl<'img, 'ctx> Sweep<'img, 'ctx> {
    pub(crate) fn new(
        image: Image<'img>,
        entry: Rva,
        budget: &'ctx Cell<usize>,
        probe_of: Option<Rva>,
    ) -> Sweep<'img, 'ctx> {
        Sweep {
            image,
            entry,
            commands: BTreeMap::new(),
            links: Vec::new(),
            issues: Vec::new(),
            budget,
            probe_of,
        }
    }

    pub(crate) fn finish(self) -> SweepResult {
        SweepResult {
            commands: self.commands,
            issues: self.issues,
        }
    }

    pub(crate) fn run(&mut self) {
        let mut address = self.entry;
        // `parsed_address` in the original: the address of the next command
        // that is already decoded, which stops the linear walk from decoding it
        // a second time
        let mut parsed_address: Option<Rva> = None;

        loop {
            let within_unparsed = parsed_address.is_none_or(|limit| address < limit);
            let outcome = if within_unparsed && self.image.is_executable(address) {
                self.parse_command(address)
            } else {
                Outcome::Stop
            };

            match outcome {
                Outcome::Continue(next) => {
                    address = next;
                    continue;
                }
                Outcome::Exhausted => return,
                Outcome::Stop => {}
            }

            let Some(next) = self.next_address() else {
                return;
            };
            address = next;
            parsed_address = self.command_after(address);
        }
    }

    /// Decodes one instruction and records its link.
    fn parse_command(&mut self, rva: Rva) -> Outcome {
        if self.budget.get() == 0 {
            return Outcome::Exhausted;
        }

        let Some(bytes) = self.image.bytes_from(rva) else {
            return Outcome::Stop;
        };
        let Some(decoded) = decode::decode_at(self.image.bitness(), bytes, rva) else {
            return Outcome::Stop;
        };
        let encoding = &bytes[..decoded.len];
        if decode::is_zero_padding(&decoded.raw, encoding) {
            // Alignment padding read as `add byte ptr [rax], al` is not code
            return Outcome::Stop;
        }
        self.budget.set(self.budget.get() - 1);

        let class = decode::classify(&self.image, &decoded.raw);
        let mut insn = Instruction::decoded(rva, decoded.raw, encoding);
        refs::bind(&self.image, &mut insn, &decoded.offsets, &mut self.issues);

        if let Some(issue) = class.issue {
            self.issues.push(match issue {
                IssueKind::IndirectJump => DecodeIssue::IndirectJump { rva },
                IssueKind::InvalidOpcode => DecodeIssue::InvalidOpcode { rva },
                IssueKind::UnsupportedControlFlow => DecodeIssue::UnsupportedControlFlow { rva },
            });
        }
        if let Some((kind, to)) = class.link {
            self.links.push(LinkEntry {
                from: rva,
                to,
                kind,
                parsed: false,
            });
        }

        let next = insn.next_rva();
        self.commands.insert(
            rva,
            Command {
                insn,
                flow: class.flow,
                link: class.link.map(|(kind, to)| Link { kind, to }),
            },
        );

        if class.flow.is_end() || class.flow.is_breaked() {
            return Outcome::Stop;
        }
        match next {
            Some(next) => Outcome::Continue(next),
            None => Outcome::Stop,
        }
    }

    /// The worklist pop, in the four passes of the original.
    fn next_address(&mut self) -> Option<Rva> {
        // Pass 1: everything that can be decided without looking at the target
        for index in 0..self.links.len() {
            let link = self.links[index];
            if link.parsed || link.kind == LinkKind::Call {
                continue;
            }

            if self.command_containing(link.to).is_some() {
                self.links[index].parsed = true;
            } else if link.to < self.entry {
                // A probe may extend backwards as far as the function that
                // spawned it. A root function drops the link, exactly as the
                // original does; the edge survives as `External`, which is what
                // a tail call to a lower address really is
                self.links[index].parsed = true;
                if let Some(outer_entry) = self.probe_of {
                    if link.to > outer_entry {
                        self.entry = link.to;
                        return Some(link.to);
                    }
                }
            } else if link.kind == LinkKind::Jmp {
                // Follow a `jmp` right away only when `.pdata` says the target
                // belongs to the same function
                let same_function = self
                    .image
                    .runtime_function(link.from)
                    .is_some_and(|range| range.contains(link.to));
                if same_function {
                    self.links[index].parsed = true;
                    if self.accept(link) {
                        return Some(link.to);
                    }
                }
            } else {
                self.links[index].parsed = true;
                if self.accept(link) {
                    return Some(link.to);
                }
            }
        }

        // Pass 2: how far the conditional branches reach
        let mut max_address = self.entry;
        for link in &self.links {
            if link.kind == LinkKind::JmpWithFlag && link.to > max_address {
                max_address = link.to;
            }
        }

        // Pass 3: a deferred `jmp` that lands inside that reach is internal
        for index in 0..self.links.len() {
            let link = self.links[index];
            if link.parsed || link.kind != LinkKind::Jmp || link.to >= max_address {
                continue;
            }
            self.links[index].parsed = true;
            if self.accept(link) {
                return Some(link.to);
            }
        }

        // Pass 4: decide the rest by disassembling the target speculatively
        for index in 0..self.links.len() {
            let link = self.links[index];
            if link.parsed || link.kind != LinkKind::Jmp {
                continue;
            }
            if self.probe_of.is_some() || self.probe_says_internal(link) {
                self.links[index].parsed = true;
                if self.accept(link) {
                    return Some(link.to);
                }
            }
        }

        None
    }

    /// Whether a followed target is really executable.
    ///
    /// The original decodes nothing at a non-executable address and pops the
    /// next link; recording the issue here keeps that behaviour while naming
    /// the branch that caused it.
    fn accept(&mut self, link: LinkEntry) -> bool {
        if self.image.is_executable(link.to) {
            return true;
        }
        self.issues.push(DecodeIssue::TargetNotExecutable {
            rva: link.from,
            target: link.to,
        });
        false
    }

    /// Disassembles the target of an ambiguous `jmp` into a throwaway function
    /// and reports whether that code belongs to this one.
    ///
    /// This is `core/processors.cc:1638-1677`. The probe is accepted when it
    /// branches into code this function already decoded, when it loops back to
    /// an aligned forward target, when it conditionally returns to the
    /// instruction after our `jmp`, or when some instruction in it falls
    /// through into the target.
    fn probe_says_internal(&self, link: LinkEntry) -> bool {
        if !self.image.is_executable(link.to) {
            return false;
        }
        let Some(after_jmp) = self.commands.get(&link.from).and_then(Command::next_rva) else {
            return false;
        };
        let to = link.to;
        let is_forward_aligned = to > link.from && to.get() & 0x0f == 0;

        let mut probe = Sweep::new(self.image, to, self.budget, Some(self.entry));
        probe.run();

        for command in probe.commands.values() {
            if let Some(probe_link) = command.link {
                let branches = matches!(probe_link.kind, LinkKind::Jmp | LinkKind::JmpWithFlag);
                if branches
                    && (self.commands.contains_key(&probe_link.to)
                        || (is_forward_aligned && probe_link.to == to)
                        || (probe_link.kind == LinkKind::JmpWithFlag && probe_link.to == after_jmp))
                {
                    return true;
                }
            }
            if command.flow.is_data() || command.flow.is_end() || command.flow.is_breaked() {
                continue;
            }
            if command.next_rva() == Some(to) {
                return true;
            }
        }
        false
    }

    /// The decoded command whose encoding covers `rva`.
    fn command_containing(&self, rva: Rva) -> Option<&Command> {
        let (start, command) = self
            .commands
            .range((Bound::Unbounded, Bound::Included(rva)))
            .next_back()?;
        let end = start.checked_add(command.insn.len() as u32)?;
        (rva < end).then_some(command)
    }

    /// The address of the first decoded command strictly after `rva`.
    fn command_after(&self, rva: Rva) -> Option<Rva> {
        self.commands
            .range((Bound::Excluded(rva), Bound::Unbounded))
            .next()
            .map(|(address, _)| *address)
    }
}

/// What the linear walk does after one instruction.
enum Outcome {
    /// Keep decoding at this address.
    Continue(Rva),
    /// Stop the straight-line run and pop the worklist.
    Stop,
    /// The instruction budget ran out.
    Exhausted,
}
