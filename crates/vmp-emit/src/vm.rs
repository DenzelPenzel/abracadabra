//! Places a captured encrypted scalar instance and translates its absolute fields to PE RVAs

use thiserror::Error;
use vmp_pe::{BaseRelocations, Fixup, FixupKind, NewSection, PeError, PeImage, RuntimeFunction};
use vmp_types::{Architecture, ImageBase, Rva};
use vmp_vm::{
    instance::{InstanceError, NativeInstance},
    logical::LogicalInstruction,
};

#[derive(Debug, Error)]
pub enum VmPlacementError {
    #[error("PE image base must be aligned to 64 KiB")]
    ImageBaseAlignment,
    #[error("VM placement virtual address overflows")]
    AddressOverflow,
    #[error("VM placement exceeds the PE RVA range")]
    RvaOverflow,
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Relocations(#[from] PeError),
}

#[derive(Debug, Error)]
pub enum VmEmbeddingError {
    #[error(
        "leaf source must match executable PE bytes, end in RET and have no existing runtime entry"
    )]
    LeafSource,
    #[error("VM section embedding requires an x64 PE")]
    Architecture,
    #[error(transparent)]
    Pe(#[from] PeError),
    #[error(transparent)]
    Placement(#[from] VmPlacementError),
}

/// Serialized PE with an appended VM that is not connected to its original entry point
pub struct VmPeArtifact {
    image: PeImage,
    placement: VmPlacement,
}

impl VmPeArtifact {
    pub fn bytes(&self) -> &[u8] {
        self.image.bytes()
    }

    pub fn placement(&self) -> &VmPlacement {
        &self.placement
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.image.into_bytes()
    }
}

/// Appends one encrypted scalar instance and merges its fixups into a separate data section
///
/// Returns no artifact if either append fails. The input entry point, native code and
/// existing unwind records remain unchanged; invoking the new gate is the caller's job
/// No Windows unwind metadata is supplied for the gate, so this is not protected output
pub fn append_vm_instance(
    data: Vec<u8>,
    bodies: &[LogicalInstruction<'_>],
    variant: u8,
) -> Result<VmPeArtifact, VmEmbeddingError> {
    append_instance(data, bodies, variant, false)
}

/// Appends an encrypted scalar leaf with persisted body exception metadata
///
/// The native leaf must remain at its original VA; entry/exit gates are not unwindable
/// This does not redirect the original entry or enable CLI virtualization
pub fn append_leaf_vm_instance(
    data: Vec<u8>,
    bodies: &[LogicalInstruction<'_>],
    variant: u8,
) -> Result<VmPeArtifact, VmEmbeddingError> {
    append_instance(data, bodies, variant, true)
}

fn append_instance(
    data: Vec<u8>,
    bodies: &[LogicalInstruction<'_>],
    variant: u8,
    leaf: bool,
) -> Result<VmPeArtifact, VmEmbeddingError> {
    let mut image = PeImage::from_bytes(data)?;
    match image.pe().architecture {
        Architecture::X64 => {}
        Architecture::X86 => return Err(VmEmbeddingError::Architecture),
    }
    if leaf {
        for body in bodies {
            let source = body.source();
            let source_rva = source.rva().ok_or(VmEmbeddingError::LeafSource)?;
            let encoding =
                image
                    .pe()
                    .mapped_range(image.bytes(), source_rva, source.raw().len() as u32)?;
            let decoded = iced_x86::Decoder::with_ip(
                64,
                encoding,
                source.raw().ip(),
                iced_x86::DecoderOptions::NONE,
            )
            .decode();
            if source_rva
                .to_va(image.pe().optional.image_base)
                .map(|a| a.0)
                != Some(source.raw().ip())
                || encoding != source.bytes()
                || decoded.is_invalid()
                || decoded != *source.raw()
                || !image.pe().sections.iter().any(|s| {
                    s.characteristics & 0x2000_0000 != 0
                        && source_rva.get() >= s.virtual_address.get()
                        && u64::from(source_rva.get()) + source.raw().len() as u64
                            <= u64::from(s.virtual_address.get()) + u64::from(s.virtual_size)
                })
            {
                return Err(VmEmbeddingError::LeafSource);
            }
            if image.pe().exception_table.as_ref().is_some_and(|table| {
                table.entries().iter().any(|entry| {
                    u64::from(source_rva.get()) < u64::from(entry.function.end.get())
                        && u64::from(source_rva.get()) + source.raw().len() as u64
                            > u64::from(entry.function.begin.get())
                })
            }) {
                return Err(VmEmbeddingError::LeafSource);
            }
        }
        let last = bodies.last().ok_or(VmEmbeddingError::LeafSource)?.source();
        let ret = last
            .rva()
            .and_then(|r| r.checked_add(last.raw().len() as u32))
            .ok_or(VmEmbeddingError::LeafSource)?;
        if image.pe().mapped_range(image.bytes(), ret, 1)? != [0xc3] {
            return Err(VmEmbeddingError::LeafSource);
        }
    }
    let rva = image.next_section_rva()?;
    let placement = VmPlacement::build(bodies, image.pe().optional.image_base, rva, variant, leaf)?;
    image.add_section(NewSection {
        name: ".vmpvm",
        data: placement.image(),
        characteristics: 0x6000_0020,
    })?;
    image.extend_base_relocations(".vmprel", placement.relocations().fixups())?;
    if leaf {
        image.extend_exception_references(".vmpexc", &placement.functions)?;
    }
    Ok(VmPeArtifact { image, placement })
}

/// Coupled bytes, entry RVA and base relocations for one placed scalar VM
#[derive(Debug)]
pub struct VmPlacement {
    image: Vec<u8>,
    functions: Vec<RuntimeFunction>,
    rva: Rva,
    entry: Rva,
    relocations: BaseRelocations,
}

impl VmPlacement {
    /// Generates at the final placement before translating instance-owned pointer positions
    ///
    /// `rva` locates the whole instance, not its entry point. The PE image base and any
    /// loader replacement base must be 64-KiB aligned so byte-key inputs survive rebasing
    /// The caller still owns section permissions, function links, unwind and publication
    pub fn generate(
        bodies: &[LogicalInstruction<'_>],
        image_base: ImageBase,
        rva: Rva,
        variant: u8,
    ) -> Result<Self, VmPlacementError> {
        Self::build(bodies, image_base, rva, variant, false)
    }

    fn build(
        bodies: &[LogicalInstruction<'_>],
        image_base: ImageBase,
        rva: Rva,
        variant: u8,
        leaf: bool,
    ) -> Result<Self, VmPlacementError> {
        if image_base.0 & 0xffff != 0 {
            return Err(VmPlacementError::ImageBaseAlignment);
        }
        let address = rva
            .to_va(image_base)
            .ok_or(VmPlacementError::AddressOverflow)?;
        let instance = if leaf {
            NativeInstance::generate_leaf_unwind(bodies, address, variant)?
        } else {
            NativeInstance::generate_encrypted(bodies, address, variant)?
        };
        let at = |offset: usize| {
            let offset = u32::try_from(offset).map_err(|_| VmPlacementError::RvaOverflow)?;
            rva.checked_add(offset).ok_or(VmPlacementError::RvaOverflow)
        };
        at(instance.image().len())?;
        let entry = at(instance.entry_offset())?;
        let mut relocations = BaseRelocations::default();
        for offset in instance.absolute_address_offsets() {
            // Insert the place for replacement
            relocations.insert(Fixup {
                rva: at(offset)?,
                kind: FixupKind::Dir64,
            })?;
        }
        let mut image = instance.image().to_vec();
        let mut functions = Vec::new();
        if let Some(unwind) = instance.unwind() {
            while image.len() % 4 != 0 {
                image.push(0);
            }
            for (index, range) in unwind.processor.iter().enumerate() {
                let unwind_info = at(image.len())?;
                image.extend_from_slice(&unwind.codes[index]);
                let handler = if index == 1 {
                    unwind.shifted_handler
                } else {
                    unwind.handler.start
                };
                image.extend_from_slice(&at(handler)?.get().to_le_bytes());
                image.extend_from_slice(&0u32.to_le_bytes());
                functions.push(RuntimeFunction {
                    begin: at(range.start)?,
                    end: at(range.end)?,
                    unwind_info,
                });
            }
            let unwind_info = at(image.len())?;
            image.extend_from_slice(&unwind.entry_codes);
            functions.push(RuntimeFunction {
                begin: at(unwind.entry.start)?,
                end: at(unwind.entry.end)?,
                unwind_info,
            });
            for (range, codes) in &unwind.exit {
                let unwind_info = at(image.len())?;
                image.extend_from_slice(codes);
                functions.push(RuntimeFunction {
                    begin: at(range.start)?,
                    end: at(range.end)?,
                    unwind_info,
                });
            }
            let unwind_info = at(image.len())?;
            // Keep the empty code-array address within the mapped section
            image.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
            for range in [
                unwind.empty_ret..unwind.empty_ret + 1,
                unwind.handler.clone(),
            ] {
                functions.push(RuntimeFunction {
                    begin: at(range.start)?,
                    end: at(range.end)?,
                    unwind_info,
                });
            }
        }
        at(image.len())?;
        Ok(Self {
            image,
            functions,
            rva,
            entry,
            relocations,
        })
    }

    pub fn image(&self) -> &[u8] {
        &self.image
    }

    pub fn rva(&self) -> Rva {
        self.rva
    }

    pub fn entry_rva(&self) -> Rva {
        self.entry
    }

    pub fn relocations(&self) -> &BaseRelocations {
        &self.relocations
    }
}
