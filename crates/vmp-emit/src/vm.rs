//! Places a captured encrypted scalar instance and translates its absolute fields to PE RVAs

use thiserror::Error;
use vmp_pe::{BaseRelocations, Fixup, FixupKind, NewSection, PeError, PeImage};
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
    let mut image = PeImage::from_bytes(data)?;
    match image.pe().architecture {
        Architecture::X64 => {}
        Architecture::X86 => return Err(VmEmbeddingError::Architecture),
    }
    let rva = image.next_section_rva()?;
    let placement = VmPlacement::generate(bodies, image.pe().optional.image_base, rva, variant)?;
    image.add_section(NewSection {
        name: ".vmpvm",
        data: placement.image(),
        characteristics: 0x6000_0020,
    })?;
    image.extend_base_relocations(".vmprel", placement.relocations().fixups())?;
    Ok(VmPeArtifact { image, placement })
}

/// Coupled bytes, entry RVA and base relocations for one placed scalar VM
#[derive(Debug)]
pub struct VmPlacement {
    instance: NativeInstance,
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
        if image_base.0 & 0xffff != 0 {
            return Err(VmPlacementError::ImageBaseAlignment);
        }
        let address = rva
            .to_va(image_base)
            .ok_or(VmPlacementError::AddressOverflow)?;
        let instance = NativeInstance::generate_encrypted(bodies, address, variant)?;
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
        Ok(Self {
            instance,
            rva,
            entry,
            relocations,
        })
    }

    pub fn image(&self) -> &[u8] {
        self.instance.image()
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
