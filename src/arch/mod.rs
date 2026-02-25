pub mod aarch64;
pub mod aarch64_patch;
pub mod arm32;
pub mod arm32_patch;
pub mod x86;
pub mod x86_patch;

use crate::types::{Arch, DecodedInstr};

/// Decode instructions from a code section for the given arch.
pub fn decode_text(
    data: &[u8],
    offset: u64,
    vaddr: u64,
    size: u64,
    arch: Arch,
) -> Vec<DecodedInstr> {
    match arch {
        Arch::X86_64 => {
            x86::decode_text_x86(data, offset, vaddr, size)
        }
        Arch::Aarch64 => {
            aarch64::decode_text_aarch64(
                data, offset, vaddr, size,
            )
        }
        Arch::Arm32 => {
            arm32::decode_text_arm32(
                data, offset, vaddr, size,
            )
        }
        Arch::X86_32 => {
            x86::decode_text_x86(data, offset, vaddr, size)
        }
    }
}

/// Get the padding check function for a given architecture.
pub fn padding_fn(arch: Arch) -> fn(u8) -> bool {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            x86_patch::is_padding_x86
        }
        Arch::Aarch64 => aarch64_patch::is_padding_aarch64,
        Arch::Arm32 => arm32_patch::is_padding_arm32,
    }
}
