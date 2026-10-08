//! Architecture-specific instruction decoders and patch modules.
//!
//! Each architecture has a decoder module (e.g., `x86`, `aarch64`) that
//! extracts call/branch targets and flow types from raw instruction bytes,
//! and a patch module (e.g., `x86_patch`, `aarch64_patch`) that rewrites
//! branch displacements after dead code compaction shifts addresses.
//! Supported architectures: x86-64/32, AArch64, ARM32, RISC-V 64/32,
//! MIPS 64/32, s390x, and LoongArch64.

pub mod aarch64;
pub mod aarch64_patch;
pub mod arm32;
pub mod arm32_patch;
pub mod loongarch;
pub mod loongarch_patch;
pub mod mips;
pub mod mips_patch;
pub mod riscv;
pub mod riscv_patch;
pub mod s390x;
pub mod s390x_patch;
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
        Arch::X86_64 | Arch::X86_32 => {
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
        Arch::RiscV64 | Arch::RiscV32 => {
            riscv::decode_text_riscv(
                data, offset, vaddr, size,
            )
        }
        Arch::Mips32 | Arch::Mips64 => {
            let big_endian = detect_mips_endian(data);
            mips::decode_text_mips(
                data, offset, vaddr, size, big_endian,
            )
        }
        Arch::S390x => {
            s390x::decode_text_s390x(
                data, offset, vaddr, size,
            )
        }
        Arch::LoongArch64 => {
            loongarch::decode_text_loongarch(
                data, offset, vaddr, size,
            )
        }
    }
}

/// The file bytes of a code section, `[offset, offset + size)` clipped
/// to the end of `data`. Empty when the section starts past the end of
/// the file or its offset does not fit a `usize` (crafted or truncated
/// input), so a decoder never slices outside `data`.
pub fn section_bytes(data: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = match usize::try_from(offset) {
        Ok(s) => s,
        Err(_) => return &[],
    };
    let len = usize::try_from(size).unwrap_or(usize::MAX);
    let end = start.saturating_add(len).min(data.len());
    data.get(start..end).unwrap_or(&[])
}

/// Get the padding check function for a given architecture.
pub fn padding_fn(arch: Arch) -> fn(u8) -> bool {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            x86_patch::is_padding_x86
        }
        Arch::Aarch64 => aarch64_patch::is_padding_aarch64,
        Arch::Arm32 => arm32_patch::is_padding_arm32,
        Arch::RiscV64 | Arch::RiscV32 => {
            riscv_patch::is_padding_riscv
        }
        Arch::Mips32 | Arch::Mips64 => {
            mips_patch::is_padding_mips
        }
        Arch::S390x => s390x_patch::is_padding_s390x,
        Arch::LoongArch64 => {
            loongarch_patch::is_padding_loongarch
        }
    }
}

/// Minimum instruction alignment for a given architecture.
/// Intervals must be multiples of this to avoid misaligning code.
pub fn instr_align(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 | Arch::X86_32 => 1,
        Arch::Aarch64 => 4,
        Arch::Arm32 => 4,
        Arch::RiscV64 | Arch::RiscV32 => 2,
        Arch::Mips32 | Arch::Mips64 => 4,
        Arch::S390x => 2,
        Arch::LoongArch64 => 4,
    }
}

/// Detect MIPS endianness from ELF EI_DATA byte. Returns true for big-endian.
fn detect_mips_endian(data: &[u8]) -> bool {
    if data.len() > 5
        && data[0] == 0x7F
        && data[1] == b'E'
    {
        return data[5] == 2;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every architecture `decode_text` dispatches on.
    const ARCHES: &[Arch] = &[
        Arch::X86_64, Arch::X86_32, Arch::Aarch64, Arch::Arm32,
        Arch::RiscV64, Arch::RiscV32, Arch::Mips32, Arch::Mips64,
        Arch::S390x, Arch::LoongArch64,
    ];

    /// A section range is clipped to the file; one starting past the end
    /// of the file (or beyond any usize) yields no bytes.
    #[test]
    fn section_bytes_stays_inside_the_file() {
        let data = [0x90u8; 64];
        assert_eq!(section_bytes(&data, 60, 16).len(), 4);
        assert_eq!(section_bytes(&data, 8, u64::MAX).len(), 56);
        assert!(section_bytes(&data, 64, 16).is_empty());
        assert!(section_bytes(&data, 65, 16).is_empty());
        assert!(section_bytes(&data, u64::MAX, u64::MAX).is_empty());
    }

    /// No decoder panics on a code section that starts past the end of
    /// the file or whose end overflows; each decodes nothing there.
    #[test]
    fn decoders_never_slice_outside_the_file() {
        let data = [0u8; 64];
        for &arch in ARCHES {
            assert!(decode_text(&data, 65, 0x1000, 16, arch).is_empty());
            assert!(decode_text(&data, 64, 0x1000, 16, arch).is_empty());
            let far = decode_text(&data, u64::MAX, 0x1000, u64::MAX, arch);
            assert!(far.is_empty(), "{:?}", arch);
            assert!(!decode_text(&data, 32, 0x1000, u64::MAX, arch).is_empty());
        }
    }
}
