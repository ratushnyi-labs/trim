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

/// Detect MIPS endianness from ELF EI_DATA byte.
fn detect_mips_endian(data: &[u8]) -> bool {
    if data.len() > 5
        && data[0] == 0x7F
        && data[1] == b'E'
    {
        return data[5] == 2;
    }
    true
}
