//! Zero-fill dead code regions.
//!
//! When physical compaction is not possible (e.g. no .text bounds),
//! dead function bodies and dead basic blocks are overwritten with
//! zeros (or arch-specific trap bytes) to improve compressibility
//! and make dead regions easily identifiable.

use crate::analysis::cfg::DeadBlock;
use crate::types::{vaddr_to_offset, Arch, Section};
use std::collections::HashMap;

/// Zero-fill dead function bytes with 0x00 for compressibility.
/// Returns (count, total_bytes).
pub fn zero_fill(
    data: &mut [u8],
    dead: &HashMap<String, (u64, u64)>,
    sections: &[Section],
) -> (usize, u64) {
    let mut count = 0;
    let mut total_bytes = 0u64;
    for (_, &(addr, size)) in dead {
        if let Some(off) = vaddr_to_offset(addr, sections) {
            let off = off as usize;
            let sz = size as usize;
            if off + sz <= data.len() {
                data[off..off + sz].fill(0x00);
                count += 1;
                total_bytes += size;
            }
        }
    }
    (count, total_bytes)
}

/// Zero-fill dead basic blocks within live functions.
/// Uses arch-specific fill byte (e.g. 0xCC for x86 INT3).
/// Returns (count, total_bytes).
pub fn zero_fill_blocks(
    data: &mut [u8],
    dead_blocks: &[DeadBlock],
    sections: &[Section],
    arch: Arch,
) -> (usize, u64) {
    let fill = fill_byte(arch);
    let mut count = 0;
    let mut total_bytes = 0u64;
    for db in dead_blocks {
        if let Some(off) = vaddr_to_offset(db.addr, sections) {
            let off = off as usize;
            let sz = db.size as usize;
            if off + sz <= data.len() {
                data[off..off + sz].fill(fill);
                count += 1;
                total_bytes += db.size;
            }
        }
    }
    (count, total_bytes)
}

/// Return the arch-specific fill byte: 0xCC (INT3) for x86, 0x00 otherwise.
fn fill_byte(arch: Arch) -> u8 {
    match arch {
        Arch::X86_64 | Arch::X86_32 => 0xCC,
        Arch::Aarch64
        | Arch::Arm32
        | Arch::RiscV64
        | Arch::RiscV32
        | Arch::Mips32
        | Arch::Mips64
        | Arch::S390x
        | Arch::LoongArch64 => 0x00,
    }
}
