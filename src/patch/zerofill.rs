use crate::analysis::cfg::DeadBlock;
use crate::types::{vaddr_to_offset, Arch, Section};
use std::collections::HashMap;

/// Zero-fill dead function bytes for compressibility.
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

/// Zero-fill dead blocks within live functions.
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

fn fill_byte(arch: Arch) -> u8 {
    match arch {
        Arch::X86_64 | Arch::X86_32 => 0xCC,
        Arch::Aarch64 | Arch::Arm32 => 0x00,
    }
}
