use crate::types::{vaddr_to_offset, Section};
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
