//! Data pointer patching in non-code sections.
//!
//! Scans GOT, init/fini arrays, and read-only/data sections for absolute
//! pointers into .text, then adjusts them according to the compaction
//! shift map so they still point to the correct (shifted) addresses.
//! `patch_slot_ptrs` instead patches only slots known from relocations.

use crate::patch::relocs::{shift_at, total_shift};
use crate::types::{Endian, Section};

/// Pointer-only section names (every entry is an address).
const PTR_SECTIONS: &[&str] = &[
    ".got",
    ".got.plt",
    ".init_array",
    ".fini_array",
    ".ctors",
    ".dtors",
];

/// Mixed-content sections (may contain non-pointer data).
const MIXED_SECTIONS: &[&str] = &[
    ".rodata",
    ".data",
    ".data.rel.ro",
];

/// Patch absolute pointers in data sections.
pub fn patch_data_ptrs(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    is64: bool,
    endian: Endian,
) {
    let psz: usize = if is64 { 8 } else { 4 };
    for sec in sections {
        let name = sec.name.as_str();
        let use_total = PTR_SECTIONS.contains(&name);
        let use_text = MIXED_SECTIONS.contains(&name);
        if !use_total && !use_text {
            continue;
        }
        patch_one_data_sec(
            data, sec, psz, is64, endian, intervals, ts, te,
            use_total,
        );
    }
}

/// An absolute 64-bit little-endian pointer slot known from relocation
/// data, not guessed from its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrSlot {
    /// Vaddr of the slot.
    pub location: u64,
    /// File offset of the slot.
    pub offset: usize,
    /// Address the slot holds in place.
    pub target: u64,
}

/// Patch absolute pointers exactly: re-point the in-place value of each
/// of `slots` that still holds its target, and nothing else. For images
/// whose every absolute pointer is a known slot (a position-independent
/// image's RELATIVE relocations), unlike `patch_data_ptrs`, which also
/// rewrites any pointer-sized value of a mixed data section that merely
/// looks like a .text address (constants, tables, metadata).
/// Returns the number of slots rewritten.
pub fn patch_slot_ptrs(
    data: &mut [u8],
    slots: &[PtrSlot],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) -> usize {
    let mut rewritten = 0;
    for s in slots {
        let shift = total_shift(s.target, intervals, ts, te);
        let word = s.offset.checked_add(8).and_then(|e| data.get_mut(s.offset..e));
        let Some(word) = word else { continue };
        let held = u64::from_le_bytes([
            word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
        ]);
        if shift > 0 && held == s.target {
            word.copy_from_slice(&(s.target - shift).to_le_bytes());
            rewritten += 1;
        }
    }
    rewritten
}

/// Scan a single data section and patch pointer-sized values that shifted.
fn patch_one_data_sec(
    data: &mut [u8],
    sec: &Section,
    psz: usize,
    is64: bool,
    endian: Endian,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    use_total: bool,
) {
    let end = (sec.offset as usize + sec.size as usize)
        .min(data.len());
    let mut i = sec.offset as usize;
    while i + psz <= end {
        let val = crate::types::read_ptr(data, i, is64, endian);
        let shift = if use_total {
            total_shift(val, intervals, ts, te)
        } else if ts <= val && val < te {
            shift_at(val, intervals)
        } else {
            0
        };
        if shift > 0 {
            crate::types::write_ptr(
                data,
                i,
                val - shift,
                is64,
                endian,
            );
        }
        i += psz;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only listed slots still holding their target are re-pointed; a
    /// look-alike value elsewhere keeps its bytes.
    #[test]
    fn patches_only_listed_slots() {
        let ivs = [(0x1100u64, 0x2180u64)];
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(&0x2200u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x2200u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x5000u64.to_le_bytes());
        let slots = [
            PtrSlot { location: 0x3000, offset: 0, target: 0x2200 },
            PtrSlot { location: 0x3010, offset: 16, target: 0x2300 },
        ];
        assert_eq!(patch_slot_ptrs(&mut data, &slots, &ivs, 0x1000, 0x3000), 1);
        assert_eq!(data[0..8], (0x2200u64 - 0x1080).to_le_bytes());
        assert_eq!(data[8..16], 0x2200u64.to_le_bytes());
        assert_eq!(data[16..24], 0x5000u64.to_le_bytes());
    }
}
