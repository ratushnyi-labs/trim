//! Data pointer patching in non-code sections.
//!
//! Scans GOT, init/fini arrays, and read-only/data sections for absolute
//! pointers into .text, then adjusts them according to the compaction
//! shift map so they still point to the correct (shifted) addresses.

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
