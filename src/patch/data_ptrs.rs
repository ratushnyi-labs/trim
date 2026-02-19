use crate::patch::relocs::{shift_at, total_shift};
use crate::types::Section;

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
) {
    let is64 = data.len() > 4 && data[4] == 2;
    let psz: usize = if is64 { 8 } else { 4 };
    for sec in sections {
        let name = sec.name.as_str();
        let use_total = PTR_SECTIONS.contains(&name);
        let use_text = MIXED_SECTIONS.contains(&name);
        if !use_total && !use_text {
            continue;
        }
        let end = (sec.offset as usize + sec.size as usize)
            .min(data.len());
        let mut i = sec.offset as usize;
        while i + psz <= end {
            let val = read_ptr(data, i, is64);
            let shift = if use_total {
                total_shift(val, intervals, ts, te)
            } else if ts <= val && val < te {
                shift_at(val, intervals)
            } else {
                0
            };
            if shift > 0 {
                write_ptr(data, i, val - shift, is64);
            }
            i += psz;
        }
    }
}

fn read_ptr(data: &[u8], i: usize, is64: bool) -> u64 {
    if is64 {
        u64::from_le_bytes(
            data[i..i + 8].try_into().unwrap_or([0; 8]),
        )
    } else {
        u32::from_le_bytes(
            data[i..i + 4].try_into().unwrap_or([0; 4]),
        ) as u64
    }
}

fn write_ptr(data: &mut [u8], i: usize, val: u64, is64: bool) {
    if is64 {
        data[i..i + 8].copy_from_slice(&val.to_le_bytes());
    } else {
        data[i..i + 4]
            .copy_from_slice(&(val as u32).to_le_bytes());
    }
}
