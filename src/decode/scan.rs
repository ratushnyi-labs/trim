//! Data section scanning for embedded function pointers.
//!
//! Scans data sections (.rodata, .got, .init_array, etc.) for pointer-sized
//! values that reference known function addresses or fall within the .text
//! range. These references anchor additional root functions for reachability
//! analysis, preventing false positives on functions called only via
//! function pointers or jump tables.

use crate::types::{Endian, Section};
use std::collections::HashSet;

/// Scan data sections for embedded function addresses.
pub fn scan_data_for_func_addrs(
    data: &[u8],
    func_addrs: &HashSet<u64>,
    sections: &[Section],
    is64: bool,
    endian: Endian,
) -> HashSet<u64> {
    let data_names: &[&str] = &[
        ".rodata",
        ".data",
        ".data.rel.ro",
        ".init_array",
        ".fini_array",
        ".got",
        ".got.plt",
        ".rdata",
        ".ctors",
        ".dtors",
    ];
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let mut refs = HashSet::new();
    for sec in sections {
        if !data_names.contains(&sec.name.as_str()) {
            continue;
        }
        scan_one_section(
            data, sec, ptr_size, is64, endian, func_addrs,
            &mut refs,
        );
    }
    refs
}

/// Scan a single section for pointer-sized values matching known function addresses.
fn scan_one_section(
    data: &[u8],
    sec: &Section,
    ptr_size: usize,
    is64: bool,
    endian: Endian,
    func_addrs: &HashSet<u64>,
    refs: &mut HashSet<u64>,
) {
    let end =
        (sec.offset as usize + sec.size as usize).min(data.len());
    let mut i = sec.offset as usize;
    while i + ptr_size <= end {
        let val =
            crate::types::read_ptr(data, i, is64, endian);
        if func_addrs.contains(&val) {
            refs.insert(val);
        }
        i += ptr_size;
    }
}

/// Scan data sections for pointers into .text range.
pub fn scan_data_code_refs(
    data: &[u8],
    sections: &[Section],
    text_start: u64,
    text_end: u64,
    is64: bool,
    endian: Endian,
) -> HashSet<u64> {
    let scan_names: &[&str] = &[
        ".data",
        ".data.rel.ro",
        ".got",
        ".got.plt",
        ".init_array",
        ".fini_array",
        ".ctors",
        ".dtors",
        ".rdata",
    ];
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let mut refs = HashSet::new();
    for sec in sections {
        if !scan_names.contains(&sec.name.as_str()) {
            continue;
        }
        let end = (sec.offset as usize + sec.size as usize)
            .min(data.len());
        let mut i = sec.offset as usize;
        while i + ptr_size <= end {
            let val =
                crate::types::read_ptr(data, i, is64, endian);
            if text_start <= val && val < text_end {
                refs.insert(val);
            }
            i += ptr_size;
        }
    }
    refs
}
