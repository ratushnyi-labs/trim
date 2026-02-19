use crate::types::Section;
use std::collections::HashSet;

/// Scan data sections for embedded function addresses.
pub fn scan_data_for_func_addrs(
    data: &[u8],
    func_addrs: &HashSet<u64>,
    sections: &[Section],
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
    let is64 = data.len() > 4 && data[4] == 2;
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let mut refs = HashSet::new();
    for sec in sections {
        if !data_names.contains(&sec.name.as_str()) {
            continue;
        }
        let end =
            (sec.offset as usize + sec.size as usize).min(data.len());
        let mut i = sec.offset as usize;
        while i + ptr_size <= end {
            let val = if is64 {
                u64::from_le_bytes(
                    data[i..i + 8].try_into().unwrap_or([0; 8]),
                )
            } else {
                u32::from_le_bytes(
                    data[i..i + 4].try_into().unwrap_or([0; 4]),
                ) as u64
            };
            if func_addrs.contains(&val) {
                refs.insert(val);
            }
            i += ptr_size;
        }
    }
    refs
}

/// Scan data sections for pointers into .text range.
pub fn scan_data_code_refs(
    data: &[u8],
    sections: &[Section],
    text_start: u64,
    text_end: u64,
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
    ];
    let is64 = data.len() > 4 && data[4] == 2;
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let mut refs = HashSet::new();
    for sec in sections {
        if !scan_names.contains(&sec.name.as_str()) {
            continue;
        }
        let end =
            (sec.offset as usize + sec.size as usize).min(data.len());
        let mut i = sec.offset as usize;
        while i + ptr_size <= end {
            let val = if is64 {
                u64::from_le_bytes(
                    data[i..i + 8].try_into().unwrap_or([0; 8]),
                )
            } else {
                u32::from_le_bytes(
                    data[i..i + 4].try_into().unwrap_or([0; 4]),
                ) as u64
            };
            if text_start <= val && val < text_end {
                refs.insert(val);
            }
            i += ptr_size;
        }
    }
    refs
}
