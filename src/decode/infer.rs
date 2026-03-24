//! Function boundary inference for stripped binaries.
//!
//! When symbol tables are unavailable (stripped binaries), infers function
//! start addresses from three sources:
//! 1. Call targets — addresses targeted by call instructions
//! 2. PC-relative references — addresses loaded via LEA/ADRP patterns
//! 3. Data section pointers — addresses found in .got, .init_array, etc.
//!
//! Each inferred function extends from its start address to the next
//! function's start (or the end of .text). Known dynamic symbols and
//! the entry point anchor the initial set.

use crate::types::{
    DecodedInstr, Endian, FuncInfo, FuncMap, Section,
};
use std::collections::BTreeMap;

/// Infer function boundaries for stripped binaries.
pub fn infer_functions(
    entry: u64,
    dynsyms: &FuncMap,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    text_start: u64,
    text_end: u64,
    is64: bool,
) -> FuncMap {
    let data_refs = scan_data_code_refs(
        data, sections, text_start, text_end, is64,
    );
    let call_targets = collect_call_targets(instrs);
    let ref_targets = collect_ref_targets(instrs);
    let mut starts: BTreeMap<u64, (String, bool)> =
        BTreeMap::new();
    for (name, fi) in dynsyms {
        if text_start <= fi.addr && fi.addr < text_end {
            starts.insert(fi.addr, (name.clone(), fi.is_global));
        }
    }
    if text_start <= entry && entry < text_end {
        starts
            .entry(entry)
            .or_insert(("_start".to_string(), true));
    }
    insert_targets(
        &mut starts, &call_targets, text_start, text_end,
    );
    insert_targets(
        &mut starts, &ref_targets, text_start, text_end,
    );
    for addr in &data_refs {
        starts
            .entry(*addr)
            .or_insert((format!("sub_{:x}", addr), true));
    }
    build_func_map(&starts, text_end)
}

/// Insert call/ref targets into the function start map if within .text bounds.
fn insert_targets(
    starts: &mut BTreeMap<u64, (String, bool)>,
    targets: &[u64],
    text_start: u64,
    text_end: u64,
) {
    for tgt in targets {
        if text_start <= *tgt && *tgt < text_end {
            starts
                .entry(*tgt)
                .or_insert((format!("sub_{:x}", tgt), false));
        }
    }
}

/// Extract all target addresses from call instructions.
fn collect_call_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter(|i| i.is_call)
        .flat_map(|i| i.targets.iter().copied())
        .collect()
}

/// Extract all PC-relative reference targets (LEA/ADRP patterns).
fn collect_ref_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter_map(|i| i.pc_rel_target)
        .collect()
}

/// Scan data sections (.got, .init_array, etc.) for pointers into .text.
fn scan_data_code_refs(
    data: &[u8],
    sections: &[Section],
    text_start: u64,
    text_end: u64,
    is64: bool,
) -> Vec<u64> {
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
    let endian = Endian::Little;
    let mut refs = Vec::new();
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
                refs.push(val);
            }
            i += ptr_size;
        }
    }
    refs
}

/// Build the final FuncMap from sorted start addresses.
/// Each function's size extends to the next function or to text_end.
fn build_func_map(
    starts: &BTreeMap<u64, (String, bool)>,
    text_end: u64,
) -> FuncMap {
    let addrs: Vec<u64> = starts.keys().copied().collect();
    let mut funcs = FuncMap::new();
    for (i, &addr) in addrs.iter().enumerate() {
        let (ref name, is_global) = starts[&addr];
        let size = if i + 1 < addrs.len() {
            addrs[i + 1] - addr
        } else {
            text_end - addr
        };
        if size > 0 {
            funcs.insert(
                name.clone(),
                FuncInfo {
                    addr,
                    size,
                    is_global,
                },
            );
        }
    }
    funcs
}
