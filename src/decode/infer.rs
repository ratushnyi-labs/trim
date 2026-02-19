use crate::elf::symbols::get_dynamic_symbols;
use crate::types::{DecodedInstr, FuncInfo, FuncMap, Section};
use goblin::elf::Elf;
use std::collections::BTreeMap;

/// Infer function boundaries for stripped binaries.
pub fn infer_functions(
    elf: &Elf,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    text_start: u64,
    text_end: u64,
) -> FuncMap {
    let dynsyms = get_dynamic_symbols(elf);
    let entry = elf.entry;
    let data_refs =
        scan_data_code_refs(data, sections, text_start, text_end);
    let call_targets = collect_call_targets(instrs);
    let ref_targets = collect_ref_targets(instrs);
    let mut starts: BTreeMap<u64, (String, bool)> =
        BTreeMap::new();
    // Dynamic symbols
    for (name, fi) in &dynsyms {
        if text_start <= fi.addr && fi.addr < text_end {
            starts.insert(fi.addr, (name.clone(), fi.is_global));
        }
    }
    // Entry point
    if text_start <= entry && entry < text_end {
        starts
            .entry(entry)
            .or_insert(("_start".to_string(), true));
    }
    // Call targets
    for tgt in &call_targets {
        if text_start <= *tgt && *tgt < text_end {
            starts
                .entry(*tgt)
                .or_insert((format!("sub_{:x}", tgt), false));
        }
    }
    // Reference targets (RIP-relative LEA etc.)
    for tgt in &ref_targets {
        if text_start <= *tgt && *tgt < text_end {
            starts
                .entry(*tgt)
                .or_insert((format!("sub_{:x}", tgt), false));
        }
    }
    // Data section references
    for addr in &data_refs {
        starts
            .entry(*addr)
            .or_insert((format!("sub_{:x}", addr), true));
    }
    build_func_map(&starts, text_end)
}

fn collect_call_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter(|i| i.is_call)
        .flat_map(|i| i.targets.iter().copied())
        .collect()
}

fn collect_ref_targets(
    instrs: &[DecodedInstr],
) -> Vec<u64> {
    instrs
        .iter()
        .filter_map(|i| i.rip_target)
        .collect()
}

fn scan_data_code_refs(
    data: &[u8],
    sections: &[Section],
    text_start: u64,
    text_end: u64,
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
    ];
    let is64 = data.len() > 4 && data[4] == 2;
    let ptr_size: usize = if is64 { 8 } else { 4 };
    let mut refs = Vec::new();
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
                refs.push(val);
            }
            i += ptr_size;
        }
    }
    refs
}

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
