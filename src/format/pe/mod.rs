pub mod sections;
pub mod symbols;

use crate::analysis::reachability::{compute_live_set, find_dead};
use crate::analysis::roots::determine_roots;
use crate::decode::callgraph::build_ref_graph_fast;
use crate::decode::scan::scan_data_for_func_addrs;
use crate::patch::zerofill::zero_fill;
use crate::types::{
    Arch, DecodedInstr, Endian, FuncMap, Section,
};
use std::collections::{HashMap, HashSet};

/// Analyze a PE binary: returns (funcs, dead, sections).
pub fn analyze_pe(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let pe = match goblin::pe::PE::parse(data) {
        Ok(p) => p,
        Err(_) => return empty_result(),
    };
    let secs = sections::get_sections(&pe);
    let text_sec = match secs.iter().find(|s| s.name == ".text")
    {
        Some(s) => s,
        None => return empty_result(),
    };
    let arch = detect_arch_pe(&pe);
    let instrs = crate::arch::decode_text(
        data, text_sec.offset, text_sec.vaddr, text_sec.size,
        arch,
    );
    if instrs.is_empty() {
        return empty_result();
    }
    let funcs = build_func_map(&pe, data, &secs, &instrs);
    if funcs.is_empty() {
        return empty_result();
    }
    let dead = run_analysis(&funcs, &instrs, data, &secs, &pe);
    (funcs, dead, secs)
}

fn build_func_map(
    pe: &goblin::pe::PE,
    data: &[u8],
    secs: &[Section],
    instrs: &[DecodedInstr],
) -> FuncMap {
    let coff = symbols::get_coff_functions(data, pe);
    if !coff.is_empty() {
        return coff;
    }
    let (ts, te) = match sections::text_bounds(secs) {
        Some(b) => b,
        None => return FuncMap::new(),
    };
    let exports = symbols::get_exports(pe);
    crate::decode::infer::infer_functions(
        pe.entry as u64, &exports, data, secs, instrs, ts, te,
        pe.is_64,
    )
}

fn run_analysis(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    data: &[u8],
    secs: &[Section],
    pe: &goblin::pe::PE,
) -> HashMap<String, (u64, u64)> {
    let (graph, orphan_refs) = build_ref_graph_fast(funcs, instrs);
    let func_addrs: HashSet<u64> =
        funcs.values().map(|fi| fi.addr).collect();
    let endian = Endian::Little;
    let data_refs = scan_data_for_func_addrs(
        data, &func_addrs, secs, pe.is_64, endian,
    );
    let by_addr: HashMap<u64, &str> = funcs
        .iter()
        .map(|(n, fi)| (fi.addr, n.as_str()))
        .collect();
    let data_names: HashSet<String> = data_refs
        .iter()
        .filter_map(|a| by_addr.get(a).map(|n| n.to_string()))
        .collect();
    let roots = determine_roots(funcs, &data_names, &orphan_refs);
    let live = compute_live_set(&roots, &graph, funcs);
    find_dead(funcs, &live)
}

fn detect_arch_pe(pe: &goblin::pe::PE) -> Arch {
    match pe.header.coff_header.machine {
        0x8664 => Arch::X86_64,
        0x014C => Arch::X86_32,
        0xAA64 => Arch::Aarch64,
        0x01C0 => Arch::Arm32,
        _ => Arch::X86_64,
    }
}

fn empty_result()
-> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}

/// Reassemble PE: zero-fill dead code (no compaction yet).
pub fn reassemble_pe(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    sections: &[Section],
) -> (usize, u64) {
    zero_fill(data, dead, sections)
}
