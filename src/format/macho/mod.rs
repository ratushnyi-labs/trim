pub mod sections;
pub mod symbols;

use crate::analysis::reachability::{compute_live_set, find_dead};
use crate::analysis::roots::determine_roots;
use crate::decode::callgraph::build_ref_graph_fast;
use crate::decode::scan::scan_data_for_func_addrs;
use crate::analysis::cfg::DeadBlock;
use crate::patch::zerofill::{zero_fill, zero_fill_blocks};
use crate::types::{
    Arch, DecodedInstr, Endian, FuncMap, Section,
};
use std::collections::{HashMap, HashSet};

/// Analyze a Mach-O binary.
pub fn analyze_macho(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let macho = match goblin::mach::MachO::parse(data, 0) {
        Ok(m) => m,
        Err(_) => return empty_result(),
    };
    let secs = sections::get_sections(&macho);
    let text_sec = match secs.iter().find(|s| s.name == ".text")
    {
        Some(s) => s,
        None => return empty_result(),
    };
    let arch = detect_arch_macho(&macho);
    let instrs = crate::arch::decode_text(
        data, text_sec.offset, text_sec.vaddr, text_sec.size,
        arch,
    );
    if instrs.is_empty() {
        return empty_result();
    }
    let funcs =
        build_func_map(&macho, data, &secs, &instrs);
    if funcs.is_empty() {
        return empty_result();
    }
    let dead = run_analysis(
        &funcs, &instrs, data, &secs, &macho,
    );
    (funcs, dead, secs)
}

fn build_func_map(
    macho: &goblin::mach::MachO,
    data: &[u8],
    secs: &[Section],
    instrs: &[DecodedInstr],
) -> FuncMap {
    let sym_funcs = symbols::get_functions(macho);
    if !sym_funcs.is_empty() {
        return sym_funcs;
    }
    let (ts, te) = match sections::text_bounds(secs) {
        Some(b) => b,
        None => return FuncMap::new(),
    };
    let entry = macho.entry as u64;
    let dynsyms = FuncMap::new();
    let is64 = macho.is_64;
    crate::decode::infer::infer_functions(
        entry, &dynsyms, data, secs, instrs, ts, te, is64,
    )
}

fn run_analysis(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    data: &[u8],
    secs: &[Section],
    macho: &goblin::mach::MachO,
) -> HashMap<String, (u64, u64)> {
    let (graph, orphan_refs) =
        build_ref_graph_fast(funcs, instrs);
    let func_addrs: HashSet<u64> =
        funcs.values().map(|fi| fi.addr).collect();
    let is64 = macho.is_64;
    let endian = Endian::Little;
    let data_refs = scan_data_for_func_addrs(
        data, &func_addrs, secs, is64, endian,
    );
    let by_addr: HashMap<u64, &str> = funcs
        .iter()
        .map(|(n, fi)| (fi.addr, n.as_str()))
        .collect();
    let data_names: HashSet<String> = data_refs
        .iter()
        .filter_map(|a| by_addr.get(a).map(|n| n.to_string()))
        .collect();
    let roots =
        determine_roots(funcs, &data_names, &orphan_refs);
    let live = compute_live_set(&roots, &graph, funcs);
    find_dead(funcs, &live)
}

fn detect_arch_macho(macho: &goblin::mach::MachO) -> Arch {
    let ct = macho.header.cputype;
    match ct {
        0x0100_0007 => Arch::X86_64,
        0x0100_000C => Arch::Aarch64,
        0x0C => Arch::Arm32,
        0x07 => Arch::X86_32,
        _ => Arch::X86_64,
    }
}

fn empty_result()
-> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}

/// Reassemble Mach-O: zero-fill dead code.
pub fn reassemble_macho(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    let arch = detect_arch_macho_raw(data);
    let (fc, fs) = zero_fill(data, dead, sections);
    let (bc, bs) =
        zero_fill_blocks(data, dead_blocks, sections, arch);
    (fc, fs, bc, bs)
}

fn detect_arch_macho_raw(data: &[u8]) -> Arch {
    if data.len() < 8 {
        return Arch::X86_64;
    }
    let magic = u32::from_le_bytes(
        data[0..4].try_into().unwrap_or([0; 4]),
    );
    let ct_off = if magic == 0xFEED_FACF
        || magic == 0xFEED_FACE
    {
        4
    } else {
        return Arch::X86_64;
    };
    let ct = u32::from_le_bytes(
        data[ct_off..ct_off + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    match ct {
        0x0100_0007 => Arch::X86_64,
        0x0100_000C => Arch::Aarch64,
        0x0C => Arch::Arm32,
        0x07 => Arch::X86_32,
        _ => Arch::X86_64,
    }
}
