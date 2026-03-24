pub mod patch;
pub mod sections;
pub mod symbols;

use crate::analysis::reachability::{compute_live_set, find_dead};
use crate::analysis::roots::determine_roots;
use crate::decode::callgraph::build_ref_graph_fast;
use crate::decode::scan::scan_data_for_func_addrs;
use crate::analysis::cfg::DeadBlock;
use crate::patch::compact::compact_text;
use crate::patch::data_ptrs::patch_data_ptrs;
use crate::patch::relocs::{
    block_intervals, combine_intervals, dead_intervals,
    defrag_intervals,
};
use crate::patch::zerofill::{zero_fill, zero_fill_blocks};
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

/// Reassemble PE: patch refs, compact .text, update PE metadata.
/// Returns (func_count, func_saved, block_count, block_saved).
pub fn reassemble_pe(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    let arch = detect_arch_pe_raw(data);
    let (ts, te) = match sections::text_bounds(sections) {
        Some(b) => b,
        None => {
            let (fc, fs) = zero_fill(data, dead, sections);
            let (bc, bs) =
                zero_fill_blocks(data, dead_blocks, sections, arch);
            return (fc, fs, bc, bs);
        }
    };
    let func_ivs = dead_intervals(dead);
    let blk_ivs = block_intervals(dead_blocks);
    let combined = combine_intervals(&func_ivs, &blk_ivs);
    let intervals = defrag_intervals(
        &combined,
        data,
        sections,
        crate::arch::padding_fn(arch),
        crate::arch::instr_align(arch),
    );
    let instrs = decode_pe_sections(data, sections, arch);
    if instrs.is_empty() {
        let (fc, fs) = zero_fill(data, dead, sections);
        let (bc, bs) =
            zero_fill_blocks(data, dead_blocks, sections, arch);
        return (fc, fs, bc, bs);
    }
    apply_pe_patches(
        data, &instrs, &intervals, sections, ts, te, arch,
    );
    let saved = compact_text(data, sections, &intervals);
    let blk_bytes: u64 =
        dead_blocks.iter().map(|b| b.size).sum();
    let func_saved = saved.saturating_sub(blk_bytes);
    (dead.len(), func_saved, dead_blocks.len(), blk_bytes)
}

fn decode_pe_sections(
    data: &[u8],
    sections: &[Section],
    arch: Arch,
) -> Vec<DecodedInstr> {
    let mut instrs = Vec::new();
    if let Some(sec) =
        sections.iter().find(|s| s.name == ".text")
    {
        instrs.extend(crate::arch::decode_text(
            data, sec.offset, sec.vaddr, sec.size, arch,
        ));
    }
    instrs
}

fn apply_pe_patches(
    data: &mut Vec<u8>,
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
    arch: Arch,
) {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            use crate::arch::x86_patch;
            x86_patch::patch_call_jmp(
                data, instrs, intervals, sections, ts, te,
            );
            x86_patch::patch_pc_rel(
                data, instrs, intervals, sections, ts, te,
            );
            x86_patch::patch_jump_tables(
                data, instrs, intervals, ts, te,
            );
        }
        Arch::Aarch64 => {
            crate::arch::aarch64_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        Arch::Arm32 => {
            crate::arch::arm32_patch::patch_branches(
                data, instrs, intervals, sections, ts, te,
            );
        }
        _ => {}
    }
    let is64 = matches!(arch, Arch::X86_64 | Arch::Aarch64);
    patch_data_ptrs(
        data, sections, intervals, ts, te, is64, Endian::Little,
    );
    patch::patch_entry_point(data, intervals, ts, te);
    patch::patch_section_headers(
        data, sections, intervals, ts, te,
    );
    patch::patch_symbols(data, intervals, ts, te);
    patch::patch_exports(
        data, sections, intervals, ts, te,
    );
    patch::patch_base_relocs(
        data, sections, intervals, ts, te,
    );
    patch::patch_pdata(
        data, sections, intervals, ts, te,
    );
}

fn detect_arch_pe_raw(data: &[u8]) -> Arch {
    if data.len() < 0x40 {
        return Arch::X86_64;
    }
    let pe_off = u32::from_le_bytes(
        data[0x3C..0x40].try_into().unwrap_or([0; 4]),
    ) as usize;
    if pe_off + 6 > data.len() {
        return Arch::X86_64;
    }
    let m = u16::from_le_bytes(
        data[pe_off + 4..pe_off + 6]
            .try_into()
            .unwrap_or([0; 2]),
    );
    match m {
        0x8664 => Arch::X86_64,
        0x014C => Arch::X86_32,
        0xAA64 => Arch::Aarch64,
        0x01C0 => Arch::Arm32,
        _ => Arch::X86_64,
    }
}
