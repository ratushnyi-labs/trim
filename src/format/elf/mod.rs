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

/// ELF code sections to decode for references.
const DECODE_SECTIONS: &[&str] = &[
    ".text", ".plt", ".plt.got", ".plt.sec", ".init", ".fini",
];

/// Analyze an ELF binary: returns (funcs, dead, sections).
pub fn analyze_elf(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let (funcs, dead, sections, _) = analyze_elf_full(data);
    (funcs, dead, sections)
}

/// Analyze ELF returning import names (PLT) alongside.
pub fn analyze_elf_full(
    data: &[u8],
) -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
    HashMap<u64, String>,
) {
    let elf = match goblin::elf::Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return empty_full(),
    };
    let sections = sections::get_sections(&elf);
    let (ts, te) = match sections::text_bounds(&sections) {
        Some(b) => b,
        None => return empty_full(),
    };
    let text_sec =
        match sections.iter().find(|s| s.name == ".text") {
            Some(s) => s,
            None => return empty_full(),
        };
    let arch = detect_arch(data);
    let instrs = crate::arch::decode_text(
        data,
        text_sec.offset,
        text_sec.vaddr,
        text_sec.size,
        arch,
    );
    if instrs.is_empty() {
        return empty_full();
    }
    let funcs =
        build_func_map(&elf, data, &sections, &instrs, ts, te);
    if funcs.is_empty() {
        return empty_full();
    }
    let plt_names =
        symbols::get_plt_names(&elf, &sections);
    let dead = run_analysis(&funcs, &instrs, data, &sections);
    (funcs, dead, sections, plt_names)
}

fn build_func_map(
    elf: &goblin::elf::Elf,
    data: &[u8],
    sections: &[Section],
    instrs: &[DecodedInstr],
    ts: u64,
    te: u64,
) -> FuncMap {
    let mut funcs = symbols::get_functions_symtab(elf);
    if funcs.is_empty() {
        let dynsyms = symbols::get_dynamic_symbols(elf);
        let is64 = elf.is_64;
        funcs = crate::decode::infer::infer_functions(
            elf.entry, &dynsyms, data, sections, instrs, ts, te,
            is64,
        );
    }
    funcs
}

fn run_analysis(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
    data: &[u8],
    sections: &[Section],
) -> HashMap<String, (u64, u64)> {
    let (graph, orphan_refs) = build_ref_graph_fast(funcs, instrs);
    let func_addrs: HashSet<u64> =
        funcs.values().map(|fi| fi.addr).collect();
    let is64 = detect_is64(data);
    let endian = detect_endian(data);
    let data_refs = scan_data_for_func_addrs(
        data, &func_addrs, sections, is64, endian,
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

fn empty_full() -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
    HashMap<u64, String>,
) {
    (FuncMap::new(), HashMap::new(), Vec::new(), HashMap::new())
}

/// Reassemble: patch refs, compact .text, update ELF metadata.
/// Returns (func_count, func_saved, block_count, block_saved).
pub fn reassemble_elf(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    let arch = detect_arch(data);
    if !matches!(arch, Arch::X86_64 | Arch::X86_32) {
        let (fc, fs) = zero_fill(data, dead, sections);
        let (bc, bs) =
            zero_fill_blocks(data, dead_blocks, sections, arch);
        return (fc, fs, bc, bs);
    }
    let (ts, te) = match sections::text_bounds(sections) {
        Some(b) => b,
        None => {
            let (fc, fs) = zero_fill(data, dead, sections);
            let (bc, bs) = zero_fill_blocks(
                data, dead_blocks, sections, arch,
            );
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
    );
    let instrs = decode_sections(data, sections);
    if instrs.is_empty() {
        let (fc, fs) = zero_fill(data, dead, sections);
        let (bc, bs) =
            zero_fill_blocks(data, dead_blocks, sections, arch);
        return (fc, fs, bc, bs);
    }
    apply_patches(
        data, &instrs, &intervals, sections, ts, te, arch,
    );
    let saved = compact_text(data, sections, &intervals);
    let blk_bytes: u64 =
        dead_blocks.iter().map(|b| b.size).sum();
    let func_saved = saved.saturating_sub(blk_bytes);
    (dead.len(), func_saved, dead_blocks.len(), blk_bytes)
}

fn decode_sections(
    data: &[u8],
    sections: &[Section],
) -> Vec<DecodedInstr> {
    let arch = detect_arch(data);
    let mut instrs = Vec::new();
    for name in DECODE_SECTIONS {
        if let Some(sec) = sections.iter().find(|s| s.name == *name)
        {
            instrs.extend(crate::arch::decode_text(
                data, sec.offset, sec.vaddr, sec.size, arch,
            ));
        }
    }
    instrs
}

fn apply_patches(
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
        _ => {}
    }
    let is64 = detect_is64(data);
    let endian = detect_endian(data);
    patch_data_ptrs(data, sections, intervals, ts, te, is64, endian);
    patch::patch_rela_dyn(data, sections, intervals, ts, te);
    patch::patch_entry_point(data, intervals, ts, te);
    patch::patch_symbols(data, sections, intervals, ts, te);
    patch::patch_dynamic(data, sections, intervals, ts, te);
    patch::patch_headers(data, sections, intervals, ts, te);
}

fn detect_arch(data: &[u8]) -> Arch {
    if data.len() < 20 {
        return Arch::X86_64;
    }
    let e_machine = u16::from_le_bytes(
        data[18..20].try_into().unwrap_or([0; 2]),
    );
    match e_machine {
        0x3E => Arch::X86_64,
        0x03 => Arch::X86_32,
        0xB7 => Arch::Aarch64,
        0x28 => Arch::Arm32,
        _ => Arch::X86_64,
    }
}

fn detect_is64(data: &[u8]) -> bool {
    data.len() > 4 && data[4] == 2
}

fn detect_endian(data: &[u8]) -> Endian {
    if data.len() > 5 && data[5] == 2 {
        Endian::Big
    } else {
        Endian::Little
    }
}
