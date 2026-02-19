pub mod analysis;
pub mod constants;
pub mod decode;
pub mod elf;
pub mod patch;
pub mod types;

use crate::analysis::reachability::{compute_live_set, find_dead};
use crate::analysis::roots::determine_roots;
use crate::decode::callgraph::build_ref_graph_fast;
use crate::decode::disasm::decode_text;
use crate::decode::infer::infer_functions;
use crate::decode::scan::scan_data_for_func_addrs;
use crate::elf::sections::{get_sections, text_bounds};
use crate::elf::symbols::get_functions_symtab;
use crate::patch::compact::compact_text;
use crate::patch::data_ptrs::patch_data_ptrs;
use crate::patch::dynamic::patch_dynamic;
use crate::patch::entry::patch_entry_point;
use crate::patch::headers::patch_headers;
use crate::patch::jump_tables::patch_jump_tables;
use crate::patch::rela_dyn::patch_rela_dyn;
use crate::patch::relocs::{dead_intervals, defrag_intervals, patch_call_jmp};
use crate::patch::riprel::patch_rip_rel;
use crate::patch::symbols::patch_symbols;
use crate::patch::zerofill::zero_fill;
use crate::types::{FuncMap, Section};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;

/// Analyze a binary, return (all_funcs, dead_funcs).
pub fn analyze(data: &[u8]) -> (FuncMap, HashMap<String, (u64, u64)>) {
    let elf = match goblin::elf::Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return (FuncMap::new(), HashMap::new()),
    };
    let sections = get_sections(&elf);
    let (ts, te) = match text_bounds(&sections) {
        Some(b) => b,
        None => return (FuncMap::new(), HashMap::new()),
    };
    let text_sec = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return (FuncMap::new(), HashMap::new()),
    };
    let instrs =
        decode_text(data, text_sec.offset, text_sec.vaddr, text_sec.size);
    if instrs.is_empty() {
        return (FuncMap::new(), HashMap::new());
    }
    let mut funcs = get_functions_symtab(&elf);
    if funcs.is_empty() {
        funcs = infer_functions(
            &elf, data, &sections, &instrs, ts, te,
        );
    }
    if funcs.is_empty() {
        return (FuncMap::new(), HashMap::new());
    }
    let (graph, orphan_refs) = build_ref_graph_fast(&funcs, &instrs);
    let func_addrs: HashSet<u64> =
        funcs.values().map(|fi| fi.addr).collect();
    let data_refs =
        scan_data_for_func_addrs(data, &func_addrs, &sections);
    let by_addr: HashMap<u64, &str> = funcs
        .iter()
        .map(|(n, fi)| (fi.addr, n.as_str()))
        .collect();
    let data_names: HashSet<String> = data_refs
        .iter()
        .filter_map(|a| by_addr.get(a).map(|n| n.to_string()))
        .collect();
    let roots = determine_roots(&funcs, &data_names, &orphan_refs);
    let live = compute_live_set(&roots, &graph, &funcs);
    let dead = find_dead(&funcs, &live);
    (funcs, dead)
}

/// Reassemble: patch refs, compact .text, update pointers.
pub fn reassemble(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    sections: &[Section],
) -> (usize, u64) {
    let (ts, te) = match text_bounds(sections) {
        Some(b) => b,
        None => return zero_fill(data, dead, sections),
    };
    let intervals = dead_intervals(dead);
    let intervals = defrag_intervals(&intervals, data, sections);
    let instrs = decode_text_from_data(data, sections);
    if instrs.is_empty() {
        return zero_fill(data, dead, sections);
    }
    patch_call_jmp(data, &instrs, &intervals, sections, ts, te);
    patch_rip_rel(data, &instrs, &intervals, sections, ts, te);
    patch_data_ptrs(data, sections, &intervals, ts, te);
    patch_jump_tables(data, &instrs, &intervals, ts, te);
    patch_rela_dyn(data, sections, &intervals, ts, te);
    patch_entry_point(data, &intervals, ts, te);
    patch_symbols(data, sections, &intervals, ts, te);
    patch_dynamic(data, sections, &intervals, ts, te);
    patch_headers(data, sections, &intervals, ts, te);
    let saved = compact_text(data, sections, &intervals);
    (dead.len(), saved)
}

/// Sections with executable code that may have RIP-relative
/// references to shifted sections (e.g. .plt → .got.plt).
const DECODE_SECTIONS: &[&str] = &[
    ".text", ".plt", ".plt.got", ".plt.sec", ".init", ".fini",
];

fn decode_text_from_data(
    data: &[u8],
    sections: &[Section],
) -> Vec<crate::types::DecodedInstr> {
    let mut instrs = Vec::new();
    for name in DECODE_SECTIONS {
        if let Some(sec) = sections.iter().find(|s| s.name == *name) {
            instrs.extend(decode_text(
                data, sec.offset, sec.vaddr, sec.size,
            ));
        }
    }
    instrs
}

/// Analyze and patch binary data, return patched bytes.
/// Reports diagnostics to stderr. Returns None if no patching
/// needed (dry_run, no dead code, or no functions).
pub fn process_bytes(
    data: &[u8],
    label: &str,
    dry_run: bool,
) -> Result<Option<Vec<u8>>> {
    eprintln!("analyzing: {} ({} bytes)", label, data.len());
    let (funcs, dead) = analyze(data);
    if funcs.is_empty() {
        eprintln!("  skipped: no functions detected");
        return Ok(None);
    }
    if dead.is_empty() {
        eprintln!(
            "  no dead code found ({} functions, all live)",
            funcs.len()
        );
        return Ok(None);
    }
    let dead_bytes: u64 = dead.values().map(|&(_, s)| s).sum();
    eprintln!(
        "  found {} dead functions ({} bytes):",
        dead.len(),
        dead_bytes
    );
    let mut sorted: Vec<(&str, u64, u64)> = dead
        .iter()
        .map(|(n, &(a, s))| (n.as_str(), a, s))
        .collect();
    sorted.sort_by(|a, b| b.2.cmp(&a.2));
    for (name, addr, sz) in &sorted {
        eprintln!("    {}: {} bytes @ 0x{:x}", name, sz, addr);
    }
    if dry_run {
        return Ok(None);
    }
    let elf = goblin::elf::Elf::parse(data)
        .context("Failed to parse ELF")?;
    let sections = get_sections(&elf);
    let mut mdata = data.to_vec();
    let (count, saved) = reassemble(&mut mdata, &dead, &sections);
    eprintln!(
        "  reassembled: {} dead functions removed, {} bytes freed",
        count, saved
    );
    Ok(Some(mdata))
}

/// Process a single file in-place: analyze and optionally patch.
pub fn process_file(path: &str, dry_run: bool) -> Result<i32> {
    let meta = fs::metadata(path)
        .with_context(|| format!("Error: '{}' not found", path))?;
    if !meta.is_file() {
        eprintln!(
            "Error: '{}' not found or not a regular file",
            path
        );
        return Ok(1);
    }
    let real = fs::canonicalize(path)?;
    let sym_meta = fs::symlink_metadata(path)?;
    if sym_meta.file_type().is_symlink()
        && !real.starts_with("/work")
    {
        eprintln!("Error: '{}' is a symlink outside /work", path);
        return Ok(1);
    }
    if !dry_run {
        let wr_meta = fs::metadata(path)?;
        if wr_meta.permissions().readonly() {
            eprintln!("Error: '{}' is not writable", path);
            return Ok(1);
        }
    }
    let data = fs::read(path)?;
    match process_bytes(&data, path, dry_run)? {
        Some(patched) => {
            fs::write(path, &patched)?;
            Ok(0)
        }
        None => Ok(0),
    }
}
