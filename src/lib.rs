pub mod analysis;
pub mod arch;
pub mod constants;
pub mod decode;
pub mod format;
pub mod patch;
pub mod types;

use crate::analysis::cfg::DeadBlock;
use crate::types::{FuncMap, Section};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;

/// Analysis result including dead functions and dead blocks.
pub struct AnalysisResult {
    pub funcs: FuncMap,
    pub dead_funcs: HashMap<String, (u64, u64)>,
    pub dead_blocks: Vec<DeadBlock>,
    pub sections: Vec<Section>,
    pub sccp_skipped: Vec<(String, usize)>,
}

/// Analyze a binary, return full analysis result.
pub fn analyze(
    data: &[u8],
    max_sccp_instrs: usize,
) -> AnalysisResult {
    let (funcs, dead_funcs, sections, import_names) =
        analyze_format(data);
    let live_funcs = compute_live_names(&funcs, &dead_funcs);
    let instrs = decode_for_cfg(data, &sections);
    let mut dead_blocks = analysis::cfg::find_dead_blocks(
        &funcs, &instrs, &live_funcs, &import_names,
    );
    let arch = detect_arch_from_data(data);
    let (sccp_dead, sccp_skipped) = run_sccp_analysis(
        &funcs, &instrs, &live_funcs, arch, max_sccp_instrs,
    );
    merge_dead_blocks(&mut dead_blocks, sccp_dead);
    AnalysisResult {
        funcs,
        dead_funcs,
        dead_blocks,
        sections,
        sccp_skipped,
    }
}

fn run_sccp_analysis(
    funcs: &FuncMap,
    instrs: &[types::DecodedInstr],
    live_funcs: &HashSet<String>,
    arch: types::Arch,
    max_instrs: usize,
) -> (Vec<analysis::cfg::DeadBlock>, Vec<(String, usize)>) {
    let mut all_dead = Vec::new();
    let mut skipped = Vec::new();
    for (name, fi) in funcs {
        if !live_funcs.contains(name) || fi.size < 32 {
            continue;
        }
        if name.starts_with("sub_") {
            continue;
        }
        let cfg = analysis::cfg::build_func_cfg(
            name, fi, instrs, funcs,
        );
        let result = analysis::sccp::sccp_dead_blocks(
            &cfg, instrs, arch, funcs, max_instrs,
        );
        if result.skipped {
            skipped.push((
                name.clone(),
                result.instr_count,
            ));
        }
        all_dead.extend(result.dead);
    }
    (all_dead, skipped)
}

fn merge_dead_blocks(
    base: &mut Vec<analysis::cfg::DeadBlock>,
    extra: Vec<analysis::cfg::DeadBlock>,
) {
    let existing: HashSet<u64> =
        base.iter().map(|b| b.addr).collect();
    for db in extra {
        if !existing.contains(&db.addr) {
            base.push(db);
        }
    }
}

fn analyze_format(
    data: &[u8],
) -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
    HashMap<u64, String>,
) {
    match format::detect_format(data) {
        Some(format::Format::Elf) => {
            format::elf::analyze_elf_full(data)
        }
        Some(format::Format::Pe) => {
            let (f, d, s) = format::pe::analyze_pe(data);
            (f, d, s, HashMap::new())
        }
        Some(format::Format::MachO) => {
            let (f, d, s) =
                format::macho::analyze_macho(data);
            (f, d, s, HashMap::new())
        }
        Some(format::Format::Dotnet) => {
            let (f, d, s) =
                format::dotnet::analyze_dotnet(data);
            (f, d, s, HashMap::new())
        }
        None => (
            FuncMap::new(),
            HashMap::new(),
            Vec::new(),
            HashMap::new(),
        ),
    }
}

fn compute_live_names(
    funcs: &FuncMap,
    dead: &HashMap<String, (u64, u64)>,
) -> HashSet<String> {
    funcs
        .keys()
        .filter(|n| !dead.contains_key(*n))
        .cloned()
        .collect()
}

fn decode_for_cfg(
    data: &[u8],
    sections: &[Section],
) -> Vec<types::DecodedInstr> {
    let text = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let arch = detect_arch_from_data(data);
    arch::decode_text(
        data, text.offset, text.vaddr, text.size, arch,
    )
}

fn detect_arch_from_data(data: &[u8]) -> types::Arch {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return detect_elf_arch(data);
    }
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return detect_pe_arch(data);
    }
    types::Arch::X86_64
}

fn detect_elf_arch(data: &[u8]) -> types::Arch {
    if data.len() < 20 {
        return types::Arch::X86_64;
    }
    let em = u16::from_le_bytes(
        data[18..20].try_into().unwrap_or([0; 2]),
    );
    match em {
        0x3E => types::Arch::X86_64,
        0x03 => types::Arch::X86_32,
        0xB7 => types::Arch::Aarch64,
        0x28 => types::Arch::Arm32,
        _ => types::Arch::X86_64,
    }
}

fn detect_pe_arch(data: &[u8]) -> types::Arch {
    if data.len() < 64 {
        return types::Arch::X86_64;
    }
    let pe_off = u32::from_le_bytes(
        data[0x3C..0x40].try_into().unwrap_or([0; 4]),
    ) as usize;
    if pe_off + 6 > data.len() {
        return types::Arch::X86_64;
    }
    let machine = u16::from_le_bytes(
        data[pe_off + 4..pe_off + 6]
            .try_into()
            .unwrap_or([0; 2]),
    );
    match machine {
        0x8664 => types::Arch::X86_64,
        0x014C => types::Arch::X86_32,
        0xAA64 => types::Arch::Aarch64,
        0x01C0 => types::Arch::Arm32,
        _ => types::Arch::X86_64,
    }
}

/// Reassemble: patch refs, compact, update metadata.
pub fn reassemble(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    reassemble_format(data, dead, dead_blocks, sections)
}

fn reassemble_format(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    dead_blocks: &[DeadBlock],
    sections: &[Section],
) -> (usize, u64, usize, u64) {
    match format::detect_format(data) {
        Some(format::Format::Elf) => {
            format::elf::reassemble_elf(
                data, dead, dead_blocks, sections,
            )
        }
        Some(format::Format::Pe) => {
            format::pe::reassemble_pe(
                data, dead, dead_blocks, sections,
            )
        }
        Some(format::Format::MachO) => {
            format::macho::reassemble_macho(
                data, dead, dead_blocks, sections,
            )
        }
        Some(format::Format::Dotnet) => {
            format::dotnet::reassemble_dotnet(
                data, dead, dead_blocks, sections,
            )
        }
        None => (0, 0, 0, 0),
    }
}

/// Analyze and patch binary data, return patched bytes.
pub fn process_bytes(
    data: &[u8],
    label: &str,
    dry_run: bool,
    max_sccp_instrs: usize,
) -> Result<Option<Vec<u8>>> {
    eprintln!("analyzing: {} ({} bytes)", label, data.len());
    let result = analyze(data, max_sccp_instrs);
    if result.funcs.is_empty() {
        eprintln!("  skipped: no functions detected");
        return Ok(None);
    }
    let has_dead_funcs = !result.dead_funcs.is_empty();
    let has_dead_blocks = !result.dead_blocks.is_empty();
    if !has_dead_funcs && !has_dead_blocks {
        report_sccp_skipped(&result.sccp_skipped);
        eprintln!(
            "  no dead code found ({} functions, all live)",
            result.funcs.len()
        );
        return Ok(None);
    }
    report_dead_funcs(&result.dead_funcs);
    report_dead_blocks(&result.dead_blocks);
    report_sccp_skipped(&result.sccp_skipped);
    if dry_run {
        return Ok(None);
    }
    patch_binary(data, &result)
}

fn report_dead_funcs(
    dead: &HashMap<String, (u64, u64)>,
) {
    if dead.is_empty() {
        return;
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
}

fn report_sccp_skipped(skipped: &[(String, usize)]) {
    if skipped.is_empty() {
        return;
    }
    eprintln!(
        "  sccp: {} functions skipped (too large):",
        skipped.len()
    );
    let mut sorted = skipped.to_vec();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, count) in &sorted {
        eprintln!(
            "    {}: {} instructions",
            name, count
        );
    }
}

fn report_dead_blocks(dead_blocks: &[DeadBlock]) {
    if dead_blocks.is_empty() {
        return;
    }
    let total: u64 = dead_blocks.iter().map(|b| b.size).sum();
    eprintln!(
        "  found {} dead branches ({} bytes):",
        dead_blocks.len(),
        total
    );
    for db in dead_blocks {
        eprintln!(
            "    dead branch: {} bytes @ 0x{:x} (in {})",
            db.size, db.addr, db.func_name
        );
    }
}

fn patch_binary(
    data: &[u8],
    result: &AnalysisResult,
) -> Result<Option<Vec<u8>>> {
    let mut mdata = data.to_vec();
    let (fc, fs, bc, bs) = reassemble(
        &mut mdata,
        &result.dead_funcs,
        &result.dead_blocks,
        &result.sections,
    );
    let total_freed = fs + bs;
    eprintln!(
        "  reassembled: {} dead functions removed, \
         {} dead branches removed, {} bytes freed",
        fc, bc, total_freed
    );
    Ok(Some(mdata))
}

/// Process a single file in-place: analyze and optionally patch.
pub fn process_file(
    path: &str,
    dry_run: bool,
    max_sccp_instrs: usize,
) -> Result<i32> {
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
    match process_bytes(&data, path, dry_run, max_sccp_instrs)? {
        Some(patched) => {
            fs::write(path, &patched)?;
            Ok(0)
        }
        None => Ok(0),
    }
}
