//! Core dispatch logic for the `trim` dead-code removal tool.
//!
//! Orchestrates the full pipeline: format detection, function discovery,
//! call-graph reachability, CFG-based dead-block detection, SCCP analysis,
//! and binary reassembly. Supports ELF, PE/COFF, Mach-O, .NET, Wasm,
//! and Java class files across x86, AArch64, ARM32, RISC-V, MIPS,
//! s390x, and LoongArch architectures.

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
    let big_endian = detect_big_endian(data);
    let (sccp_dead, sccp_skipped) = run_sccp_analysis(
        &funcs, &instrs, &live_funcs, arch,
        max_sccp_instrs, big_endian,
    );
    merge_dead_blocks(&mut dead_blocks, sccp_dead);
    // Format-specific dead block detection for Wasm and .NET
    let format_dead = find_format_dead_blocks(data, &dead_funcs);
    merge_dead_blocks(&mut dead_blocks, format_dead);
    AnalysisResult {
        funcs,
        dead_funcs,
        dead_blocks,
        sections,
        sccp_skipped,
    }
}

/// Run SCCP (Sparse Conditional Constant Propagation) on all eligible
/// live functions and collect dead blocks where branches resolve statically.
fn run_sccp_analysis(
    funcs: &FuncMap,
    instrs: &[types::DecodedInstr],
    live_funcs: &HashSet<String>,
    arch: types::Arch,
    max_instrs: usize,
    big_endian: bool,
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
            big_endian,
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

/// Detect dead blocks in format-specific bytecode (Wasm, .NET IL, Java).
fn find_format_dead_blocks(
    data: &[u8],
    dead_funcs: &HashMap<String, (u64, u64)>,
) -> Vec<analysis::cfg::DeadBlock> {
    match format::detect_format(data) {
        Some(format::Format::Wasm) => {
            format::wasm::find_wasm_dead_blocks(data, dead_funcs)
        }
        Some(format::Format::Dotnet) => {
            find_dotnet_dead_blocks(data, dead_funcs)
        }
        Some(format::Format::Java) => {
            format::java::find_java_dead_blocks(
                data, dead_funcs,
            )
        }
        _ => Vec::new(),
    }
}

/// Find dead blocks in .NET IL method bodies by cross-referencing
/// the dead function set with CIL method RVAs.
fn find_dotnet_dead_blocks(
    data: &[u8],
    dead_funcs: &HashMap<String, (u64, u64)>,
) -> Vec<analysis::cfg::DeadBlock> {
    let parsed = match parse_dotnet_for_blocks(data) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let rvas: Vec<u32> =
        parsed.methods.iter().map(|m| m.rva).collect();
    let names: Vec<String> = parsed
        .methods
        .iter()
        .map(|m| {
            format::dotnet::tables::get_string(
                data, &parsed.root, m.name_idx,
            )
        })
        .collect();
    let dead_indices: HashSet<usize> = parsed
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            let name = format::dotnet::tables::get_string(
                data, &parsed.root, m.name_idx,
            );
            dead_funcs.contains_key(&name)
        })
        .map(|(i, _)| i)
        .collect();
    let all_indices: HashSet<usize> =
        (0..parsed.methods.len()).collect();
    let live_indices: HashSet<usize> = all_indices
        .difference(&dead_indices)
        .copied()
        .collect();
    let rva_fn = |rva: u32| -> Option<usize> {
        format::dotnet::pe_rva_to_offset_pub(data, rva)
    };
    format::dotnet::il::find_il_dead_blocks(
        data, &rvas, &live_indices, &dead_indices,
        &rva_fn, &names,
    )
}

/// Parsed .NET metadata needed for dead-block detection.
struct DotnetParsed {
    root: format::dotnet::metadata::MetadataRoot,
    methods: Vec<format::dotnet::tables::MethodDef>,
}

/// Parse .NET PE metadata tables to extract method definitions.
fn parse_dotnet_for_blocks(data: &[u8]) -> Option<DotnetParsed> {
    let cli_off =
        format::dotnet::metadata::cli_header_offset(data)?;
    let cli =
        format::dotnet::metadata::parse_cli_header(
            data, cli_off,
        )?;
    let md_off = format::dotnet::pe_rva_to_offset_pub(
        data, cli.metadata_rva,
    )?;
    let root =
        format::dotnet::metadata::parse_metadata_root(
            data, md_off,
        )?;
    let ts =
        format::dotnet::tables::parse_table_stream(data, &root)?;
    let methods =
        format::dotnet::tables::read_method_defs(data, &ts);
    if methods.is_empty() {
        return None;
    }
    Some(DotnetParsed { root, methods })
}

/// Merge extra dead blocks into the base list, deduplicating by address.
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

/// Detect binary format and run format-specific analysis to discover
/// functions, dead functions, sections, and import names.
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
        Some(format::Format::Wasm) => {
            let (f, d, s) =
                format::wasm::analyze_wasm(data);
            (f, d, s, HashMap::new())
        }
        Some(format::Format::Java) => {
            let (f, d, s) =
                format::java::analyze_java(data);
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

/// Compute the set of function names that are alive (not in the dead set).
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

/// Decode the .text section instructions for CFG construction.
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

/// Detect if the binary is big-endian from the ELF EI_DATA byte.
fn detect_big_endian(data: &[u8]) -> bool {
    if data.len() >= 6 && &data[..4] == b"\x7fELF" {
        return data[5] == 2; // EI_DATA: 2 = big-endian
    }
    false
}

/// Detect the CPU architecture from the binary header (ELF or PE).
fn detect_arch_from_data(data: &[u8]) -> types::Arch {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return detect_elf_arch(data);
    }
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return detect_pe_arch(data);
    }
    types::Arch::X86_64
}

/// Read the ELF e_machine field to determine the CPU architecture.
fn detect_elf_arch(data: &[u8]) -> types::Arch {
    if data.len() < 20 {
        return types::Arch::X86_64;
    }
    let is_be = data.len() > 5 && data[5] == 2;
    let em = if is_be {
        u16::from_be_bytes(
            data[18..20].try_into().unwrap_or([0; 2]),
        )
    } else {
        u16::from_le_bytes(
            data[18..20].try_into().unwrap_or([0; 2]),
        )
    };
    let is64 = data.len() > 4 && data[4] == 2;
    match em {
        0x3E => types::Arch::X86_64,
        0x03 => types::Arch::X86_32,
        0xB7 => types::Arch::Aarch64,
        0x28 => types::Arch::Arm32,
        0xF3 => {
            if is64 { types::Arch::RiscV64 }
            else { types::Arch::RiscV32 }
        }
        0x08 => {
            if is64 { types::Arch::Mips64 }
            else { types::Arch::Mips32 }
        }
        0x16 => types::Arch::S390x,
        0x102 => types::Arch::LoongArch64,
        _ => types::Arch::X86_64,
    }
}

/// Read the PE COFF machine field to determine the CPU architecture.
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
        0x5064 => types::Arch::RiscV64,
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

/// Dispatch to the format-specific reassembler to patch the binary.
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
        Some(format::Format::Wasm) => {
            format::wasm::reassemble_wasm(
                data, dead, dead_blocks,
            )
        }
        Some(format::Format::Java) => {
            format::java::reassemble_java(
                data, dead, dead_blocks,
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

/// Print discovered dead functions to stderr, sorted by size descending.
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

/// Print functions that were skipped by SCCP due to instruction count limits.
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

/// Print discovered dead branches to stderr.
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

/// Apply dead-code patches to the binary data and report results.
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
