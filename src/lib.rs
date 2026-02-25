pub mod analysis;
pub mod arch;
pub mod constants;
pub mod decode;
pub mod format;
pub mod patch;
pub mod types;

use crate::types::{FuncMap, Section};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;

/// Analyze a binary, return (all_funcs, dead_funcs, sections).
pub fn analyze(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    match format::detect_format(data) {
        Some(format::Format::Elf) => {
            format::elf::analyze_elf(data)
        }
        Some(format::Format::Pe) => {
            format::pe::analyze_pe(data)
        }
        Some(format::Format::MachO) => {
            format::macho::analyze_macho(data)
        }
        Some(format::Format::Dotnet) => {
            format::dotnet::analyze_dotnet(data)
        }
        None => (FuncMap::new(), HashMap::new(), Vec::new()),
    }
}

/// Reassemble: patch refs, compact, update metadata.
pub fn reassemble(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    sections: &[Section],
) -> (usize, u64) {
    match format::detect_format(data) {
        Some(format::Format::Elf) => {
            format::elf::reassemble_elf(data, dead, sections)
        }
        Some(format::Format::Pe) => {
            format::pe::reassemble_pe(data, dead, sections)
        }
        Some(format::Format::MachO) => {
            format::macho::reassemble_macho(
                data, dead, sections,
            )
        }
        Some(format::Format::Dotnet) => {
            format::dotnet::reassemble_dotnet(
                data, dead, sections,
            )
        }
        None => (0, 0),
    }
}

/// Analyze and patch binary data, return patched bytes.
pub fn process_bytes(
    data: &[u8],
    label: &str,
    dry_run: bool,
) -> Result<Option<Vec<u8>>> {
    eprintln!("analyzing: {} ({} bytes)", label, data.len());
    let (funcs, dead, sections) = analyze(data);
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
    let mut mdata = data.to_vec();
    let (count, saved) =
        reassemble(&mut mdata, &dead, &sections);
    eprintln!(
        "  reassembled: {} dead functions removed, {} bytes freed",
        count, saved
    );
    Ok(Some(mdata))
}

/// Process a single file in-place: analyze and optionally patch.
pub fn process_file(
    path: &str,
    dry_run: bool,
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
    match process_bytes(&data, path, dry_run)? {
        Some(patched) => {
            fs::write(path, &patched)?;
            Ok(0)
        }
        None => Ok(0),
    }
}
