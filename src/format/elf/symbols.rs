//! ELF symbol table parsing.
//!
//! Extracts function entries from static (.symtab) and dynamic (.dynsym)
//! symbol tables, and maps PLT stub addresses to imported symbol names.

use crate::types::{FuncInfo, FuncMap, Section};
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_TLS};
use goblin::elf::Elf;
use std::collections::HashMap;

/// Extract defined text functions from the static symbol table (.symtab).
pub fn get_functions_symtab(elf: &Elf) -> FuncMap {
    let mut funcs = FuncMap::new();
    for sym in &elf.syms {
        if sym.st_type() != STT_FUNC {
            continue;
        }
        if sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF as usize {
            continue;
        }
        let bind = sym.st_bind();
        if bind != STB_GLOBAL && bind != STB_WEAK {
            if sym.st_type() != STT_FUNC {
                continue;
            }
        }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let is_global = bind == STB_GLOBAL || bind == STB_WEAK;
        funcs.insert(
            name,
            FuncInfo {
                addr: sym.st_value,
                size: sym.st_size,
                is_global,
            },
        );
    }
    funcs
}

/// Code entry points of the dynamic symbol table (.dynsym): every
/// defined entry whose value lies in an executable section, whatever
/// its type (STT_FUNC, an IFUNC resolver, an untyped assembly label,
/// ...). The dynamic linker reaches them through `st_value` alone, so
/// all are roots. A name seen again at another address (symbol
/// versions) gets an `@<addr>` suffix so that no entry is lost.
pub fn get_dynamic_symbols(elf: &Elf) -> FuncMap {
    let code = exec_ranges(elf);
    let mut funcs = FuncMap::new();
    for sym in &elf.dynsyms {
        if sym.st_shndx == SHN_UNDEF as usize || sym.st_type() == STT_TLS {
            continue;
        }
        let addr = sym.st_value;
        if !code.iter().any(|&(lo, hi)| lo <= addr && addr < hi) {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let key = match funcs.get(name) {
            Some(fi) if fi.addr != addr => format!("{}@{:x}", name, addr),
            _ => name.to_string(),
        };
        let fi = FuncInfo { addr, size: sym.st_size, is_global: true };
        funcs.insert(key, fi);
    }
    funcs
}

/// Address ranges `[lo, hi)` of the allocated executable sections, or
/// of the executable PT_LOAD segments when there are no section headers.
fn exec_ranges(elf: &Elf) -> Vec<(u64, u64)> {
    use goblin::elf::program_header::{PF_X, PT_LOAD};
    use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR};
    let span = |lo: u64, len: u64| Some((lo, lo.checked_add(len)?));
    let flags = u64::from(SHF_ALLOC | SHF_EXECINSTR);
    let secs: Vec<(u64, u64)> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_flags & flags == flags && sh.sh_addr != 0)
        .filter_map(|sh| span(sh.sh_addr, sh.sh_size))
        .collect();
    if !secs.is_empty() {
        return secs;
    }
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
        .filter_map(|ph| span(ph.p_vaddr, ph.p_memsz))
        .collect()
}

/// Map PLT entry addresses to imported symbol names.
pub fn get_plt_names(
    elf: &Elf,
    sections: &[Section],
) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let plt = find_plt_section(sections);
    let plt = match plt {
        Some(s) => s,
        None => return map,
    };
    let entry_size = plt_entry_size(plt);
    if entry_size == 0 {
        return map;
    }
    let skip = if plt.name == ".plt" { 1u64 } else { 0 };
    for (i, rel) in elf.pltrelocs.iter().enumerate() {
        let sym_idx = rel.r_sym;
        if let Some(sym) = elf.dynsyms.get(sym_idx) {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("");
            if !name.is_empty() {
                let addr = plt.vaddr
                    + (skip + i as u64) * entry_size;
                map.insert(addr, name.to_string());
            }
        }
    }
    map
}

/// Find the PLT section, preferring .plt.sec over .plt.
fn find_plt_section<'a>(
    sections: &'a [Section],
) -> Option<&'a Section> {
    sections
        .iter()
        .find(|s| s.name == ".plt.sec")
        .or_else(|| {
            sections.iter().find(|s| s.name == ".plt")
        })
}

/// Return the per-entry size of the given PLT section.
fn plt_entry_size(sec: &Section) -> u64 {
    match sec.name.as_str() {
        ".plt" => 16,
        ".plt.sec" => 8,
        _ => 16,
    }
}
