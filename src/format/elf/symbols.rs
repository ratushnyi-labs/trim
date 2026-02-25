use crate::types::{FuncInfo, FuncMap, Section};
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC};
use goblin::elf::Elf;
use std::collections::HashMap;

/// Extract defined text functions from the static symbol table.
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

/// Extract defined functions from the dynamic symbol table.
pub fn get_dynamic_symbols(elf: &Elf) -> FuncMap {
    let mut funcs = FuncMap::new();
    for sym in &elf.dynsyms {
        if sym.st_type() != STT_FUNC {
            continue;
        }
        if sym.st_value == 0
            || sym.st_shndx == SHN_UNDEF as usize
        {
            continue;
        }
        let name = elf
            .dynstrtab
            .get_at(sym.st_name)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let bind = sym.st_bind();
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

fn plt_entry_size(sec: &Section) -> u64 {
    match sec.name.as_str() {
        ".plt" => 16,
        ".plt.sec" => 8,
        _ => 16,
    }
}
