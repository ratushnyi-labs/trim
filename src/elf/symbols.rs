use crate::types::{FuncInfo, FuncMap};
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC};
use goblin::elf::Elf;

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
