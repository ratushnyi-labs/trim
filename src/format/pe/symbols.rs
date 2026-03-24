//! PE/COFF symbol and export table parsing.
//!
//! Extracts function entries from the COFF symbol table (for object
//! files and debug builds) and the PE export directory (for DLLs),
//! converting them into the crate's `FuncMap` type.

use crate::types::{FuncInfo, FuncMap};
use goblin::pe::PE;

/// Extract functions from the COFF symbol table, if present.
pub fn get_coff_functions(data: &[u8], pe: &PE) -> FuncMap {
    let ptr =
        pe.header.coff_header.pointer_to_symbol_table as usize;
    let count =
        pe.header.coff_header.number_of_symbol_table as usize;
    if ptr == 0 || count == 0 {
        return FuncMap::new();
    }
    let str_off = ptr + count * 18;
    let mut funcs = FuncMap::new();
    let mut i = 0;
    while i < count {
        parse_one_sym(
            data, pe, ptr, str_off, i, &mut funcs,
        );
        let off = ptr + i * 18;
        let aux = if off + 17 < data.len() {
            data[off + 17] as usize
        } else {
            0
        };
        i += 1 + aux;
    }
    funcs
}

/// Parse a single COFF symbol entry, adding it to `funcs` if it is a function.
fn parse_one_sym(
    data: &[u8],
    pe: &PE,
    sym_base: usize,
    str_off: usize,
    idx: usize,
    funcs: &mut FuncMap,
) {
    let off = sym_base + idx * 18;
    if off + 18 > data.len() {
        return;
    }
    let value = u32::from_le_bytes(
        data[off + 8..off + 12].try_into().unwrap_or([0; 4]),
    );
    let sec_num = i16::from_le_bytes(
        data[off + 12..off + 14].try_into().unwrap_or([0; 2]),
    );
    let typ = u16::from_le_bytes(
        data[off + 14..off + 16].try_into().unwrap_or([0; 2]),
    );
    let class = data[off + 16];
    let is_func = (typ >> 4) & 0xF == 2;
    if !is_func || sec_num <= 0 {
        return;
    }
    let name = coff_sym_name(data, off, str_off);
    if name.is_empty() {
        return;
    }
    let rva = section_rva(pe, sec_num, value);
    let is_global = class == 2;
    funcs.insert(
        name,
        FuncInfo { addr: rva, size: 0, is_global },
    );
}

/// Compute the RVA of a COFF symbol by adding its value to the section base.
fn section_rva(pe: &PE, sec_num: i16, value: u32) -> u64 {
    let idx = (sec_num - 1) as usize;
    if idx < pe.sections.len() {
        pe.sections[idx].virtual_address as u64 + value as u64
    } else {
        value as u64
    }
}

/// Extract the name of a COFF symbol (inline or from the string table).
fn coff_sym_name(
    data: &[u8],
    sym_off: usize,
    str_table_off: usize,
) -> String {
    let nb = &data[sym_off..sym_off + 8];
    if nb[0..4] == [0, 0, 0, 0] {
        return str_table_name(data, nb, str_table_off);
    }
    let end = nb.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&nb[..end]).to_string()
}

/// Look up a symbol name from the COFF string table.
fn str_table_name(
    data: &[u8],
    nb: &[u8],
    str_table_off: usize,
) -> String {
    let off = u32::from_le_bytes(
        nb[4..8].try_into().unwrap_or([0; 4]),
    ) as usize;
    let abs = str_table_off + off;
    if abs >= data.len() {
        return String::new();
    }
    let end = data[abs..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| abs + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[abs..end]).to_string()
}

/// Extract exported functions (for DLLs).
pub fn get_exports(pe: &PE) -> FuncMap {
    let mut funcs = FuncMap::new();
    for exp in &pe.exports {
        add_export(&mut funcs, exp);
    }
    funcs
}

/// Add a single PE export to the function map if it has a name and RVA.
fn add_export(funcs: &mut FuncMap, exp: &goblin::pe::export::Export) {
    let name = match exp.name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return,
    };
    if exp.rva == 0 {
        return;
    }
    funcs.insert(
        name,
        FuncInfo {
            addr: exp.rva as u64,
            size: exp.size as u64,
            is_global: true,
        },
    );
}
