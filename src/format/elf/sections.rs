//! ELF section header parsing.
//!
//! Converts goblin ELF section headers into the crate's unified `Section`
//! type and provides helpers for locating the .text section bounds.

use crate::types::Section;
use goblin::elf::Elf;

/// Extract all non-empty sections from a parsed ELF into `Section` structs.
pub fn get_sections(elf: &Elf) -> Vec<Section> {
    elf.section_headers
        .iter()
        .filter_map(|sh| {
            if sh.sh_type == 0 || sh.sh_size == 0 {
                return None;
            }
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            Some(Section {
                name,
                size: sh.sh_size,
                vaddr: sh.sh_addr,
                offset: sh.sh_offset,
                align: sh.sh_addralign,
            })
        })
        .collect()
}

/// Return (start_vaddr, end_vaddr) of the .text section.
pub fn text_bounds(
    sections: &[Section],
) -> Option<(u64, u64)> {
    sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| (s.vaddr, s.vaddr + s.size))
}
