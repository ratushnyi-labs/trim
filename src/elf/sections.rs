use crate::types::Section;
use goblin::elf::Elf;

/// Extract sections from a parsed ELF.
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
            })
        })
        .collect()
}

/// Return (start_vaddr, end_vaddr) of the .text section.
pub fn text_bounds(sections: &[Section]) -> Option<(u64, u64)> {
    sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| (s.vaddr, s.vaddr + s.size))
}

/// Convert a virtual address to a file offset.
pub fn vaddr_to_offset(
    vaddr: u64,
    sections: &[Section],
) -> Option<u64> {
    for s in sections {
        if s.vaddr <= vaddr && vaddr < s.vaddr + s.size {
            return Some(s.offset + (vaddr - s.vaddr));
        }
    }
    None
}
