use crate::types::Section;
use goblin::pe::PE;

/// Extract sections from a parsed PE.
pub fn get_sections(pe: &PE) -> Vec<Section> {
    pe.sections
        .iter()
        .filter_map(|sec| {
            let sz = sec.virtual_size.max(sec.size_of_raw_data);
            if sz == 0 {
                return None;
            }
            Some(Section {
                name: section_name(sec),
                size: sec.virtual_size as u64,
                vaddr: sec.virtual_address as u64,
                offset: sec.pointer_to_raw_data as u64,
                align: 0,
            })
        })
        .collect()
}

fn section_name(
    sec: &goblin::pe::section_table::SectionTable,
) -> String {
    let end = sec.name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&sec.name[..end]).to_string()
}

/// Return (start_rva, end_rva) of the .text section.
pub fn text_bounds(
    sections: &[Section],
) -> Option<(u64, u64)> {
    sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| (s.vaddr, s.vaddr + s.size))
}
