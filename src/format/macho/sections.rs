//! Mach-O section parsing.
//!
//! Iterates Mach-O segments and sections, mapping the native
//! (segment, section) naming convention to ELF-like flat names
//! (e.g. `__TEXT,__text` becomes `.text`).

use crate::types::Section;

/// Extract sections from a parsed Mach-O, mapping names to ELF-like format.
pub fn get_sections(
    macho: &goblin::mach::MachO,
) -> Vec<Section> {
    let mut secs = Vec::new();
    for seg in &macho.segments {
        let seg_name = seg_name_str(seg);
        for (sec, _data) in seg.sections().unwrap_or_default() {
            let name = map_section_name(&seg_name, &sec);
            let size = sec.size;
            if size == 0 {
                continue;
            }
            secs.push(Section {
                name,
                size,
                vaddr: sec.addr,
                offset: sec.offset as u64,
                align: 1u64 << sec.align,
            });
        }
    }
    secs
}

/// Extract the segment name as a String.
fn seg_name_str(
    seg: &goblin::mach::segment::Segment,
) -> String {
    seg.name().unwrap_or("").to_string()
}

/// Map Mach-O (segment, section) to a flat name.
fn map_section_name(
    seg: &str,
    sec: &goblin::mach::segment::Section,
) -> String {
    let sec_name = sec.name().unwrap_or("").to_string();
    match (seg, sec_name.as_str()) {
        ("__TEXT" | "", "__text") => ".text".to_string(),
        ("__TEXT" | "", "__stubs") => ".plt".to_string(),
        ("__TEXT" | "", "__cstring") => ".rodata".to_string(),
        ("__TEXT" | "", "__const") => {
            ".rodata.const".to_string()
        }
        ("__DATA" | "", "__data") => ".data".to_string(),
        ("__DATA", "__const") => ".data.const".to_string(),
        ("__DATA" | "", "__got") => ".got".to_string(),
        ("__DATA" | "", "__la_symbol_ptr") => {
            ".got.plt".to_string()
        }
        ("__DATA" | "", "__bss") => ".bss".to_string(),
        _ => format!("{},{}", seg, sec_name),
    }
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
