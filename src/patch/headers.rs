use crate::patch::relocs::{page_shrink, total_shift};
use crate::types::Section;

/// Patch ELF section headers, program headers, and e_shoff.
pub fn patch_headers(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return;
    }
    if data[4] != 2 {
        return; // Only 64-bit supported
    }
    let ps = page_shrink(intervals);
    if ps == 0 {
        return; // No page-aligned bytes to remove
    }
    let text_sec = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return,
    };
    let text_file_end = text_sec.offset + text_sec.size;
    patch_section_headers(
        data, intervals, ts, te, ps, text_sec, text_file_end,
    );
    patch_program_headers(
        data, intervals, ts, te, ps, text_sec, text_file_end,
    );
    patch_elf_shoff(data, ps, text_file_end);
}

fn patch_section_headers(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    let e_shoff = read_u64(data, 40) as usize;
    let e_shnum = u16::from_le_bytes(
        data[60..62].try_into().unwrap_or([0; 2]),
    ) as usize;
    let sh_ent = 64usize;
    for idx in 0..e_shnum {
        let base = e_shoff + idx * sh_ent;
        if base + sh_ent > data.len() {
            break;
        }
        patch_one_shdr(
            data, base, intervals, ts, te, ps, text_sec,
            text_file_end,
        );
    }
}

fn patch_one_shdr(
    data: &mut [u8],
    base: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    let sh_addr = read_u64(data, base + 16);
    let sh_offset = read_u64(data, base + 24);
    let sh_size_val = read_u64(data, base + 32);
    if sh_addr > 0 {
        let shift = total_shift(sh_addr, intervals, ts, te);
        if shift > 0 {
            write_u64(data, base + 16, sh_addr - shift);
        }
    }
    let is_text = sh_addr == text_sec.vaddr
        && sh_offset == text_sec.offset;
    if is_text {
        write_u64(data, base + 32, sh_size_val - ps);
    }
    if sh_offset >= text_file_end {
        write_u64(data, base + 24, sh_offset - ps);
    }
}

fn patch_program_headers(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    let e_phoff = read_u64(data, 32) as usize;
    let e_phnum = u16::from_le_bytes(
        data[56..58].try_into().unwrap_or([0; 2]),
    ) as usize;
    let ph_ent = 56usize;
    for idx in 0..e_phnum {
        let base = e_phoff + idx * ph_ent;
        if base + ph_ent > data.len() {
            break;
        }
        patch_one_phdr(
            data, base, intervals, ts, te, ps, text_sec,
            text_file_end,
        );
    }
}

fn patch_one_phdr(
    data: &mut [u8],
    base: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    let p_offset = read_u64(data, base + 8);
    let p_vaddr = read_u64(data, base + 16);
    let p_paddr = read_u64(data, base + 24);
    let p_filesz = read_u64(data, base + 32);
    let p_memsz = read_u64(data, base + 40);
    let contains_text =
        p_vaddr <= ts && te <= p_vaddr + p_memsz;
    if contains_text {
        write_u64(data, base + 32, p_filesz - ps);
        write_u64(data, base + 40, p_memsz - ps);
    }
    if p_vaddr > 0 {
        let shift = total_shift(p_vaddr, intervals, ts, te);
        if shift > 0 {
            write_u64(data, base + 16, p_vaddr - shift);
            write_u64(data, base + 24, p_paddr - shift);
        }
    }
    if p_offset >= text_file_end {
        write_u64(data, base + 8, p_offset - ps);
    }
}

fn patch_elf_shoff(data: &mut [u8], ps: u64, text_file_end: u64) {
    let e_shoff = read_u64(data, 40);
    if e_shoff >= text_file_end {
        write_u64(data, 40, e_shoff - ps);
    }
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(
        data[off..off + 8].try_into().unwrap_or([0; 8]),
    )
}

fn write_u64(data: &mut [u8], off: usize, val: u64) {
    if off + 8 <= data.len() {
        data[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }
}
