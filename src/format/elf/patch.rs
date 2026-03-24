use crate::patch::relocs::{page_shrink, total_shift};
use crate::types::Section;

// ---- Endian helpers -----------------------------------------------

fn elf_be(data: &[u8]) -> bool {
    data.len() > 5 && data[5] == 2
}

fn read_u16e(data: &[u8], off: usize, be: bool) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    let b: [u8; 2] =
        data[off..off + 2].try_into().unwrap_or([0; 2]);
    if be { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }
}

fn read_u32e(data: &[u8], off: usize, be: bool) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    let b: [u8; 4] =
        data[off..off + 4].try_into().unwrap_or([0; 4]);
    if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
}

fn read_u64e(data: &[u8], off: usize, be: bool) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    let b: [u8; 8] =
        data[off..off + 8].try_into().unwrap_or([0; 8]);
    if be { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }
}

fn write_u32e(data: &mut [u8], off: usize, val: u32, be: bool) {
    if off + 4 <= data.len() {
        let b = if be {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        data[off..off + 4].copy_from_slice(&b);
    }
}

fn write_u64e(data: &mut [u8], off: usize, val: u64, be: bool) {
    if off + 8 <= data.len() {
        let b = if be {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        data[off..off + 8].copy_from_slice(&b);
    }
}

fn read_i64e(data: &[u8], off: usize, be: bool) -> i64 {
    if off + 8 > data.len() {
        return 0;
    }
    let b: [u8; 8] =
        data[off..off + 8].try_into().unwrap_or([0; 8]);
    if be { i64::from_be_bytes(b) } else { i64::from_le_bytes(b) }
}

fn write_i64e(data: &mut [u8], off: usize, val: i64, be: bool) {
    if off + 8 <= data.len() {
        let b = if be {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        data[off..off + 8].copy_from_slice(&b);
    }
}

// ---- Entry point ------------------------------------------------

/// Patch ELF entry point if it shifted due to compaction.
pub fn patch_entry_point(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return;
    }
    let be = elf_be(data);
    let is64 = data[4] == 2;
    let (off, sz) =
        if is64 { (24usize, 8usize) } else { (24, 4) };
    if off + sz > data.len() {
        return;
    }
    let entry = read_entry(data, off, is64, be);
    let shift = total_shift(entry, intervals, ts, te);
    if shift > 0 {
        write_entry(data, off, entry - shift, is64, be);
    }
}

fn read_entry(
    data: &[u8],
    off: usize,
    is64: bool,
    be: bool,
) -> u64 {
    if is64 {
        read_u64e(data, off, be)
    } else {
        read_u32e(data, off, be) as u64
    }
}

fn write_entry(
    data: &mut [u8],
    off: usize,
    val: u64,
    is64: bool,
    be: bool,
) {
    if is64 {
        write_u64e(data, off, val, be);
    } else {
        write_u32e(data, off, val as u32, be);
    }
}

// ---- .rela.dyn / .rela.plt -------------------------------------

/// Patch .rela.dyn: update r_offset and RELATIVE addends.
pub fn patch_rela_dyn(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let be = elf_be(data);
    for sec in sections {
        if sec.name != ".rela.dyn" && sec.name != ".rela.plt" {
            continue;
        }
        let entry_size = 24usize;
        let mut i = sec.offset as usize;
        let end = i + sec.size as usize;
        while i + entry_size <= end
            && i + entry_size <= data.len()
        {
            patch_rela_entry(data, i, intervals, ts, te, be);
            i += entry_size;
        }
    }
}

fn patch_rela_entry(
    data: &mut [u8],
    i: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    be: bool,
) {
    let r_offset = read_u64e(data, i, be);
    let off_shift = total_shift(r_offset, intervals, ts, te);
    if off_shift > 0 {
        let new_off = r_offset - off_shift;
        write_u64e(data, i, new_off, be);
    }
    let r_info = read_u64e(data, i + 8, be);
    if (r_info & 0xFFFFFFFF) == 8 {
        let addend = read_i64e(data, i + 16, be);
        let a = addend as u64;
        let shift = total_shift(a, intervals, ts, te);
        if shift > 0 {
            let new_addend = addend - shift as i64;
            write_i64e(data, i + 16, new_addend, be);
        }
    }
}

// ---- Symbol tables ----------------------------------------------

/// Patch st_value in .symtab and .dynsym.
pub fn patch_symbols(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let be = elf_be(data);
    for sec in sections {
        if sec.name != ".symtab" && sec.name != ".dynsym" {
            continue;
        }
        patch_symtab(data, sec, intervals, ts, te, be);
    }
}

fn patch_symtab(
    data: &mut [u8],
    sec: &Section,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    be: bool,
) {
    let is64 = data.len() > 4 && data[4] == 2;
    let (entry_sz, val_off, val_sz) = if is64 {
        (24usize, 8usize, 8usize)
    } else {
        (16usize, 4usize, 4usize)
    };
    let end =
        (sec.offset as usize + sec.size as usize).min(data.len());
    let mut i = sec.offset as usize;
    while i + entry_sz <= end {
        patch_one_sym(
            data, i, val_off, val_sz, is64, intervals, ts, te,
            be,
        );
        i += entry_sz;
    }
}

fn patch_one_sym(
    data: &mut [u8],
    i: usize,
    val_off: usize,
    _val_sz: usize,
    is64: bool,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    be: bool,
) {
    let val = if is64 {
        read_u64e(data, i + val_off, be)
    } else {
        read_u32e(data, i + val_off, be) as u64
    };
    if val == 0 {
        return;
    }
    let shift = total_shift(val, intervals, ts, te);
    if shift == 0 {
        return;
    }
    let new_val = val - shift;
    if is64 {
        write_u64e(data, i + val_off, new_val, be);
    } else {
        write_u32e(data, i + val_off, new_val as u32, be);
    }
}

// ---- .dynamic ---------------------------------------------------

const ADDR_TAGS: &[u64] = &[
    3,          // DT_PLTGOT
    4,          // DT_HASH
    5,          // DT_STRTAB
    6,          // DT_SYMTAB
    7,          // DT_RELA
    12,         // DT_INIT
    13,         // DT_FINI
    23,         // DT_JMPREL
    25,         // DT_INIT_ARRAY
    26,         // DT_FINI_ARRAY
    0x6ffffef5, // DT_GNU_HASH
    0x6ffffff0, // DT_VERSYM
    0x6ffffffe, // DT_VERNEED
];

/// Patch .dynamic section: shift address-type DT_* values.
pub fn patch_dynamic(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let be = elf_be(data);
    for sec in sections {
        if sec.name != ".dynamic" {
            continue;
        }
        let entry_sz = 16usize;
        let mut i = sec.offset as usize;
        let end = (sec.offset as usize + sec.size as usize)
            .min(data.len());
        while i + entry_sz <= end {
            let d_tag = read_u64e(data, i, be);
            if d_tag == 0 {
                break;
            }
            if ADDR_TAGS.contains(&d_tag) {
                patch_dyn_val(data, i + 8, intervals, ts, te, be);
            }
            i += entry_sz;
        }
    }
}

fn patch_dyn_val(
    data: &mut [u8],
    off: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    be: bool,
) {
    let d_val = read_u64e(data, off, be);
    if d_val == 0 {
        return;
    }
    let shift = total_shift(d_val, intervals, ts, te);
    if shift > 0 {
        let new_val = d_val - shift;
        write_u64e(data, off, new_val, be);
    }
}

// ---- Section & program headers ----------------------------------

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
        return;
    }
    let be = elf_be(data);
    let ps = page_shrink(intervals);
    if ps == 0 {
        return;
    }
    let text_sec =
        match sections.iter().find(|s| s.name == ".text") {
            Some(s) => s,
            None => return,
        };
    let text_file_end = text_sec.offset + text_sec.size;
    patch_shdrs(
        data, intervals, ts, te, ps, text_sec, text_file_end, be,
    );
    patch_phdrs(
        data, intervals, ts, te, ps, text_sec, text_file_end, be,
    );
    patch_elf_shoff(data, ps, text_file_end, be);
}

fn patch_shdrs(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
    be: bool,
) {
    let e_shoff = read_u64e(data, 40, be) as usize;
    let e_shnum = read_u16e(data, 60, be) as usize;
    for idx in 0..e_shnum {
        let base = e_shoff + idx * 64;
        if base + 64 > data.len() {
            break;
        }
        patch_one_shdr(
            data, base, intervals, ts, te, ps, text_sec,
            text_file_end, be,
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
    be: bool,
) {
    let sh_addr = read_u64e(data, base + 16, be);
    let sh_offset = read_u64e(data, base + 24, be);
    let sh_size_val = read_u64e(data, base + 32, be);
    if sh_addr > 0 {
        let shift = total_shift(sh_addr, intervals, ts, te);
        if shift > 0 {
            write_u64e(data, base + 16, sh_addr - shift, be);
        }
    }
    let is_text = sh_addr == text_sec.vaddr
        && sh_offset == text_sec.offset;
    if is_text {
        write_u64e(data, base + 32, sh_size_val - ps, be);
    }
    if sh_offset >= text_file_end {
        write_u64e(data, base + 24, sh_offset - ps, be);
    }
}

fn patch_phdrs(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
    be: bool,
) {
    let e_phoff = read_u64e(data, 32, be) as usize;
    let e_phnum = read_u16e(data, 56, be) as usize;
    for idx in 0..e_phnum {
        let base = e_phoff + idx * 56;
        if base + 56 > data.len() {
            break;
        }
        patch_one_phdr(
            data, base, intervals, ts, te, ps, text_sec,
            text_file_end, be,
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
    _text_sec: &Section,
    text_file_end: u64,
    be: bool,
) {
    let p_offset = read_u64e(data, base + 8, be);
    let p_vaddr = read_u64e(data, base + 16, be);
    let p_paddr = read_u64e(data, base + 24, be);
    let p_filesz = read_u64e(data, base + 32, be);
    let p_memsz = read_u64e(data, base + 40, be);
    let contains_text =
        p_vaddr <= ts && te <= p_vaddr + p_memsz;
    if contains_text {
        write_u64e(data, base + 32, p_filesz - ps, be);
        write_u64e(data, base + 40, p_memsz - ps, be);
    }
    if p_vaddr > 0 {
        let shift = total_shift(p_vaddr, intervals, ts, te);
        if shift > 0 {
            write_u64e(data, base + 16, p_vaddr - shift, be);
            write_u64e(data, base + 24, p_paddr - shift, be);
        }
    }
    if p_offset >= text_file_end {
        write_u64e(data, base + 8, p_offset - ps, be);
    }
}

fn patch_elf_shoff(
    data: &mut [u8],
    ps: u64,
    text_file_end: u64,
    be: bool,
) {
    let e_shoff = read_u64e(data, 40, be);
    if e_shoff >= text_file_end {
        write_u64e(data, 40, e_shoff - ps, be);
    }
}
