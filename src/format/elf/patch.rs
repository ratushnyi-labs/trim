use crate::patch::relocs::{page_shrink, total_shift};
use crate::types::Section;

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
    let is64 = data[4] == 2;
    let (off, sz) =
        if is64 { (24usize, 8usize) } else { (24, 4) };
    if off + sz > data.len() {
        return;
    }
    let entry = read_entry(data, off, is64);
    let shift = total_shift(entry, intervals, ts, te);
    if shift > 0 {
        write_entry(data, off, entry - shift, is64);
    }
}

fn read_entry(data: &[u8], off: usize, is64: bool) -> u64 {
    if is64 {
        u64::from_le_bytes(
            data[off..off + 8].try_into().unwrap_or([0; 8]),
        )
    } else {
        u32::from_le_bytes(
            data[off..off + 4].try_into().unwrap_or([0; 4]),
        ) as u64
    }
}

fn write_entry(
    data: &mut [u8],
    off: usize,
    val: u64,
    is64: bool,
) {
    if is64 {
        data[off..off + 8]
            .copy_from_slice(&val.to_le_bytes());
    } else {
        data[off..off + 4]
            .copy_from_slice(&(val as u32).to_le_bytes());
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
            patch_rela_entry(data, i, intervals, ts, te);
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
) {
    let r_offset = u64::from_le_bytes(
        data[i..i + 8].try_into().unwrap_or([0; 8]),
    );
    let off_shift = total_shift(r_offset, intervals, ts, te);
    if off_shift > 0 {
        let new_off = r_offset - off_shift;
        data[i..i + 8].copy_from_slice(&new_off.to_le_bytes());
    }
    let r_info = u64::from_le_bytes(
        data[i + 8..i + 16].try_into().unwrap_or([0; 8]),
    );
    if (r_info & 0xFFFFFFFF) == 8 {
        let addend = i64::from_le_bytes(
            data[i + 16..i + 24].try_into().unwrap_or([0; 8]),
        );
        let a = addend as u64;
        let shift = total_shift(a, intervals, ts, te);
        if shift > 0 {
            let new_addend = addend - shift as i64;
            data[i + 16..i + 24]
                .copy_from_slice(&new_addend.to_le_bytes());
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
    for sec in sections {
        if sec.name != ".symtab" && sec.name != ".dynsym" {
            continue;
        }
        patch_symtab(data, sec, intervals, ts, te);
    }
}

fn patch_symtab(
    data: &mut [u8],
    sec: &Section,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
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
) {
    let val = if is64 {
        u64::from_le_bytes(
            data[i + val_off..i + val_off + 8]
                .try_into()
                .unwrap_or([0; 8]),
        )
    } else {
        u32::from_le_bytes(
            data[i + val_off..i + val_off + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as u64
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
        data[i + val_off..i + val_off + 8]
            .copy_from_slice(&new_val.to_le_bytes());
    } else {
        data[i + val_off..i + val_off + 4]
            .copy_from_slice(&(new_val as u32).to_le_bytes());
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
    for sec in sections {
        if sec.name != ".dynamic" {
            continue;
        }
        let entry_sz = 16usize;
        let mut i = sec.offset as usize;
        let end = (sec.offset as usize + sec.size as usize)
            .min(data.len());
        while i + entry_sz <= end {
            let d_tag = u64::from_le_bytes(
                data[i..i + 8].try_into().unwrap_or([0; 8]),
            );
            if d_tag == 0 {
                break;
            }
            if ADDR_TAGS.contains(&d_tag) {
                patch_dyn_val(data, i + 8, intervals, ts, te);
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
) {
    let d_val = u64::from_le_bytes(
        data[off..off + 8].try_into().unwrap_or([0; 8]),
    );
    if d_val == 0 {
        return;
    }
    let shift = total_shift(d_val, intervals, ts, te);
    if shift > 0 {
        let new_val = d_val - shift;
        data[off..off + 8]
            .copy_from_slice(&new_val.to_le_bytes());
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
        data, intervals, ts, te, ps, text_sec, text_file_end,
    );
    patch_phdrs(
        data, intervals, ts, te, ps, text_sec, text_file_end,
    );
    patch_elf_shoff(data, ps, text_file_end);
}

fn patch_shdrs(
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
    for idx in 0..e_shnum {
        let base = e_shoff + idx * 64;
        if base + 64 > data.len() {
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

fn patch_phdrs(
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
    for idx in 0..e_phnum {
        let base = e_phoff + idx * 56;
        if base + 56 > data.len() {
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

fn patch_elf_shoff(
    data: &mut [u8],
    ps: u64,
    text_file_end: u64,
) {
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
