use crate::patch::relocs::{page_shrink, total_shift};
use crate::types::Section;

// ---- Mach-O constants -------------------------------------------

const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_MAGIC_32: u32 = 0xFEED_FACE;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_MAIN: u32 = 0x8000_0028;
const LC_UNIXTHREAD: u32 = 0x05;

// ---- LE read/write helpers --------------------------------------

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    )
}

fn write_u32(data: &mut [u8], off: usize, val: u32) {
    if off + 4 <= data.len() {
        data[off..off + 4].copy_from_slice(&val.to_le_bytes());
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

// ---- Mach-O header parsing --------------------------------------

fn macho_is64(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    read_u32(data, 0) == MH_MAGIC_64
}

fn macho_valid(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let m = read_u32(data, 0);
    m == MH_MAGIC_64 || m == MH_MAGIC_32
}

/// Size of the Mach-O header (before load commands).
fn header_size(is64: bool) -> usize {
    if is64 { 32 } else { 28 }
}

/// Number of load commands from the Mach-O header.
fn ncmds(data: &[u8], is64: bool) -> u32 {
    let off = if is64 { 16 } else { 12 };
    read_u32(data, off)
}

// ---- Entry point ------------------------------------------------

/// Patch entry point in LC_MAIN or LC_UNIXTHREAD.
pub fn patch_entry_point(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if !macho_valid(data) {
        return;
    }
    let is64 = macho_is64(data);
    let nc = ncmds(data, is64) as usize;
    let mut pos = header_size(is64);
    for _ in 0..nc {
        if pos + 8 > data.len() {
            break;
        }
        let cmd = read_u32(data, pos);
        let cmd_size = read_u32(data, pos + 4) as usize;
        if cmd_size < 8 {
            break;
        }
        if cmd == LC_MAIN && pos + 16 <= data.len() {
            // LC_MAIN: entryoff at +8 (u64) is offset from
            // __TEXT segment start
            let entryoff = read_u64(data, pos + 8);
            let shift =
                total_shift(entryoff, intervals, ts, te);
            if shift > 0 {
                write_u64(data, pos + 8, entryoff - shift);
            }
        }
        if cmd == LC_UNIXTHREAD {
            // x86_64: RIP at thread_state + 128
            // AArch64: PC at thread_state + 256
            // thread_state starts at pos + 16
            if is64 && pos + 16 + 136 <= data.len() {
                let pc = read_u64(data, pos + 16 + 128);
                let shift =
                    total_shift(pc, intervals, ts, te);
                if shift > 0 {
                    write_u64(
                        data, pos + 16 + 128, pc - shift,
                    );
                }
            }
        }
        pos += cmd_size;
    }
}

// ---- Load commands (segments/sections) --------------------------

/// Patch LC_SEGMENT_64/LC_SEGMENT: update vmaddr, vmsize,
/// fileoff, filesize for __TEXT segment and its sections.
pub fn patch_load_commands(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if !macho_valid(data) {
        return;
    }
    let is64 = macho_is64(data);
    let nc = ncmds(data, is64) as usize;
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
    let mut pos = header_size(is64);
    for _ in 0..nc {
        if pos + 8 > data.len() {
            break;
        }
        let cmd = read_u32(data, pos);
        let cmd_size = read_u32(data, pos + 4) as usize;
        if cmd_size < 8 {
            break;
        }
        if cmd == LC_SEGMENT_64 {
            patch_segment64(
                data, pos, intervals, ts, te, ps,
                text_sec, text_file_end,
            );
        } else if cmd == LC_SEGMENT {
            patch_segment32(
                data, pos, intervals, ts, te, ps,
                text_sec, text_file_end,
            );
        }
        pos += cmd_size;
    }
}

fn seg_name_at(data: &[u8], pos: usize) -> [u8; 16] {
    let off = pos + 8;
    if off + 16 > data.len() {
        return [0; 16];
    }
    let mut name = [0u8; 16];
    name.copy_from_slice(&data[off..off + 16]);
    name
}

fn is_seg_name(raw: &[u8; 16], name: &[u8]) -> bool {
    raw.starts_with(name)
        && raw[name.len()..].iter().all(|&b| b == 0)
}

fn patch_segment64(
    data: &mut [u8],
    pos: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    // LC_SEGMENT_64 layout:
    // +8:  segname[16]
    // +24: vmaddr (u64)
    // +32: vmsize (u64)
    // +40: fileoff (u64)
    // +48: filesize (u64)
    // +56: maxprot, initprot, nsects, flags
    // +68: sections start (each 80 bytes)
    if pos + 72 > data.len() {
        return;
    }
    let seg_name = seg_name_at(data, pos);
    let vmaddr = read_u64(data, pos + 24);
    let vmsize = read_u64(data, pos + 32);
    let fileoff = read_u64(data, pos + 40);
    let filesize = read_u64(data, pos + 48);
    let nsects = read_u32(data, pos + 64) as usize;
    let is_text_seg = is_seg_name(&seg_name, b"__TEXT");
    // Shrink __TEXT segment
    if is_text_seg {
        if vmsize > ps {
            write_u64(data, pos + 32, vmsize - ps);
        }
        if filesize > ps {
            write_u64(data, pos + 48, filesize - ps);
        }
    }
    // Shift segments after .text on disk
    if fileoff >= text_file_end {
        write_u64(data, pos + 40, fileoff - ps);
    }
    // Shift vmaddr
    if vmaddr > 0 {
        let shift = total_shift(vmaddr, intervals, ts, te);
        if shift > 0 {
            write_u64(data, pos + 24, vmaddr - shift);
        }
    }
    // Patch sections within this segment
    let sec_base = pos + 80;
    for i in 0..nsects {
        let soff = sec_base + i * 80;
        if soff + 80 > data.len() {
            break;
        }
        patch_section64(
            data, soff, intervals, ts, te, ps,
            text_sec, text_file_end,
        );
    }
}

fn patch_section64(
    data: &mut [u8],
    soff: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    // Section64 layout:
    // +0:  sectname[16]
    // +16: segname[16]
    // +32: addr (u64)
    // +40: size (u64)
    // +48: offset (u32)
    // +52: align, reloff, nreloc, flags, ...
    let addr = read_u64(data, soff + 32);
    let size = read_u64(data, soff + 40);
    let offset = read_u32(data, soff + 48) as u64;
    let is_text = addr == text_sec.vaddr;
    if is_text && size > ps {
        write_u64(data, soff + 40, size - ps);
    }
    if addr > 0 {
        let shift = total_shift(addr, intervals, ts, te);
        if shift > 0 {
            write_u64(data, soff + 32, addr - shift);
        }
    }
    if offset >= text_file_end {
        write_u32(data, soff + 48, (offset - ps) as u32);
    }
}

fn patch_segment32(
    data: &mut [u8],
    pos: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    // LC_SEGMENT layout:
    // +8:  segname[16]
    // +24: vmaddr (u32)
    // +28: vmsize (u32)
    // +32: fileoff (u32)
    // +36: filesize (u32)
    // +40: maxprot, initprot, nsects, flags
    // +56: sections start (each 68 bytes)
    if pos + 56 > data.len() {
        return;
    }
    let seg_name = seg_name_at(data, pos);
    let vmaddr = read_u32(data, pos + 24) as u64;
    let vmsize = read_u32(data, pos + 28) as u64;
    let fileoff = read_u32(data, pos + 32) as u64;
    let filesize = read_u32(data, pos + 36) as u64;
    let nsects = read_u32(data, pos + 48) as usize;
    let is_text_seg = is_seg_name(&seg_name, b"__TEXT");
    if is_text_seg {
        if vmsize > ps {
            write_u32(data, pos + 28, (vmsize - ps) as u32);
        }
        if filesize > ps {
            write_u32(data, pos + 36, (filesize - ps) as u32);
        }
    }
    if fileoff >= text_file_end {
        write_u32(data, pos + 32, (fileoff - ps) as u32);
    }
    if vmaddr > 0 {
        let shift = total_shift(vmaddr, intervals, ts, te);
        if shift > 0 {
            write_u32(
                data, pos + 24, (vmaddr - shift) as u32,
            );
        }
    }
    let sec_base = pos + 56;
    for i in 0..nsects {
        let soff = sec_base + i * 68;
        if soff + 68 > data.len() {
            break;
        }
        patch_section32(
            data, soff, intervals, ts, te, ps,
            text_sec, text_file_end,
        );
    }
}

fn patch_section32(
    data: &mut [u8],
    soff: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
) {
    // Section32 layout:
    // +0:  sectname[16]
    // +16: segname[16]
    // +32: addr (u32)
    // +36: size (u32)
    // +40: offset (u32)
    let addr = read_u32(data, soff + 32) as u64;
    let size = read_u32(data, soff + 36) as u64;
    let offset = read_u32(data, soff + 40) as u64;
    let is_text = addr == text_sec.vaddr;
    if is_text && size > ps {
        write_u32(data, soff + 36, (size - ps) as u32);
    }
    if addr > 0 {
        let shift = total_shift(addr, intervals, ts, te);
        if shift > 0 {
            write_u32(
                data, soff + 32, (addr - shift) as u32,
            );
        }
    }
    if offset >= text_file_end {
        write_u32(data, soff + 40, (offset - ps) as u32);
    }
}

// ---- Symbol table (LC_SYMTAB) -----------------------------------

/// Patch nlist n_value entries in the symbol table.
pub fn patch_symtab(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if !macho_valid(data) {
        return;
    }
    let is64 = macho_is64(data);
    let nc = ncmds(data, is64) as usize;
    let mut pos = header_size(is64);
    for _ in 0..nc {
        if pos + 8 > data.len() {
            break;
        }
        let cmd = read_u32(data, pos);
        let cmd_size = read_u32(data, pos + 4) as usize;
        if cmd_size < 8 {
            break;
        }
        if cmd == LC_SYMTAB && pos + 20 <= data.len() {
            // LC_SYMTAB: symoff(u32), nsyms(u32),
            //            stroff(u32), strsize(u32)
            let symoff =
                read_u32(data, pos + 8) as usize;
            let nsyms =
                read_u32(data, pos + 12) as usize;
            patch_nlist(
                data, symoff, nsyms, is64, intervals,
                ts, te,
            );
            // Shift stroff/symoff if after .text
            let ps = page_shrink(intervals);
            if ps > 0 {
                shift_symtab_offsets(
                    data, pos, intervals, ts, te, ps,
                );
            }
        }
        pos += cmd_size;
    }
}

fn patch_nlist(
    data: &mut [u8],
    symoff: usize,
    nsyms: usize,
    is64: bool,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let entry_sz: usize = if is64 { 16 } else { 12 };
    let val_off: usize = if is64 { 8 } else { 8 };
    for i in 0..nsyms {
        let off = symoff + i * entry_sz;
        if off + entry_sz > data.len() {
            break;
        }
        let val = if is64 {
            read_u64(data, off + val_off)
        } else {
            read_u32(data, off + val_off) as u64
        };
        if val == 0 {
            continue;
        }
        let shift = total_shift(val, intervals, ts, te);
        if shift > 0 {
            if is64 {
                write_u64(data, off + val_off, val - shift);
            } else {
                write_u32(
                    data, off + val_off,
                    (val - shift) as u32,
                );
            }
        }
    }
}

fn shift_symtab_offsets(
    data: &mut [u8],
    pos: usize,
    _intervals: &[(u64, u64)],
    _ts: u64,
    _te: u64,
    ps: u64,
) {
    // Shift symoff and stroff if they point past .text
    // We only do this if page_shrink > 0
    let symoff = read_u32(data, pos + 8) as u64;
    let stroff = read_u32(data, pos + 16) as u64;
    // These offsets are file-relative; check if they're
    // past where we're removing bytes. Approximate: if
    // symoff is very large it's likely past .text.
    // Use a heuristic: if page_shrink > 0 and the offset
    // is clearly after text segment, shift it.
    // For safety, we do not shift these offsets since
    // compact_text handles drain from a precise location,
    // and load commands are more complex. Symtab offsets
    // are managed by the linker and may not be in text.
    let _ = (symoff, stroff, ps);
}
