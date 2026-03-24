//! PE/COFF metadata patching after dead code compaction.
//!
//! Updates all PE structures affected by .text compaction: entry point,
//! section headers, COFF symbol table, export address table, base
//! relocations (.reloc), and exception handler table (.pdata).

use crate::patch::relocs::{page_shrink, total_shift};
use crate::types::Section;

// ---- PE header helpers -------------------------------------------

/// Return the file offset of the PE signature from the DOS header.
fn pe_offset(data: &[u8]) -> usize {
    if data.len() < 0x40 {
        return 0;
    }
    u32::from_le_bytes(
        data[0x3C..0x40].try_into().unwrap_or([0; 4]),
    ) as usize
}

/// Return true if the PE is PE32+ (64-bit, magic 0x020B).
fn is_pe64(data: &[u8]) -> bool {
    let off = pe_offset(data);
    if off + 26 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes(
        data[off + 24..off + 26].try_into().unwrap_or([0; 2]),
    );
    magic == 0x020B // PE32+
}

/// Read a little-endian u16 at `off`.
fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(
        data[off..off + 2].try_into().unwrap_or([0; 2]),
    )
}

/// Read a little-endian u32 at `off`.
fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    )
}

/// Write a little-endian u32 at `off`.
fn write_u32(data: &mut [u8], off: usize, val: u32) {
    if off + 4 <= data.len() {
        data[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
}

/// Read a little-endian u64 at `off`.
fn read_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(
        data[off..off + 8].try_into().unwrap_or([0; 8]),
    )
}

/// Write a little-endian u64 at `off`.
fn write_u64(data: &mut [u8], off: usize, val: u64) {
    if off + 8 <= data.len() {
        data[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }
}

// ---- Entry point ------------------------------------------------

/// Patch AddressOfEntryPoint in PE optional header.
pub fn patch_entry_point(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let pe_off = pe_offset(data);
    // AddressOfEntryPoint is at optional_header + 16
    // optional_header starts at pe_off + 24
    let ep_off = pe_off + 40; // 24 + 16
    if ep_off + 4 > data.len() {
        return;
    }
    let ep = read_u32(data, ep_off) as u64;
    let shift = total_shift(ep, intervals, ts, te);
    if shift > 0 {
        write_u32(data, ep_off, (ep - shift) as u32);
    }
}

// ---- Section headers --------------------------------------------

/// Patch PE section headers: update .text VirtualSize and
/// PointerToRawData for sections after .text.
pub fn patch_section_headers(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let pe_off = pe_offset(data);
    let is64 = is_pe64(data);
    let opt_hdr_size =
        read_u16(data, pe_off + 20) as usize;
    let num_sec =
        read_u16(data, pe_off + 6) as usize;
    let sec_hdr_base = pe_off + 24 + opt_hdr_size;
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
    for i in 0..num_sec {
        let base = sec_hdr_base + i * 40;
        if base + 40 > data.len() {
            break;
        }
        patch_one_sec_hdr(
            data, base, ts, te, ps, text_sec, text_file_end,
            intervals,
        );
    }
    // Update SizeOfCode in optional header
    let soc_off = pe_off + 28; // optional_header + 4
    let soc = read_u32(data, soc_off) as u64;
    if soc > ps {
        write_u32(data, soc_off, (soc - ps) as u32);
    }
    // Update SizeOfImage
    let soi_off = if is64 {
        pe_off + 24 + 56 // PE32+ offset
    } else {
        pe_off + 24 + 56
    };
    let soi = read_u32(data, soi_off) as u64;
    if soi > ps {
        write_u32(data, soi_off, (soi - ps) as u32);
    }
}

/// Patch a single PE section header: shrink .text sizes, shift
/// VirtualAddress if in .text range, and shift raw offsets after .text.
fn patch_one_sec_hdr(
    data: &mut [u8],
    base: usize,
    ts: u64,
    te: u64,
    ps: u64,
    text_sec: &Section,
    text_file_end: u64,
    intervals: &[(u64, u64)],
) {
    let va = read_u32(data, base + 12) as u64;
    let vsize = read_u32(data, base + 8) as u64;
    let raw_off = read_u32(data, base + 20) as u64;
    // Shrink .text virtual size
    let is_text = va == text_sec.vaddr;
    if is_text {
        write_u32(data, base + 8, (vsize - ps) as u32);
        let raw_sz = read_u32(data, base + 16) as u64;
        if raw_sz > ps {
            write_u32(data, base + 16, (raw_sz - ps) as u32);
        }
    }
    // Shift VirtualAddress for sections in .text range
    if va > 0 && va >= ts && va < te {
        let shift = total_shift(va, intervals, ts, te);
        if shift > 0 {
            write_u32(data, base + 12, (va - shift) as u32);
        }
    }
    // Shift file offset for sections after .text
    if raw_off >= text_file_end {
        write_u32(data, base + 20, (raw_off - ps) as u32);
    }
}

// ---- COFF symbol table ------------------------------------------

/// Patch COFF symbol st_value entries.
pub fn patch_symbols(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let pe_off = pe_offset(data);
    if pe_off + 16 > data.len() {
        return;
    }
    let sym_ptr =
        read_u32(data, pe_off + 12) as usize;
    let sym_cnt =
        read_u32(data, pe_off + 16) as usize;
    if sym_ptr == 0 || sym_cnt == 0 {
        return;
    }
    for i in 0..sym_cnt {
        let off = sym_ptr + i * 18;
        if off + 18 > data.len() {
            break;
        }
        let val = read_u32(data, off + 8) as u64;
        if val == 0 {
            continue;
        }
        let shift = total_shift(val, intervals, ts, te);
        if shift > 0 {
            write_u32(
                data, off + 8, (val - shift) as u32,
            );
        }
    }
}

// ---- Export directory -------------------------------------------

/// Patch Export Address Table RVAs for shifted functions.
pub fn patch_exports(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let pe_off = pe_offset(data);
    let is64 = is_pe64(data);
    // Data directory 0 = Export Table
    let dd_off = if is64 {
        pe_off + 24 + 112 // PE32+: opt_hdr + 112
    } else {
        pe_off + 24 + 96 // PE32: opt_hdr + 96
    };
    if dd_off + 8 > data.len() {
        return;
    }
    let exp_rva = read_u32(data, dd_off) as u64;
    let exp_size = read_u32(data, dd_off + 4) as u64;
    if exp_rva == 0 || exp_size == 0 {
        return;
    }
    let exp_foff = match rva_to_offset(exp_rva, sections) {
        Some(o) => o as usize,
        None => return,
    };
    if exp_foff + 40 > data.len() {
        return;
    }
    let num_funcs = read_u32(data, exp_foff + 20) as usize;
    let eat_rva = read_u32(data, exp_foff + 28) as u64;
    let eat_foff = match rva_to_offset(eat_rva, sections) {
        Some(o) => o as usize,
        None => return,
    };
    for i in 0..num_funcs {
        let off = eat_foff + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let rva = read_u32(data, off) as u64;
        if rva == 0 {
            continue;
        }
        let shift = total_shift(rva, intervals, ts, te);
        if shift > 0 {
            write_u32(data, off, (rva - shift) as u32);
        }
    }
}

// ---- Base relocations -------------------------------------------

/// Patch .reloc base relocation table: update entries that
/// point into shifted .text addresses.
pub fn patch_base_relocs(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let reloc_sec =
        match sections.iter().find(|s| s.name == ".reloc") {
            Some(s) => s,
            None => return,
        };
    let is64 = is_pe64(data);
    let mut pos = reloc_sec.offset as usize;
    let end =
        (reloc_sec.offset + reloc_sec.size) as usize;
    while pos + 8 <= end && pos + 8 <= data.len() {
        let page_rva = read_u32(data, pos) as u64;
        let block_size = read_u32(data, pos + 4) as usize;
        if block_size < 8 || pos + block_size > data.len() {
            break;
        }
        let entry_count = (block_size - 8) / 2;
        for i in 0..entry_count {
            let eoff = pos + 8 + i * 2;
            if eoff + 2 > data.len() {
                break;
            }
            let entry = read_u16(data, eoff);
            let rtype = (entry >> 12) & 0xF;
            let offset = (entry & 0xFFF) as u64;
            let target_rva = page_rva + offset;
            // Type 3 = HIGHLOW (32-bit), Type 10 = DIR64 (64-bit)
            if rtype == 3 || rtype == 10 {
                patch_reloc_target(
                    data, sections, target_rva, intervals,
                    ts, te, is64, rtype,
                );
            }
        }
        pos += block_size;
    }
}

/// Patch a single base relocation target (HIGHLOW or DIR64).
fn patch_reloc_target(
    data: &mut [u8],
    sections: &[Section],
    target_rva: u64,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
    _is64: bool,
    rtype: u16,
) {
    let foff = match rva_to_offset(target_rva, sections) {
        Some(o) => o as usize,
        None => return,
    };
    if rtype == 3 {
        // HIGHLOW: 32-bit absolute address
        if foff + 4 > data.len() {
            return;
        }
        let val = read_u32(data, foff) as u64;
        let shift = total_shift(val, intervals, ts, te);
        if shift > 0 {
            write_u32(data, foff, (val - shift) as u32);
        }
    } else if rtype == 10 {
        // DIR64: 64-bit absolute address
        if foff + 8 > data.len() {
            return;
        }
        let val = read_u64(data, foff);
        let shift = total_shift(val, intervals, ts, te);
        if shift > 0 {
            write_u64(data, foff, val - shift);
        }
    }
}

// ---- .pdata (exception handlers) --------------------------------

/// Patch .pdata RUNTIME_FUNCTION entries.
pub fn patch_pdata(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let pdata =
        match sections.iter().find(|s| s.name == ".pdata") {
            Some(s) => s,
            None => return,
        };
    let mut pos = pdata.offset as usize;
    let end = (pdata.offset + pdata.size) as usize;
    // Each RUNTIME_FUNCTION is 12 bytes:
    // [0..4] BeginAddress (RVA)
    // [4..8] EndAddress (RVA)
    // [8..12] UnwindInfoAddress (RVA)
    while pos + 12 <= end && pos + 12 <= data.len() {
        let begin = read_u32(data, pos) as u64;
        let end_addr = read_u32(data, pos + 4) as u64;
        if begin == 0 && end_addr == 0 {
            pos += 12;
            continue;
        }
        let s1 = total_shift(begin, intervals, ts, te);
        if s1 > 0 {
            write_u32(data, pos, (begin - s1) as u32);
        }
        let s2 = total_shift(end_addr, intervals, ts, te);
        if s2 > 0 {
            write_u32(data, pos + 4, (end_addr - s2) as u32);
        }
        // UnwindInfoAddress: shift if in .text range
        let unwind = read_u32(data, pos + 8) as u64;
        let s3 = total_shift(unwind, intervals, ts, te);
        if s3 > 0 {
            write_u32(data, pos + 8, (unwind - s3) as u32);
        }
        pos += 12;
    }
}

// ---- Helper: RVA to file offset ---------------------------------

/// Convert an RVA to a file offset using section mappings.
fn rva_to_offset(rva: u64, sections: &[Section]) -> Option<u64> {
    for sec in sections {
        if rva >= sec.vaddr && rva < sec.vaddr + sec.size {
            return Some(sec.offset + (rva - sec.vaddr));
        }
    }
    None
}
