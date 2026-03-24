//! AArch64 branch offset patching after dead code compaction.
//!
//! Rewrites B/BL (26-bit), B.cond/CBZ/CBNZ (19-bit), TBZ/TBNZ (14-bit),
//! ADRP (page-relative 21-bit), and ADR (PC-relative 21-bit) immediates
//! to account for address shifts caused by dead code removal.

use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is AArch64 padding (zero = UDF).
pub fn is_padding_aarch64(b: u8) -> bool {
    b == 0x00
}

/// Patch branch offsets in AArch64 instructions after dead code
/// removal shifts addresses.
pub fn patch_branches(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    for instr in instrs {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        patch_one(data, instr, intervals, sections, ts, te);
    }
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}

/// Patch a single AArch64 instruction's branch/PC-rel immediate.
fn patch_one(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    if instr.raw.len() < 4 {
        return;
    }
    let w = u32::from_le_bytes(
        instr.raw[..4].try_into().unwrap_or([0; 4]),
    );
    let foff = match vaddr_to_offset(instr.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };
    if foff + 4 > data.len() {
        return;
    }

    let op = w >> 26;
    // B (000101) or BL (100101) — 26-bit immediate
    if op == 0b000101 || op == 0b100101 {
        let imm26 = (w & 0x03FF_FFFF) as i32;
        let offset = (sign_extend(imm26, 26) as i64) << 2;
        let target = (instr.addr as i64 + offset) as u64;
        let shift_src =
            total_shift(instr.addr, intervals, ts, te) as i64;
        let shift_tgt =
            total_shift(target, intervals, ts, te) as i64;
        let delta = shift_src - shift_tgt;
        if delta == 0 {
            return;
        }
        let new_addr = instr.addr as i64 - shift_src;
        let new_target = target as i64 - shift_tgt;
        let new_offset = new_target - new_addr;
        let new_imm26 = (new_offset >> 2) as u32;
        let new_word =
            (w & 0xFC00_0000) | (new_imm26 & 0x03FF_FFFF);
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
        return;
    }

    // B.cond — 19-bit immediate
    if (w & 0xFF00_0010) == 0x5400_0000 {
        patch_branch19(data, instr, w, foff, intervals, ts, te);
        return;
    }

    // CBZ/CBNZ — 19-bit immediate
    if (w & 0x7E00_0000) == 0x3400_0000 {
        patch_branch19(data, instr, w, foff, intervals, ts, te);
        return;
    }

    // TBZ/TBNZ — 14-bit immediate
    if (w & 0x7E00_0000) == 0x3600_0000 {
        let imm14 = ((w >> 5) & 0x3FFF) as i32;
        let offset = (sign_extend(imm14, 14) as i64) << 2;
        let target = (instr.addr as i64 + offset) as u64;
        let shift_src =
            total_shift(instr.addr, intervals, ts, te) as i64;
        let shift_tgt =
            total_shift(target, intervals, ts, te) as i64;
        let delta = shift_src - shift_tgt;
        if delta == 0 {
            return;
        }
        let new_addr = instr.addr as i64 - shift_src;
        let new_target = target as i64 - shift_tgt;
        let new_offset = new_target - new_addr;
        let new_imm14 = (new_offset >> 2) as u32;
        let new_word =
            (w & 0xFFF8_001F) | ((new_imm14 & 0x3FFF) << 5);
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
        return;
    }

    // ADRP — page-relative 21-bit
    if (w & 0x9F00_0000) == 0x9000_0000 {
        let immhi = ((w >> 5) & 0x7FFFF) as i32;
        let immlo = ((w >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let offset = sign_extend(imm, 21) as i64;
        let page = (instr.addr & !0xFFF) as i64;
        let target = (page + (offset << 12)) as u64;
        let shift_src =
            total_shift(instr.addr, intervals, ts, te) as i64;
        let shift_tgt =
            total_shift(target, intervals, ts, te) as i64;
        let delta = shift_src - shift_tgt;
        if delta == 0 {
            return;
        }
        let new_addr = instr.addr as i64 - shift_src;
        let new_target = target as i64 - shift_tgt;
        let new_page = new_addr & !0xFFF;
        let new_page_delta = (new_target as i64 - new_page) >> 12;
        let new_imm = new_page_delta as u32;
        let new_immhi = (new_imm >> 2) & 0x7FFFF;
        let new_immlo = new_imm & 0x3;
        let new_word = (w & 0x9F00_001F)
            | (new_immhi << 5)
            | (new_immlo << 29);
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
        return;
    }

    // ADR — PC-relative 21-bit
    if (w & 0x9F00_0000) == 0x1000_0000 {
        let immhi = ((w >> 5) & 0x7FFFF) as i32;
        let immlo = ((w >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let offset = sign_extend(imm, 21) as i64;
        let target = (instr.addr as i64 + offset) as u64;
        let shift_src =
            total_shift(instr.addr, intervals, ts, te) as i64;
        let shift_tgt =
            total_shift(target, intervals, ts, te) as i64;
        let delta = shift_src - shift_tgt;
        if delta == 0 {
            return;
        }
        let new_addr = instr.addr as i64 - shift_src;
        let new_target = target as i64 - shift_tgt;
        let new_offset = new_target - new_addr;
        let new_imm = new_offset as u32;
        let new_immhi = (new_imm >> 2) & 0x7FFFF;
        let new_immlo = new_imm & 0x3;
        let new_word = (w & 0x9F00_001F)
            | (new_immhi << 5)
            | (new_immlo << 29);
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
    }
}

/// Patch a 19-bit branch offset (B.cond, CBZ, CBNZ).
fn patch_branch19(
    data: &mut [u8],
    instr: &DecodedInstr,
    w: u32,
    foff: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let imm19 = ((w >> 5) & 0x7FFFF) as i32;
    let offset = (sign_extend(imm19, 19) as i64) << 2;
    let target = (instr.addr as i64 + offset) as u64;
    let shift_src =
        total_shift(instr.addr, intervals, ts, te) as i64;
    let shift_tgt =
        total_shift(target, intervals, ts, te) as i64;
    let delta = shift_src - shift_tgt;
    if delta == 0 {
        return;
    }
    let new_addr = instr.addr as i64 - shift_src;
    let new_target = target as i64 - shift_tgt;
    let new_offset = new_target - new_addr;
    let new_imm19 = (new_offset >> 2) as u32;
    let new_word =
        (w & 0xFF00_001F) | ((new_imm19 & 0x7FFFF) << 5);
    data[foff..foff + 4]
        .copy_from_slice(&new_word.to_le_bytes());
}
