//! LoongArch64 branch and PC-relative offset patching after dead code compaction.
//!
//! Rewrites B/BL (26-bit split), BEQ/BNE/BLT/BGE/BLTU/BGEU (16-bit),
//! BEQZ/BNEZ (21-bit split) branch immediates and PCALA/PCADDU12I/
//! PCADDU18I (20-bit) PC-relative immediates to account for address shifts.
//! LoongArch64 is always little-endian with fixed 32-bit instructions.

use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is LoongArch padding (0x00).
pub fn is_padding_loongarch(b: u8) -> bool {
    b == 0x00
}

/// Patch LoongArch64 branch offsets after dead code removal.
/// LoongArch64 is always little-endian with fixed 32-bit
/// instructions.
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

/// Dispatch branch vs PC-relative patching for a single instruction.
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
    let has_branch = !instr.targets.is_empty();
    let has_pc_rel = instr.pc_rel_target.is_some();
    if !has_branch && !has_pc_rel {
        return;
    }
    let foff = match vaddr_to_offset(instr.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };
    if foff + 4 > data.len() {
        return;
    }
    let w = u32::from_le_bytes(
        instr.raw[..4].try_into().unwrap_or([0; 4]),
    );
    if has_branch {
        patch_branch(
            data, foff, w, instr, intervals, sections,
            ts, te,
        );
    } else if has_pc_rel {
        patch_pc_rel(
            data, foff, w, instr, intervals, sections,
            ts, te,
        );
    }
}

/// Patch a LoongArch branch immediate (B/BL, BEQ-family, BEQZ/BNEZ).
fn patch_branch(
    data: &mut [u8],
    foff: usize,
    w: u32,
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    _sections: &[Section],
    ts: u64,
    te: u64,
) {
    let target = instr.targets[0];
    let shift_src =
        total_shift(instr.addr, intervals, ts, te);
    let shift_tgt =
        total_shift(target, intervals, ts, te);
    let delta = shift_src as i64 - shift_tgt as i64;
    if delta == 0 {
        return;
    }
    let new_addr = instr.addr.wrapping_sub(shift_src);
    let new_target = target.wrapping_sub(shift_tgt);
    let op6 = w >> 26;
    let new_w = match op6 {
        // B / BL — 26-bit split immediate
        0x14 | 0x15 => {
            let new_offset =
                (new_target as i64 - new_addr as i64) >> 2;
            let new_imm =
                (new_offset as u32) & 0x03FF_FFFF;
            // lo_part = imm[25:16] -> bits[9:0]
            let lo_part = (new_imm >> 16) & 0x3FF;
            // hi_part = imm[15:0]  -> bits[25:10]
            let hi_part = new_imm & 0xFFFF;
            (w & 0xFC00_0000)
                | ((hi_part << 10) & 0x03FF_FC00)
                | (lo_part & 0x3FF)
        }
        // BEQ/BNE/BLT/BGE/BLTU/BGEU — 16-bit at bits[25:10]
        0x16 | 0x17 | 0x18 | 0x19 | 0x1A | 0x1B => {
            let new_offset =
                (new_target as i64 - new_addr as i64) >> 2;
            let new_imm16 =
                (new_offset as u32) & 0xFFFF;
            (w & 0xFC00_03FF)
                | ((new_imm16 << 10) & 0x03FF_FC00)
        }
        // BEQZ / BNEZ — 21-bit split immediate
        0x10 | 0x11 => {
            let new_offset =
                (new_target as i64 - new_addr as i64) >> 2;
            let new_imm =
                (new_offset as u32) & 0x001F_FFFF;
            // lo16 = imm[15:0] -> bits[25:10]
            let new_lo16 = new_imm & 0xFFFF;
            // hi5  = imm[20:16] -> bits[4:0]
            let new_hi5 = (new_imm >> 16) & 0x1F;
            // Keep opcode [31:26] and rj [9:5]
            (w & 0xFC00_03E0)
                | ((new_lo16 << 10) & 0x03FF_FC00)
                | (new_hi5 & 0x1F)
        }
        _ => return,
    };
    let bytes = new_w.to_le_bytes();
    data[foff..foff + 4].copy_from_slice(&bytes);
}

/// Patch a LoongArch PC-relative immediate (PCALA, PCADDU).
fn patch_pc_rel(
    data: &mut [u8],
    foff: usize,
    w: u32,
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    _sections: &[Section],
    ts: u64,
    te: u64,
) {
    let pc_target = match instr.pc_rel_target {
        Some(t) => t,
        None => return,
    };
    let shift_src =
        total_shift(instr.addr, intervals, ts, te);
    let shift_tgt =
        total_shift(pc_target, intervals, ts, te);
    let delta = shift_src as i64 - shift_tgt as i64;
    if delta == 0 {
        return;
    }
    let new_addr = instr.addr.wrapping_sub(shift_src);
    let new_target = pc_target.wrapping_sub(shift_tgt);
    let op7 = w >> 25;
    let new_w = match op7 {
        // PCALA / PCADDU12I — 20-bit page-relative
        0x0E | 0x0D => {
            let new_offset =
                new_target as i64
                    - (new_addr & !0xFFF) as i64;
            let new_imm20 =
                ((new_offset >> 12) as u32) & 0xFFFFF;
            (w & 0xFE00_001F)
                | ((new_imm20 << 5) & 0x01FF_FFE0)
        }
        _ => {
            // op6-based: PCADDU18I (0x0D by op6)
            let op6 = w >> 26;
            if op6 == 0x0D {
                let new_offset =
                    new_target as i64 - new_addr as i64;
                let new_imm20 =
                    ((new_offset >> 2) as u32) & 0xFFFFF;
                (w & 0xFE00_001F)
                    | ((new_imm20 << 5) & 0x01FF_FFE0)
            } else {
                return;
            }
        }
    };
    let bytes = new_w.to_le_bytes();
    data[foff..foff + 4].copy_from_slice(&bytes);
}
