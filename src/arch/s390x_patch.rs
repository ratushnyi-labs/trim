//! s390x branch offset patching after dead code compaction.
//!
//! Rewrites BRC/BRAS 16-bit halfword-relative offsets (4-byte instructions)
//! and BRCL/BRASL 32-bit halfword-relative offsets (6-byte instructions)
//! to account for address shifts. s390x is always big-endian.

use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is s390x padding (0x00).
pub fn is_padding_s390x(b: u8) -> bool {
    b == 0x00
}

/// Patch s390x branch offsets after dead code removal.
/// s390x is always big-endian with variable-length
/// instructions (2/4/6 bytes).
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

/// Patch a single s390x instruction's branch offset by length dispatch.
fn patch_one(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    if instr.targets.is_empty() {
        return;
    }
    let target = instr.targets[0];
    let shift_src =
        total_shift(instr.addr, intervals, ts, te);
    let shift_tgt =
        total_shift(target, intervals, ts, te);
    let delta = shift_src as i64 - shift_tgt as i64;
    if delta == 0 {
        return;
    }
    let foff = match vaddr_to_offset(instr.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };
    let raw = &instr.raw;
    match raw.len() {
        4 => patch_4byte(data, foff, raw, instr, target,
                         shift_src, shift_tgt),
        6 => patch_6byte(data, foff, raw, instr, target,
                         shift_src, shift_tgt),
        _ => {}
    }
}

/// Patch a 4-byte s390x instruction (BRC/BRAS) 16-bit halfword offset.
fn patch_4byte(
    data: &mut [u8],
    foff: usize,
    raw: &[u8],
    instr: &DecodedInstr,
    target: u64,
    shift_src: u64,
    shift_tgt: u64,
) {
    if raw[0] != 0xA7 {
        return;
    }
    let op4 = raw[1] & 0x0F;
    // BRC (0x04) or BRAS (0x05) — 16-bit halfword offset
    if op4 != 0x04 && op4 != 0x05 {
        return;
    }
    if foff + 4 > data.len() {
        return;
    }
    let new_addr = instr.addr.wrapping_sub(shift_src);
    let new_target = target.wrapping_sub(shift_tgt);
    let new_imm16 = ((new_target as i64
        - new_addr as i64)
        / 2) as i16;
    let bytes = new_imm16.to_be_bytes();
    data[foff + 2..foff + 4].copy_from_slice(&bytes);
}

/// Patch a 6-byte s390x instruction (BRCL/BRASL) 32-bit halfword offset.
fn patch_6byte(
    data: &mut [u8],
    foff: usize,
    raw: &[u8],
    instr: &DecodedInstr,
    target: u64,
    shift_src: u64,
    shift_tgt: u64,
) {
    if raw[0] != 0xC0 {
        return;
    }
    let op4 = raw[1] & 0x0F;
    // BRCL (0x04) or BRASL (0x05) — 32-bit halfword offset
    if op4 != 0x04 && op4 != 0x05 {
        return;
    }
    if foff + 6 > data.len() {
        return;
    }
    let new_addr = instr.addr.wrapping_sub(shift_src);
    let new_target = target.wrapping_sub(shift_tgt);
    let new_imm32 = ((new_target as i64
        - new_addr as i64)
        / 2) as i32;
    let bytes = new_imm32.to_be_bytes();
    data[foff + 2..foff + 6].copy_from_slice(&bytes);
}
