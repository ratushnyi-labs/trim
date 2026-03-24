use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is ARM32 padding (zero = UDF).
pub fn is_padding_arm32(b: u8) -> bool {
    b == 0x00
}

/// Patch branch offsets in ARM32 instructions after dead code
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

    // BLX immediate: 1111_101H imm24
    if (w & 0xFE00_0000) == 0xFA00_0000 {
        let imm24 = (w & 0x00FF_FFFF) as i32;
        let h = ((w >> 24) & 1) as i64;
        let offset =
            ((sign_extend(imm24, 24) as i64) << 2) | (h << 1);
        let target = (instr.addr as i64 + 8 + offset) as u64;
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
        let new_offset = new_target - new_addr - 8;
        // Reconstruct H bit and imm24
        let new_h = ((new_offset >> 1) & 1) as u32;
        let new_imm24 =
            ((new_offset >> 2) as u32) & 0x00FF_FFFF;
        let new_word = (w & 0xFE00_0000)
            | (new_h << 24)
            | new_imm24;
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
        return;
    }

    // B/BL: cond[31:28] 101[27:25] L[24] imm24[23:0]
    // bits[27:25] must be 101, cond must not be 1111
    let cond = w >> 28;
    if ((w >> 25) & 7) == 0b101 && cond != 0xF {
        let imm24 = (w & 0x00FF_FFFF) as i32;
        let offset = (sign_extend(imm24, 24) as i64) << 2;
        let target = (instr.addr as i64 + 8 + offset) as u64;
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
        let new_offset = new_target - new_addr - 8;
        let new_imm24 =
            ((new_offset >> 2) as u32) & 0x00FF_FFFF;
        let new_word = (w & 0xFF00_0000) | new_imm24;
        data[foff..foff + 4]
            .copy_from_slice(&new_word.to_le_bytes());
    }
}
