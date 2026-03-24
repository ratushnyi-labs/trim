use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is MIPS padding (0x00 = NOP).
pub fn is_padding_mips(b: u8) -> bool {
    b == 0x00
}

/// Patch MIPS branch offsets after dead code removal.
pub fn patch_branches(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
    big_endian: bool,
) {
    for instr in instrs {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        patch_one(
            data, instr, intervals, sections, ts, te,
            big_endian,
        );
    }
}

fn read_word(raw: &[u8], big_endian: bool) -> u32 {
    let b: [u8; 4] =
        raw[..4].try_into().unwrap_or([0; 4]);
    if big_endian {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    }
}

fn write_word(
    data: &mut [u8],
    off: usize,
    w: u32,
    big_endian: bool,
) {
    let b = if big_endian {
        w.to_be_bytes()
    } else {
        w.to_le_bytes()
    };
    data[off..off + 4].copy_from_slice(&b);
}

fn patch_one(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
    big_endian: bool,
) {
    if instr.raw.len() < 4 {
        return;
    }
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
    if foff + 4 > data.len() {
        return;
    }
    let w = read_word(&instr.raw, big_endian);
    let op = w >> 26;
    match op {
        // J / JAL — 26-bit region target
        0x02 | 0x03 => {
            let new_target = target.wrapping_sub(shift_tgt);
            let new_index =
                (new_target >> 2) & 0x03FF_FFFF;
            let new_w =
                (w & 0xFC00_0000) | new_index as u32;
            write_word(data, foff, new_w, big_endian);
        }
        // BEQ / BNE / BLEZ / BGTZ — 16-bit PC-relative
        0x04 | 0x05 | 0x06 | 0x07 => {
            let new_addr =
                instr.addr.wrapping_sub(shift_src);
            let new_target =
                target.wrapping_sub(shift_tgt);
            let new_imm16 = ((new_target as i64
                - new_addr as i64
                - 4)
                >> 2) as u32
                & 0xFFFF;
            let new_w =
                (w & 0xFFFF_0000) | new_imm16;
            write_word(data, foff, new_w, big_endian);
        }
        // REGIMM (BLTZ / BGEZ) — 16-bit PC-relative
        0x01 => {
            let new_addr =
                instr.addr.wrapping_sub(shift_src);
            let new_target =
                target.wrapping_sub(shift_tgt);
            let new_imm16 = ((new_target as i64
                - new_addr as i64
                - 4)
                >> 2) as u32
                & 0xFFFF;
            let new_w =
                (w & 0xFFFF_0000) | new_imm16;
            write_word(data, foff, new_w, big_endian);
        }
        _ => {}
    }
}
