use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is x86 padding (INT3 or NOP).
pub fn is_padding_x86(b: u8) -> bool {
    b == 0xCC || b == 0x90
}

/// Decode call/jmp displacement: (offset_in_instr, size, old_rel).
pub fn decode_rel_ref(
    raw: &[u8],
) -> Option<(usize, usize, i64)> {
    if raw.is_empty() {
        return None;
    }
    let op = raw[0];
    if (op == 0xE8 || op == 0xE9) && raw.len() >= 5 {
        let rel = i32::from_le_bytes(
            raw[1..5].try_into().ok()?,
        ) as i64;
        return Some((1, 4, rel));
    }
    if op == 0xEB && raw.len() >= 2 {
        return Some((1, 1, raw[1] as i8 as i64));
    }
    if op == 0x0F
        && raw.len() >= 6
        && (0x80..=0x8F).contains(&raw[1])
    {
        let rel = i32::from_le_bytes(
            raw[2..6].try_into().ok()?,
        ) as i64;
        return Some((2, 4, rel));
    }
    if (0x70..=0x7F).contains(&op) && raw.len() >= 2 {
        return Some((1, 1, raw[1] as i8 as i64));
    }
    None
}

/// Patch relative call/jmp offsets for compacted addresses.
pub fn patch_call_jmp(
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
        patch_one_rel(data, instr, intervals, sections, ts, te);
    }
}

fn patch_one_rel(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let (doff, dsz, old_rel) = match decode_rel_ref(&instr.raw) {
        Some(v) => v,
        None => return,
    };
    let target =
        (instr.addr as i64 + instr.len as i64 + old_rel) as u64;
    let delta = total_shift(instr.addr, intervals, ts, te) as i64
        - total_shift(target, intervals, ts, te) as i64;
    if delta == 0 {
        return;
    }
    let new_rel = old_rel + delta;
    if let Some(foff) = vaddr_to_offset(instr.addr, sections) {
        let pos = foff as usize + doff;
        if dsz == 4 && pos + 4 <= data.len() {
            let bytes = (new_rel as i32).to_le_bytes();
            data[pos..pos + 4].copy_from_slice(&bytes);
        } else if dsz == 1 && pos + 1 <= data.len() {
            data[pos] = new_rel as i8 as u8;
        }
    }
}

/// Patch PC-relative displacements for shifted references.
pub fn patch_pc_rel(
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
        patch_one_pc_rel(data, instr, intervals, sections, ts, te);
    }
}

fn patch_one_pc_rel(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let pc_target = match instr.pc_rel_target {
        Some(t) => t,
        None => return,
    };
    let old_disp = pc_target as i64
        - (instr.addr + instr.len as u64) as i64;
    let shift_src = total_shift(instr.addr, intervals, ts, te);
    let shift_tgt = total_shift(pc_target, intervals, ts, te);
    let delta = shift_src as i64 - shift_tgt as i64;
    if delta == 0 {
        return;
    }
    let new_disp = old_disp + delta;
    let pos = find_disp_pos(&instr.raw, old_disp as i32);
    if let (Some(pos), Some(foff)) =
        (pos, vaddr_to_offset(instr.addr, sections))
    {
        let abs_pos = foff as usize + pos;
        if abs_pos + 4 <= data.len() {
            let bytes = (new_disp as i32).to_le_bytes();
            data[abs_pos..abs_pos + 4].copy_from_slice(&bytes);
        }
    }
}

fn find_disp_pos(raw: &[u8], disp_val: i32) -> Option<usize> {
    let packed = disp_val.to_le_bytes();
    raw.windows(4).position(|w| w == packed)
}

/// Find switch jump tables: [(base_offset, count)].
pub fn find_jump_tables(
    instrs: &[DecodedInstr],
) -> Vec<(u64, usize)> {
    let mut tables = Vec::new();
    let n = instrs.len();
    for i in 0..n {
        if !is_movslq_scale4(&instrs[i]) {
            continue;
        }
        if let Some(table) = detect_one_table(instrs, i, n) {
            tables.push(table);
        }
    }
    tables
}

fn detect_one_table(
    instrs: &[DecodedInstr],
    i: usize,
    n: usize,
) -> Option<(u64, usize)> {
    let mut has_add = false;
    let mut has_jmp = false;
    for j in (i + 1)..((i + 4).min(n)) {
        if instrs[j].targets.is_empty() {
            has_add = true;
        }
        if !instrs[j].is_call && instrs[j].raw.len() >= 2 {
            if instrs[j].raw[0] == 0xFF {
                has_jmp = true;
            }
        }
    }
    if !(has_add && has_jmp) {
        return None;
    }
    for j in (i.saturating_sub(6))..i {
        if let Some(base) = instrs[j].pc_rel_target {
            let mut count = 256usize;
            for k in (i.saturating_sub(12))..i {
                if let Some(c) = extract_cmp_imm(&instrs[k]) {
                    count = c + 1;
                }
            }
            return Some((base, count));
        }
    }
    None
}

/// Patch relative jump table entries.
pub fn patch_jump_tables(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let tables = find_jump_tables(instrs);
    for (base, count) in tables {
        patch_one_table(data, base, count, intervals, ts, te);
    }
}

fn patch_one_table(
    data: &mut [u8],
    base: u64,
    count: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let base_shift = total_shift(base, intervals, ts, te) as i64;
    for idx in 0..count {
        let off = base as usize + idx * 4;
        if off + 4 > data.len() {
            break;
        }
        let entry = i32::from_le_bytes(
            data[off..off + 4].try_into().unwrap_or([0; 4]),
        );
        let target = (base as i64 + entry as i64) as u64;
        let tgt_shift =
            total_shift(target, intervals, ts, te) as i64;
        let delta = base_shift - tgt_shift;
        if delta != 0 {
            let new_entry = entry + delta as i32;
            data[off..off + 4]
                .copy_from_slice(&new_entry.to_le_bytes());
        }
    }
}

fn is_movslq_scale4(instr: &DecodedInstr) -> bool {
    if instr.raw.len() >= 3 {
        let has_rex_w = instr.raw[0] == 0x48;
        let is_movsxd = instr.raw.get(1) == Some(&0x63);
        return has_rex_w && is_movsxd;
    }
    false
}

fn extract_cmp_imm(instr: &DecodedInstr) -> Option<usize> {
    let raw = &instr.raw;
    if raw.is_empty() {
        return None;
    }
    if raw.len() >= 3
        && raw[0] == 0x83
        && (0xF8..=0xFF).contains(&raw[1])
    {
        return Some(raw[2] as usize);
    }
    if raw.len() >= 6
        && raw[0] == 0x81
        && (0xF8..=0xFF).contains(&raw[1])
    {
        let val = u32::from_le_bytes(
            raw[2..6].try_into().ok()?,
        );
        return Some(val as usize);
    }
    None
}
