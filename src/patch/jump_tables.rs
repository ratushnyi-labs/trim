use crate::patch::relocs::total_shift;
use crate::types::DecodedInstr;

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
        let mut has_add = false;
        let mut has_jmp = false;
        for j in (i + 1)..((i + 4).min(n)) {
            if instrs[j].targets.is_empty() {
                has_add = true;
            }
            // Indirect jump would have no near targets
            if !instrs[j].is_call && instrs[j].raw.len() >= 2 {
                let op = instrs[j].raw[0];
                if op == 0xFF {
                    has_jmp = true;
                }
            }
        }
        if !(has_add && has_jmp) {
            continue;
        }
        // Look for LEA with RIP-relative target
        for j in (i.saturating_sub(6))..i {
            if let Some(base) = instrs[j].rip_target {
                let mut count = 256usize;
                for k in (i.saturating_sub(12))..i {
                    if let Some(c) = extract_cmp_imm(&instrs[k]) {
                        count = c + 1;
                    }
                }
                tables.push((base, count));
                break;
            }
        }
    }
    tables
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
        let base_shift =
            total_shift(base, intervals, ts, te) as i64;
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
}

fn is_movslq_scale4(instr: &DecodedInstr) -> bool {
    // movslq with scale 4 pattern: 48 63 ... ,4)
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
    // cmp reg, imm8: 83 F8..FF imm8
    if raw.len() >= 3
        && raw[0] == 0x83
        && (0xF8..=0xFF).contains(&raw[1])
    {
        return Some(raw[2] as usize);
    }
    // cmp reg, imm32: 81 F8..FF imm32
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
