use crate::elf::sections::vaddr_to_offset;
use crate::types::{DecodedInstr, Section};
use std::collections::HashMap;

/// Sorted dead intervals [(start_vaddr, end_vaddr)].
pub fn dead_intervals(
    dead: &HashMap<String, (u64, u64)>,
) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> =
        dead.values().map(|&(a, s)| (a, a + s)).collect();
    v.sort();
    v
}

/// Total dead bytes before a given address.
pub fn shift_at(addr: u64, intervals: &[(u64, u64)]) -> u64 {
    let mut total = 0u64;
    for &(start, end) in intervals {
        if start < addr {
            total += end.min(addr) - start;
        }
    }
    total
}

/// Check if address is inside any dead interval.
pub fn in_dead_range(
    addr: u64,
    intervals: &[(u64, u64)],
) -> bool {
    intervals
        .iter()
        .any(|&(start, end)| start <= addr && addr < end)
}

const PAGE_SIZE: u64 = 4096;

/// Total dead bytes across all intervals.
pub fn total_dead(intervals: &[(u64, u64)]) -> u64 {
    intervals.iter().map(|&(s, e)| e - s).sum()
}

/// Page-aligned dead bytes that can be physically removed.
pub fn page_shrink(intervals: &[(u64, u64)]) -> u64 {
    let td = total_dead(intervals);
    (td / PAGE_SIZE) * PAGE_SIZE
}

/// Unified shift: within .text uses per-interval shift,
/// at or after .text end returns page-aligned shrink amount.
pub fn total_shift(
    addr: u64,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) -> u64 {
    if addr < ts {
        0
    } else if addr < te {
        shift_at(addr, intervals)
    } else {
        page_shrink(intervals)
    }
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
        if let Some((doff, dsz, old_rel)) =
            decode_rel_ref(&instr.raw)
        {
            let target =
                (instr.addr as i64 + instr.len as i64 + old_rel)
                    as u64;
            let delta = total_shift(instr.addr, intervals, ts, te)
                as i64
                - total_shift(target, intervals, ts, te) as i64;
            if delta == 0 {
                continue;
            }
            let new_rel = old_rel + delta;
            if let Some(foff) =
                vaddr_to_offset(instr.addr, sections)
            {
                let pos = foff as usize + doff;
                if dsz == 4 && pos + 4 <= data.len() {
                    let bytes = (new_rel as i32).to_le_bytes();
                    data[pos..pos + 4].copy_from_slice(&bytes);
                } else if dsz == 1 && pos + 1 <= data.len() {
                    data[pos] = new_rel as i8 as u8;
                }
            }
        }
    }
}

/// Extend dead intervals to absorb adjacent NOP/INT3 alignment
/// padding, then merge overlapping intervals.
pub fn defrag_intervals(
    intervals: &[(u64, u64)],
    data: &[u8],
    sections: &[Section],
) -> Vec<(u64, u64)> {
    let text = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return intervals.to_vec(),
    };
    let ts = text.vaddr;
    let te = text.vaddr + text.size;
    let mut expanded: Vec<(u64, u64)> =
        Vec::with_capacity(intervals.len());
    for &(start, end) in intervals {
        let mut lo = start;
        let mut hi = end;
        while lo > ts {
            let off = (text.offset + lo - 1 - ts) as usize;
            if off >= data.len() || !is_padding(data[off]) {
                break;
            }
            lo -= 1;
        }
        while hi < te {
            let off = (text.offset + hi - ts) as usize;
            if off >= data.len() || !is_padding(data[off]) {
                break;
            }
            hi += 1;
        }
        expanded.push((lo, hi));
    }
    merge_intervals(&mut expanded)
}

fn is_padding(b: u8) -> bool {
    b == 0xCC || b == 0x90
}

fn merge_intervals(
    intervals: &mut Vec<(u64, u64)>,
) -> Vec<(u64, u64)> {
    if intervals.is_empty() {
        return Vec::new();
    }
    intervals.sort();
    let mut merged = vec![intervals[0]];
    for &(start, end) in &intervals[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1 {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

/// Decode call/jmp displacement: (offset_in_instr, size, old_rel).
fn decode_rel_ref(raw: &[u8]) -> Option<(usize, usize, i64)> {
    if raw.is_empty() {
        return None;
    }
    let op = raw[0];
    // E8 call rel32, E9 jmp rel32
    if (op == 0xE8 || op == 0xE9) && raw.len() >= 5 {
        let rel = i32::from_le_bytes(
            raw[1..5].try_into().ok()?,
        ) as i64;
        return Some((1, 4, rel));
    }
    // EB jmp rel8
    if op == 0xEB && raw.len() >= 2 {
        let rel = raw[1] as i8 as i64;
        return Some((1, 1, rel));
    }
    // 0F 80..8F jcc rel32
    if op == 0x0F
        && raw.len() >= 6
        && (0x80..=0x8F).contains(&raw[1])
    {
        let rel = i32::from_le_bytes(
            raw[2..6].try_into().ok()?,
        ) as i64;
        return Some((2, 4, rel));
    }
    // 70..7F jcc rel8
    if (0x70..=0x7F).contains(&op) && raw.len() >= 2 {
        let rel = raw[1] as i8 as i64;
        return Some((1, 1, rel));
    }
    None
}
