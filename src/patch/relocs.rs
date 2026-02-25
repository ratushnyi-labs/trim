use crate::analysis::cfg::DeadBlock;
use crate::types::Section;
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

/// Convert dead blocks to sorted intervals.
pub fn block_intervals(
    blocks: &[DeadBlock],
) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = blocks
        .iter()
        .map(|b| (b.addr, b.addr + b.size))
        .collect();
    v.sort();
    v
}

/// Merge two sorted interval lists into one sorted,
/// non-overlapping list.
pub fn combine_intervals(
    a: &[(u64, u64)],
    b: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let mut all: Vec<(u64, u64)> = Vec::with_capacity(
        a.len() + b.len(),
    );
    all.extend_from_slice(a);
    all.extend_from_slice(b);
    merge_intervals(&mut all)
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
/// at or after .text end returns page-aligned shrink.
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

/// Extend dead intervals to absorb adjacent padding bytes,
/// then merge overlapping intervals.
pub fn defrag_intervals(
    intervals: &[(u64, u64)],
    data: &[u8],
    sections: &[Section],
    is_padding: fn(u8) -> bool,
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
        let (lo, hi) =
            expand_one(data, text, ts, te, start, end, is_padding);
        expanded.push((lo, hi));
    }
    merge_intervals(&mut expanded)
}

fn expand_one(
    data: &[u8],
    text: &Section,
    ts: u64,
    te: u64,
    start: u64,
    end: u64,
    is_padding: fn(u8) -> bool,
) -> (u64, u64) {
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
    (lo, hi)
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
