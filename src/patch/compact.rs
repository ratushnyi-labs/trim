use crate::patch::relocs::page_shrink;
use crate::types::Section;

/// Compact .text by removing dead intervals, then physically
/// remove page-aligned freed bytes from the file. Returns
/// total dead bytes compacted.
pub fn compact_text(
    data: &mut Vec<u8>,
    sections: &[Section],
    intervals: &[(u64, u64)],
) -> u64 {
    let text = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return 0,
    };
    let off = text.offset as usize;
    let size = text.size as usize;
    let vma = text.vaddr;
    let new_text = build_live_text(data, intervals, off, size, vma);
    let saved = size - new_text.len();
    if saved == 0 {
        return 0;
    }
    apply_compact(data, off, size, &new_text, intervals);
    saved as u64
}

fn build_live_text(
    data: &[u8],
    intervals: &[(u64, u64)],
    off: usize,
    size: usize,
    vma: u64,
) -> Vec<u8> {
    let dead_file: Vec<(usize, usize)> = intervals
        .iter()
        .filter(|&&(s, e)| vma <= s && e <= vma + size as u64)
        .map(|&(s, e)| {
            (off + (s - vma) as usize, off + (e - vma) as usize)
        })
        .collect();
    let mut new_text = Vec::with_capacity(size);
    let mut pos = off;
    for &(ds, de) in &dead_file {
        if pos < ds {
            new_text.extend_from_slice(&data[pos..ds]);
        }
        pos = de;
    }
    let text_end = off + size;
    if pos < text_end {
        new_text.extend_from_slice(&data[pos..text_end]);
    }
    new_text
}

fn apply_compact(
    data: &mut Vec<u8>,
    off: usize,
    size: usize,
    new_text: &[u8],
    intervals: &[(u64, u64)],
) {
    let ps = page_shrink(intervals) as usize;
    let live_len = new_text.len();
    let text_end = off + size;
    data[off..off + live_len].copy_from_slice(new_text);
    if ps > 0 {
        let pad_end = off + size - ps;
        data[off + live_len..pad_end].fill(0x00);
        data.drain(pad_end..text_end);
    } else {
        data[off + live_len..text_end].fill(0x00);
    }
}
