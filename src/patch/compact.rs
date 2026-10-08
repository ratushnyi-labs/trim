//! Physical dead code compaction for the .text section.
//!
//! Removes dead intervals from .text by building a compacted copy of
//! live bytes, then drains the freed page-aligned region from the file.
//! Used by all binary formats after branch and metadata patching.
//! Every range is derived from the file, so it is checked rather than
//! trusted: an inconsistent plan is skipped, never panicked on.

use crate::patch::relocs::page_shrink;
use crate::types::Section;

/// True if compacting .text by `intervals` is consistent: the .text file
/// range lies inside a file of `data_len` bytes, and the intervals are
/// sorted, disjoint and inside .text, so the page-aligned drain never
/// exceeds the dead bytes removed from .text. Callers check this before
/// patching anything, so a plan that does not fit is never half-applied.
pub fn compaction_fits(
    data_len: usize,
    sections: &[Section],
    intervals: &[(u64, u64)],
) -> bool {
    let text = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return false,
    };
    let te = match text.vaddr.checked_add(text.size) {
        Some(e) => e,
        None => return false,
    };
    if text_file_range(text, data_len).is_none() {
        return false;
    }
    let mut prev = text.vaddr;
    for &(s, e) in intervals {
        if s < prev || e < s || e > te {
            return false;
        }
        prev = e;
    }
    true
}

/// Compact .text by removing dead intervals, then physically
/// remove page-aligned freed bytes from the file. Returns
/// total dead bytes compacted (0 when the plan is skipped).
pub fn compact_text(
    data: &mut Vec<u8>,
    sections: &[Section],
    intervals: &[(u64, u64)],
) -> u64 {
    let text = match sections.iter().find(|s| s.name == ".text") {
        Some(s) => s,
        None => return 0,
    };
    let (off, size) = match text_file_range(text, data.len()) {
        Some(r) => r,
        None => return 0,
    };
    let vma = text.vaddr;
    let new_text = build_live_text(data, intervals, off, size, vma);
    let saved = size.saturating_sub(new_text.len());
    if saved == 0 {
        return 0;
    }
    if !apply_compact(data, off, size, &new_text, intervals) {
        return 0;
    }
    saved as u64
}

/// File range `(offset, size)` of `text`, if it lies inside a file of
/// `data_len` bytes.
fn text_file_range(text: &Section, data_len: usize) -> Option<(usize, usize)> {
    let off = usize::try_from(text.offset).ok()?;
    let size = usize::try_from(text.size).ok()?;
    (off.checked_add(size)? <= data_len).then_some((off, size))
}

/// Build a new byte vector containing only live (non-dead) text bytes.
/// `data[off..off + size]` must be in bounds (see `text_file_range`);
/// intervals not wholly inside .text are ignored.
fn build_live_text(
    data: &[u8],
    intervals: &[(u64, u64)],
    off: usize,
    size: usize,
    vma: u64,
) -> Vec<u8> {
    let text = match data.get(off..off + size) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut new_text = Vec::with_capacity(size);
    let mut pos = 0usize;
    for &(s, e) in intervals {
        if s < vma || e < s || e - vma > size as u64 {
            continue;
        }
        let (ds, de) = ((s - vma) as usize, (e - vma) as usize);
        if let Some(live) = text.get(pos..ds) {
            new_text.extend_from_slice(live);
        }
        pos = pos.max(de);
    }
    if let Some(live) = text.get(pos..) {
        new_text.extend_from_slice(live);
    }
    new_text
}

/// Write compacted text back into `data` and drain freed pages.
/// Returns false, leaving `data` unchanged, if the page-aligned drain
/// would exceed the bytes freed in .text (an inconsistent plan).
fn apply_compact(
    data: &mut Vec<u8>,
    off: usize,
    size: usize,
    new_text: &[u8],
    intervals: &[(u64, u64)],
) -> bool {
    let live_len = new_text.len();
    let freed = size.saturating_sub(live_len);
    let ps = match usize::try_from(page_shrink(intervals)) {
        Ok(ps) if live_len <= size && ps <= freed => ps,
        _ => {
            eprintln!(
                "  warning: .text compaction skipped: drain exceeds \
                 freed bytes"
            );
            return false;
        }
    };
    let text_end = off + size;
    let pad_end = text_end - ps;
    let (live, pad) = match data.get_mut(off..pad_end) {
        Some(t) => t.split_at_mut(live_len),
        None => return false,
    };
    live.copy_from_slice(new_text);
    pad.fill(0x00);
    if ps > 0 {
        data.drain(pad_end..text_end);
    }
    true
}
