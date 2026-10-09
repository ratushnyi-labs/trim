//! 32-bit self-relative pointers (RELPTR32) in data after compaction.
//!
//! A RELPTR32 field at `location` designates `location + value` (signed
//! 32-bit). Compacting .text moves code inside it by the per-interval
//! shift and everything after it by the page-aligned drain, so a field
//! whose location and target move by different amounts goes stale: it is
//! rewritten to `new_target - new_location`. A field whose location and
//! target move by the same amount stays valid and is left alone. Like
//! every patcher this works on original vaddrs and file offsets, before
//! `compact_text` drains the file. Fields are little-endian.

use crate::patch::relocs::{in_dead_range, total_shift};

/// A RELPTR32 field: where it is and what it designates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelField {
    /// Vaddr of the 32-bit field.
    pub location: u64,
    /// File offset of the field (the field is file-backed).
    pub offset: usize,
    /// `location` plus the field's signed value.
    pub target: u64,
}

/// Why compacting by `intervals` would break one of `fields`: a field
/// inside .text `[ts, te)` (it would move with the code, or be removed),
/// a target inside removed code, or a new value that does not fit 32
/// bits. None if every field can follow.
pub fn relptr32_conflict(
    fields: &[RelField],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) -> Option<String> {
    for f in fields {
        if ts <= f.location && f.location < te {
            return Some(format!("RELPTR32 at {:#x} lies in .text", f.location));
        }
        if in_dead_range(f.target, intervals) {
            return Some(format!(
                "RELPTR32 at {:#x} designates removed code at {:#x}",
                f.location, f.target
            ));
        }
        if new_value(f, intervals, ts, te).is_none() {
            return Some(format!("RELPTR32 at {:#x} out of range", f.location));
        }
    }
    None
}

/// The field's value after compaction: `new_target - new_location`.
/// None if it does not fit a signed 32-bit field.
fn new_value(f: &RelField, intervals: &[(u64, u64)], ts: u64, te: u64) -> Option<i32> {
    let loc = f.location.wrapping_sub(total_shift(f.location, intervals, ts, te));
    let tgt = f.target.wrapping_sub(total_shift(f.target, intervals, ts, te));
    i32::try_from(tgt.wrapping_sub(loc) as i64).ok()
}

/// True if the field's location and target move by different amounts.
fn moves_apart(f: &RelField, intervals: &[(u64, u64)], ts: u64, te: u64) -> bool {
    total_shift(f.location, intervals, ts, te) != total_shift(f.target, intervals, ts, te)
}

/// Rewrite every field of `fields` whose location and target move apart
/// under the compaction `intervals`; the others stay valid as they are.
/// Callers check `relptr32_conflict` first. A field whose offset lies
/// outside `data`, or whose new value does not fit, is left untouched.
/// Returns (rewritten, left unchanged).
pub fn patch_relptr32(
    data: &mut [u8],
    fields: &[RelField],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) -> (usize, usize) {
    let mut rewritten = 0;
    for f in fields {
        if !moves_apart(f, intervals, ts, te) {
            continue;
        }
        let v = match new_value(f, intervals, ts, te) {
            Some(v) => v,
            None => continue,
        };
        let slot = f.offset.checked_add(4).and_then(|e| data.get_mut(f.offset..e));
        if let Some(slot) = slot {
            slot.copy_from_slice(&v.to_le_bytes());
            rewritten += 1;
        }
    }
    (rewritten, fields.len() - rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// .text [0x1000, 0x3000) loses [0x1100, 0x2180): one page drained,
    /// 0x80 bytes of padding left at the end of .text.
    const IVS: &[(u64, u64)] = &[(0x1100, 0x2180)];
    const TS: u64 = 0x1000;
    const TE: u64 = 0x3000;

    /// A field at `location` (file offset = vaddr - 0x1000) whose stored
    /// value designates `target`.
    fn field(data: &mut [u8], location: u64, target: u64) -> RelField {
        let offset = (location - 0x1000) as usize;
        let v = target.wrapping_sub(location) as i64 as i32;
        data[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
        RelField { location, offset, target }
    }

    /// Value stored in the field after patching, as a target address
    /// relative to the field's new location.
    fn new_target(data: &[u8], f: &RelField) -> u64 {
        let b = &data[f.offset..f.offset + 4];
        let v = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let loc = f.location - total_shift(f.location, IVS, TS, TE);
        loc.wrapping_add(v as i64 as u64)
    }

    /// A field after .text designating code moved by a partial shift is
    /// re-pointed; one designating data after .text moves with it.
    #[test]
    fn repoints_only_fields_that_move_apart() {
        let mut data = vec![0u8; 0x4000];
        let into_text = field(&mut data, 0x3010, 0x2200);
        let into_data = field(&mut data, 0x3014, 0x3800);
        let before = field(&mut data, 0x3018, 0x1080);
        let fields = [into_text, into_data, before];
        assert_eq!(relptr32_conflict(&fields, IVS, TS, TE), None);
        assert_eq!(patch_relptr32(&mut data, &fields, IVS, TS, TE), (2, 1));
        assert_eq!(new_target(&data, &into_text), 0x2200 - 0x1080);
        assert_eq!(new_target(&data, &into_data), 0x3800 - 0x1000);
        assert_eq!(new_target(&data, &before), 0x1080);
    }

    /// Fields inside .text and fields designating removed code are
    /// refused before anything is written.
    #[test]
    fn refuses_fields_that_cannot_follow() {
        let mut data = vec![0u8; 0x4000];
        let in_text = field(&mut data, 0x1010, 0x3800);
        assert!(relptr32_conflict(&[in_text], IVS, TS, TE).is_some());
        let removed = field(&mut data, 0x3010, 0x1200);
        let why = relptr32_conflict(&[removed], IVS, TS, TE);
        assert!(why.is_some_and(|w| w.contains("removed code")));
    }
}
