use crate::patch::relocs::total_shift;

/// Patch ELF entry point if it shifted due to compaction.
pub fn patch_entry_point(
    data: &mut [u8],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return;
    }
    let is64 = data[4] == 2;
    let (off, sz) = if is64 { (24usize, 8usize) } else { (24, 4) };
    if off + sz > data.len() {
        return;
    }
    let entry = if is64 {
        u64::from_le_bytes(
            data[off..off + 8].try_into().unwrap_or([0; 8]),
        )
    } else {
        u32::from_le_bytes(
            data[off..off + 4].try_into().unwrap_or([0; 4]),
        ) as u64
    };
    let shift = total_shift(entry, intervals, ts, te);
    if shift > 0 {
        if is64 {
            data[off..off + 8].copy_from_slice(
                &(entry - shift).to_le_bytes(),
            );
        } else {
            data[off..off + 4].copy_from_slice(
                &((entry - shift) as u32).to_le_bytes(),
            );
        }
    }
}
