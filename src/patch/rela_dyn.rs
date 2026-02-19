use crate::patch::relocs::total_shift;
use crate::types::Section;

/// Patch .rela.dyn: update r_offset and R_X86_64_RELATIVE addends.
pub fn patch_rela_dyn(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    for sec in sections {
        if sec.name != ".rela.dyn" && sec.name != ".rela.plt" {
            continue;
        }
        let entry_size = 24usize; // sizeof(Elf64_Rela)
        let mut i = sec.offset as usize;
        let end = i + sec.size as usize;
        while i + entry_size <= end && i + entry_size <= data.len() {
            patch_rela_entry(data, i, intervals, ts, te);
            i += entry_size;
        }
    }
}

fn patch_rela_entry(
    data: &mut [u8],
    i: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    // r_offset at byte 0 (8 bytes)
    let r_offset = u64::from_le_bytes(
        data[i..i + 8].try_into().unwrap_or([0; 8]),
    );
    let off_shift = total_shift(r_offset, intervals, ts, te);
    if off_shift > 0 {
        let new_off = r_offset - off_shift;
        data[i..i + 8].copy_from_slice(&new_off.to_le_bytes());
    }
    // r_info at offset 8
    let r_info = u64::from_le_bytes(
        data[i + 8..i + 16].try_into().unwrap_or([0; 8]),
    );
    // R_X86_64_RELATIVE = 8
    if (r_info & 0xFFFFFFFF) == 8 {
        // r_addend at offset 16
        let addend = i64::from_le_bytes(
            data[i + 16..i + 24].try_into().unwrap_or([0; 8]),
        );
        let a = addend as u64;
        let shift = total_shift(a, intervals, ts, te);
        if shift > 0 {
            let new_addend = addend - shift as i64;
            data[i + 16..i + 24]
                .copy_from_slice(&new_addend.to_le_bytes());
        }
    }
}
