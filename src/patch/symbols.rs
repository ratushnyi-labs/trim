use crate::patch::relocs::total_shift;
use crate::types::Section;

/// Patch st_value in .symtab and .dynsym for shifted addresses.
pub fn patch_symbols(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    for sec in sections {
        if sec.name != ".symtab" && sec.name != ".dynsym" {
            continue;
        }
        patch_symtab(data, sec, intervals, ts, te);
    }
}

fn patch_symtab(
    data: &mut [u8],
    sec: &Section,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let is64 = data.len() > 4 && data[4] == 2;
    let (entry_sz, val_off, val_sz) = if is64 {
        (24usize, 8usize, 8usize) // Elf64_Sym
    } else {
        (16usize, 4usize, 4usize) // Elf32_Sym
    };
    let mut i = sec.offset as usize;
    let end =
        (sec.offset as usize + sec.size as usize).min(data.len());
    while i + entry_sz <= end {
        let val = if is64 {
            u64::from_le_bytes(
                data[i + val_off..i + val_off + 8]
                    .try_into()
                    .unwrap_or([0; 8]),
            )
        } else {
            u32::from_le_bytes(
                data[i + val_off..i + val_off + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as u64
        };
        if val > 0 {
            let shift = total_shift(val, intervals, ts, te);
            if shift > 0 {
                let new_val = val - shift;
                if is64 {
                    data[i + val_off..i + val_off + 8]
                        .copy_from_slice(&new_val.to_le_bytes());
                } else {
                    data[i + val_off..i + val_off + 4]
                        .copy_from_slice(
                            &(new_val as u32).to_le_bytes(),
                        );
                }
            }
        }
        // Also patch st_size for .symtab symbols in dead ranges
        i += entry_sz;
    }
}
