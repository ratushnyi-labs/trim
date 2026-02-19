use crate::patch::relocs::total_shift;
use crate::types::Section;

/// Address-type DT_* tags whose d_val is a virtual address.
const ADDR_TAGS: &[u64] = &[
    3,          // DT_PLTGOT
    4,          // DT_HASH
    5,          // DT_STRTAB
    6,          // DT_SYMTAB
    7,          // DT_RELA
    12,         // DT_INIT
    13,         // DT_FINI
    23,         // DT_JMPREL
    25,         // DT_INIT_ARRAY
    26,         // DT_FINI_ARRAY
    0x6ffffef5, // DT_GNU_HASH
    0x6ffffff0, // DT_VERSYM
    0x6ffffffe, // DT_VERNEED
];

/// Patch .dynamic section: shift address-type DT_* values.
pub fn patch_dynamic(
    data: &mut [u8],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    for sec in sections {
        if sec.name != ".dynamic" {
            continue;
        }
        let entry_sz = 16usize; // sizeof(Elf64_Dyn)
        let mut i = sec.offset as usize;
        let end =
            (sec.offset as usize + sec.size as usize).min(data.len());
        while i + entry_sz <= end {
            let d_tag = u64::from_le_bytes(
                data[i..i + 8].try_into().unwrap_or([0; 8]),
            );
            if d_tag == 0 {
                break; // DT_NULL
            }
            if ADDR_TAGS.contains(&d_tag) {
                let d_val = u64::from_le_bytes(
                    data[i + 8..i + 16]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                if d_val > 0 {
                    let shift =
                        total_shift(d_val, intervals, ts, te);
                    if shift > 0 {
                        let new_val = d_val - shift;
                        data[i + 8..i + 16].copy_from_slice(
                            &new_val.to_le_bytes(),
                        );
                    }
                }
            }
            i += entry_sz;
        }
    }
}
