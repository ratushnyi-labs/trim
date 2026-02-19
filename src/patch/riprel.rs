use crate::elf::sections::vaddr_to_offset;
use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{DecodedInstr, Section};

/// Patch RIP-relative displacements for shifted references.
pub fn patch_rip_rel(
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
        let rip_target = match instr.rip_target {
            Some(t) => t,
            None => continue,
        };
        let old_disp =
            rip_target as i64 - (instr.addr + instr.len as u64) as i64;
        let shift_src = total_shift(instr.addr, intervals, ts, te);
        let shift_tgt =
            total_shift(rip_target, intervals, ts, te);
        let delta = shift_src as i64 - shift_tgt as i64;
        if delta == 0 {
            continue;
        }
        let new_disp = old_disp + delta;
        let pos = find_disp_pos(&instr.raw, old_disp as i32);
        if let (Some(pos), Some(foff)) =
            (pos, vaddr_to_offset(instr.addr, sections))
        {
            let abs_pos = foff as usize + pos;
            if abs_pos + 4 <= data.len() {
                let bytes = (new_disp as i32).to_le_bytes();
                data[abs_pos..abs_pos + 4].copy_from_slice(&bytes);
            }
        }
    }
}

fn find_disp_pos(raw: &[u8], disp_val: i32) -> Option<usize> {
    let packed = disp_val.to_le_bytes();
    raw.windows(4)
        .position(|w| w == packed)
}
