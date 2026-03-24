//! ARM32 (A32) instruction decoder for dead code analysis.
//!
//! Decodes fixed-width 32-bit little-endian ARM instructions to extract
//! B, BL, BLX branch targets and BX return detection. Does not handle
//! Thumb mode. Follows the AAPCS (ARM Architecture Procedure Call Standard).

use crate::types::{DecodedInstr, FlowType};

/// Decode ARM32 instructions (fixed 32-bit, little-endian).
/// Only extracts branch targets. Does not handle Thumb mode.
pub fn decode_text_arm32(
    data: &[u8],
    text_offset: u64,
    text_vaddr: u64,
    text_size: u64,
) -> Vec<DecodedInstr> {
    let end = text_offset as usize + text_size as usize;
    let slice = &data[text_offset as usize..end.min(data.len())];
    let mut instrs = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= slice.len() {
        let addr = text_vaddr + offset as u64;
        let raw = slice[offset..offset + 4].to_vec();
        let word = u32::from_le_bytes(
            raw[..4].try_into().unwrap_or([0; 4]),
        );
        let (targets, pc_rel, flow) =
            decode_arm32_word(addr, word);
        instrs.push(DecodedInstr {
            addr,
            raw,
            len: 4,
            targets,
            pc_rel_target: pc_rel,
            is_call: matches!(flow, FlowType::Call),
            flow,
        });
        offset += 4;
    }
    instrs
}

/// Decode a single ARM32 instruction word into targets and flow type.
fn decode_arm32_word(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let mut targets = Vec::new();
    // BLX (immediate): 1111 101 H imm24
    if (w & 0xFE00_0000) == 0xFA00_0000 {
        let imm24 = (w & 0x00FF_FFFF) as i32;
        let h = ((w >> 24) & 1) as i64;
        let offset = (sign_extend(imm24, 24) as i64) << 2 | h << 1;
        let t = (addr as i64 + 8 + offset) as u64;
        targets.push(t);
        return (targets, None, FlowType::Call);
    }
    // BX lr (return): cond 0001_0010 1111_1111_1111 0001 Rm
    if (w & 0x0FFF_FFF0) == 0x012F_FF10 {
        let rm = w & 0xF;
        if rm == 14 {
            return (targets, None, FlowType::Return);
        }
        return (targets, None, FlowType::IndirectBranch);
    }
    decode_arm32_b_bl(addr, w, &mut targets)
}

/// Decode ARM32 B/BL conditional branch instruction.
fn decode_arm32_b_bl(
    addr: u64,
    w: u32,
    targets: &mut Vec<u64>,
) -> (Vec<u64>, Option<u64>, FlowType) {
    // B/BL: cond[31:28] 101[27:25] L[24] imm24[23:0]
    // bits [27:25] must be 101, cond must not be 1111
    let top = (w >> 25) & 0x7F;
    let cond = w >> 28;
    if (top & 0x7) != 0b101 || cond == 0xF {
        return (targets.clone(), None, FlowType::Normal);
    }
    let is_link = (w >> 24) & 1 == 1;
    let imm24 = (w & 0x00FF_FFFF) as i32;
    let offset = (sign_extend(imm24, 24) as i64) << 2;
    let t = (addr as i64 + 8 + offset) as u64;
    targets.push(t);
    let flow = if is_link {
        FlowType::Call
    } else if cond == 0xE {
        FlowType::UnconditionalBranch
    } else {
        FlowType::ConditionalBranch
    };
    (targets.clone(), None, flow)
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
