//! LoongArch64 instruction decoder for dead code analysis.
//!
//! Decodes fixed-width 32-bit little-endian LoongArch instructions.
//! Extracts B/BL 26-bit jump targets, BEQ/BNE/BLT/BGE/BLTU/BGEU
//! 16-bit conditional branches, BEQZ/BNEZ 21-bit branches, JIRL
//! indirect calls/returns, and PCALA/PCADDU PC-relative references.
//! Follows the LoongArch LP64D calling convention.

use crate::types::{DecodedInstr, FlowType};

/// Decode LoongArch64 instructions (fixed 32-bit, little-endian).
pub fn decode_text_loongarch(
    data: &[u8],
    text_offset: u64,
    text_vaddr: u64,
    text_size: u64,
) -> Vec<DecodedInstr> {
    let end = text_offset as usize + text_size as usize;
    let slice =
        &data[text_offset as usize..end.min(data.len())];
    let mut instrs = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= slice.len() {
        let addr = text_vaddr + offset as u64;
        let raw = slice[offset..offset + 4].to_vec();
        let word = u32::from_le_bytes(
            raw[..4].try_into().unwrap_or([0; 4]),
        );
        let (targets, pc_rel, flow) =
            decode_la_word(addr, word);
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

/// Decode a single LoongArch instruction word by opcode dispatch.
fn decode_la_word(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let op6 = w >> 26;
    match op6 {
        0x14 => decode_b(addr, w),
        0x15 => decode_bl(addr, w),
        0x13 => decode_jirl(w),
        0x16 => decode_beq(addr, w),
        0x17 => decode_bne(addr, w),
        0x18 => decode_blt(addr, w),
        0x19 => decode_bge(addr, w),
        0x1A => decode_bltu(addr, w),
        0x1B => decode_bgeu(addr, w),
        0x10 => decode_beqz(addr, w),
        0x11 => decode_bnez(addr, w),
        _ => decode_la_other(addr, w),
    }
}

fn decode_b(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i26_target(addr, w);
    (vec![target], None, FlowType::UnconditionalBranch)
}

fn decode_bl(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i26_target(addr, w);
    (vec![target], None, FlowType::Call)
}

fn decode_jirl(
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let rd = w & 0x1F;
    let rj = (w >> 5) & 0x1F;
    let flow = if rd == 0 && rj == 1 {
        FlowType::Return
    } else if rd == 1 {
        FlowType::IndirectCall
    } else {
        FlowType::IndirectBranch
    };
    (Vec::new(), None, flow)
}

fn decode_beq(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_bne(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_blt(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_bge(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_bltu(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_bgeu(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i16_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_beqz(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i21_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_bnez(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let target = i21_target(addr, w);
    (vec![target], None, FlowType::ConditionalBranch)
}

/// Decode PC-relative and halt instructions (PCALA, PCADDU, BREAK).
fn decode_la_other(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let op7 = w >> 25;
    match op7 {
        0x0E => {
            let imm = ((w >> 5) & 0xFFFFF) as i32;
            let offset = sign_extend(imm, 20) as i64;
            let target = (addr as i64 + (offset << 12)) as u64;
            return (Vec::new(), Some(target), FlowType::Normal);
        }
        _ => {}
    }
    let op = w >> 26;
    if op == 0x0D {
        let imm = ((w >> 5) & 0xFFFFF) as i32;
        let offset = (sign_extend(imm, 20) as i64) << 2;
        let target = (addr as i64 + offset) as u64;
        return (Vec::new(), Some(target), FlowType::Normal);
    }
    if (w >> 25) == 0x0D {
        let imm = ((w >> 5) & 0xFFFFF) as i32;
        let offset = sign_extend(imm, 20) as i64;
        let page = (addr & !0xFFF) as i64;
        let target = (page + (offset << 12)) as u64;
        return (Vec::new(), Some(target), FlowType::Normal);
    }
    if w == 0x002A_0000 {
        return (Vec::new(), None, FlowType::Halt);
    }
    if (w & 0xFFFF_8000) == 0x002A_8000 {
        return (Vec::new(), None, FlowType::Halt);
    }
    (Vec::new(), None, FlowType::Normal)
}

fn i26_target(addr: u64, w: u32) -> u64 {
    let lo16 = (w & 0x03FF) as i32;
    let hi16 = ((w >> 10) & 0xFFFF) as i32;
    let raw = (lo16 << 16) | hi16;
    let offset = (sign_extend(raw, 26) as i64) << 2;
    (addr as i64 + offset) as u64
}

fn i16_target(addr: u64, w: u32) -> u64 {
    let imm = ((w >> 10) & 0xFFFF) as i32;
    let offset = (sign_extend(imm, 16) as i64) << 2;
    (addr as i64 + offset) as u64
}

fn i21_target(addr: u64, w: u32) -> u64 {
    let lo16 = ((w >> 10) & 0xFFFF) as i32;
    let hi5 = (w & 0x1F) as i32;
    let raw = (hi5 << 16) | lo16;
    let offset = (sign_extend(raw, 21) as i64) << 2;
    (addr as i64 + offset) as u64
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
