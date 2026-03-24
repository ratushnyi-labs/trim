//! AArch64 instruction decoder for dead code analysis.
//!
//! Decodes A64 fixed-width 32-bit little-endian instructions to extract
//! call/branch targets (B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ) and
//! PC-relative references (ADRP, ADR, LDR literal). Used by the
//! analysis engine to build call graphs and detect dead branches
//! on 64-bit ARM binaries. Follows the AAPCS64 calling convention.

use crate::types::{DecodedInstr, FlowType};

/// Decode AArch64 instructions (fixed 32-bit, little-endian).
/// Only extracts branch targets and PC-relative references.
pub fn decode_text_aarch64(
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
        let d = decode_a64_word(addr, word);
        instrs.push(DecodedInstr {
            addr,
            raw,
            len: 4,
            targets: d.targets,
            pc_rel_target: d.pc_rel,
            is_call: matches!(d.flow, FlowType::Call),
            flow: d.flow,
        });
        offset += 4;
    }
    instrs
}

/// Intermediate decoded A64 instruction data.
struct A64Decoded {
    targets: Vec<u64>,
    pc_rel: Option<u64>,
    flow: FlowType,
}

/// Decode a single A64 instruction word at the given address.
fn decode_a64_word(addr: u64, w: u32) -> A64Decoded {
    let mut d = A64Decoded {
        targets: Vec::new(),
        pc_rel: None,
        flow: FlowType::Normal,
    };
    let op = w >> 26;
    match op {
        0b000101 => {
            d.targets.push(branch26_target(addr, w));
            d.flow = FlowType::UnconditionalBranch;
        }
        0b100101 => {
            d.targets.push(branch26_target(addr, w));
            d.flow = FlowType::Call;
        }
        _ => {
            decode_a64_other(addr, w, &mut d);
        }
    }
    if let Some(t) = d.pc_rel {
        if !d.targets.contains(&t) {
            d.targets.push(t);
        }
    }
    d
}

/// Decode RET, BR, BLR, BRK, and delegate to branch/pcrel decoders.
fn decode_a64_other(addr: u64, w: u32, d: &mut A64Decoded) {
    // RET: 1101_0110_0101_1111_0000_00 Rn 00000
    if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
        d.flow = FlowType::Return;
        return;
    }
    // BR Xn (indirect branch): 1101_0110_0001_1111_0000_00 Rn 00000
    if (w & 0xFFFF_FC1F) == 0xD61F_0000 {
        d.flow = FlowType::IndirectBranch;
        return;
    }
    // BLR Xn (indirect call): 1101_0110_0011_1111_0000_00 Rn 00000
    if (w & 0xFFFF_FC1F) == 0xD63F_0000 {
        d.flow = FlowType::IndirectCall;
        return;
    }
    // BRK #imm16: HLT/trap
    if (w & 0xFFE0_0000) == 0xD420_0000 {
        d.flow = FlowType::Halt;
        return;
    }
    decode_a64_branches(addr, w, d);
}

/// Decode conditional branches: B.cond, CBZ/CBNZ, TBZ/TBNZ.
fn decode_a64_branches(addr: u64, w: u32, d: &mut A64Decoded) {
    // B.cond: 0101_0100 imm19[23:5] 0 cond[3:0]
    if (w & 0xFF00_0010) == 0x5400_0000 {
        d.targets.push(branch19_target(addr, w));
        d.flow = FlowType::ConditionalBranch;
        return;
    }
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    if (w & 0x7E00_0000) == 0x3400_0000 {
        d.targets.push(branch19_target(addr, w));
        d.flow = FlowType::ConditionalBranch;
        return;
    }
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if (w & 0x7E00_0000) == 0x3600_0000 {
        d.targets.push(branch14_target(addr, w));
        d.flow = FlowType::ConditionalBranch;
        return;
    }
    decode_a64_pcrel(addr, w, d);
}

/// Decode PC-relative instructions: ADRP, ADR, LDR literal.
fn decode_a64_pcrel(addr: u64, w: u32, d: &mut A64Decoded) {
    // ADRP
    if (w & 0x9F00_0000) == 0x9000_0000 {
        d.pc_rel = Some(adrp_target(addr, w));
        return;
    }
    // ADR
    if (w & 0x9F00_0000) == 0x1000_0000 {
        d.pc_rel = Some(adr_target(addr, w));
        return;
    }
    // LDR literal
    if (w & 0x3B00_0000) == 0x1800_0000 {
        d.pc_rel = Some(branch19_target(addr, w));
    }
}

/// Compute target from a 26-bit signed immediate (B/BL).
fn branch26_target(addr: u64, w: u32) -> u64 {
    let imm26 = (w & 0x03FF_FFFF) as i32;
    let offset = sign_extend(imm26, 26) << 2;
    (addr as i64 + offset as i64) as u64
}

/// Compute target from a 19-bit signed immediate (B.cond, CBZ, CBNZ).
fn branch19_target(addr: u64, w: u32) -> u64 {
    let imm19 = ((w >> 5) & 0x7FFFF) as i32;
    let offset = sign_extend(imm19, 19) << 2;
    (addr as i64 + offset as i64) as u64
}

/// Compute target from a 14-bit signed immediate (TBZ/TBNZ).
fn branch14_target(addr: u64, w: u32) -> u64 {
    let imm14 = ((w >> 5) & 0x3FFF) as i32;
    let offset = sign_extend(imm14, 14) << 2;
    (addr as i64 + offset as i64) as u64
}

/// Compute ADRP target (page-aligned PC-relative).
fn adrp_target(addr: u64, w: u32) -> u64 {
    let immhi = ((w >> 5) & 0x7FFFF) as i64;
    let immlo = ((w >> 29) & 0x3) as i64;
    let imm = (immhi << 2) | immlo;
    let offset = sign_extend(imm as i32, 21) as i64;
    let page = (addr & !0xFFF) as i64;
    (page + (offset << 12)) as u64
}

/// Compute ADR target (PC-relative byte offset).
fn adr_target(addr: u64, w: u32) -> u64 {
    let immhi = ((w >> 5) & 0x7FFFF) as i64;
    let immlo = ((w >> 29) & 0x3) as i64;
    let imm = (immhi << 2) | immlo;
    let offset = sign_extend(imm as i32, 21) as i64;
    (addr as i64 + offset) as u64
}

/// Sign-extend an integer from the given bit width to 32 bits.
fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
