use crate::types::{DecodedInstr, FlowType};

/// Decode RISC-V instructions (RV32/RV64 + C extension).
/// Base instructions are 32-bit little-endian.
/// Compressed (C) instructions are 16-bit, detected when
/// the low 2 bits are not `11`.
pub fn decode_text_riscv(
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
    while offset < slice.len() {
        let addr = text_vaddr + offset as u64;
        if offset + 2 > slice.len() {
            break;
        }
        let lo2 = slice[offset] & 0x03;
        if lo2 != 0x03 {
            let raw = slice[offset..offset + 2].to_vec();
            let hw = u16::from_le_bytes(
                raw[..2].try_into().unwrap_or([0; 2]),
            );
            let d = decode_compressed(addr, hw);
            instrs.push(d);
            offset += 2;
        } else {
            if offset + 4 > slice.len() {
                break;
            }
            let raw = slice[offset..offset + 4].to_vec();
            let word = u32::from_le_bytes(
                raw[..4].try_into().unwrap_or([0; 4]),
            );
            let d = decode_rv_word(addr, word);
            instrs.push(d);
            offset += 4;
        }
    }
    instrs
}

fn decode_rv_word(addr: u64, w: u32) -> DecodedInstr {
    let opcode = w & 0x7F;
    let (targets, pc_rel, flow) = match opcode {
        0x6F => decode_jal(addr, w),
        0x67 => decode_jalr(w),
        0x63 => decode_branch(addr, w),
        0x17 => decode_auipc(addr, w),
        0x73 => decode_system(w),
        _ => (Vec::new(), None, FlowType::Normal),
    };
    DecodedInstr {
        addr,
        raw: w.to_le_bytes().to_vec(),
        len: 4,
        targets,
        pc_rel_target: pc_rel,
        is_call: matches!(flow, FlowType::Call),
        flow,
    }
}

fn decode_jal(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let rd = (w >> 7) & 0x1F;
    let imm = jal_imm(w);
    let target = (addr as i64 + imm as i64) as u64;
    let flow = if rd == 1 || rd == 5 {
        FlowType::Call
    } else {
        FlowType::UnconditionalBranch
    };
    (vec![target], None, flow)
}

fn decode_jalr(
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let rd = (w >> 7) & 0x1F;
    let rs1 = (w >> 15) & 0x1F;
    let flow = if rd == 0 && rs1 == 1 {
        FlowType::Return
    } else if rd == 1 || rd == 5 {
        FlowType::IndirectCall
    } else {
        FlowType::IndirectBranch
    };
    (Vec::new(), None, flow)
}

fn decode_branch(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = branch_imm(w);
    let target = (addr as i64 + imm as i64) as u64;
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_auipc(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = (w & 0xFFFFF000) as i32 as i64;
    let target = (addr as i64 + imm) as u64;
    (Vec::new(), Some(target), FlowType::Normal)
}

fn decode_system(
    w: u32,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let funct12 = w >> 20;
    let flow = match funct12 {
        0x000 | 0x001 => FlowType::Halt,
        _ => FlowType::Normal,
    };
    (Vec::new(), None, flow)
}

fn decode_compressed(addr: u64, hw: u16) -> DecodedInstr {
    let op = hw & 0x03;
    let funct3 = (hw >> 13) & 0x07;
    let (targets, pc_rel, flow) = match (op, funct3) {
        (0x01, 0x05) => decode_c_j(addr, hw),
        (0x01, 0x01) => decode_c_jal(addr, hw),
        (0x01, 0x06) => decode_c_beqz(addr, hw),
        (0x01, 0x07) => decode_c_bnez(addr, hw),
        (0x02, 0x04) => decode_c_jr_jalr(hw),
        _ => (Vec::new(), None, FlowType::Normal),
    };
    DecodedInstr {
        addr,
        raw: hw.to_le_bytes().to_vec(),
        len: 2,
        targets,
        pc_rel_target: pc_rel,
        is_call: matches!(flow, FlowType::Call),
        flow,
    }
}

fn decode_c_j(
    addr: u64,
    hw: u16,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = c_j_imm(hw);
    let target = (addr as i64 + imm as i64) as u64;
    (vec![target], None, FlowType::UnconditionalBranch)
}

fn decode_c_jal(
    addr: u64,
    hw: u16,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = c_j_imm(hw);
    let target = (addr as i64 + imm as i64) as u64;
    (vec![target], None, FlowType::Call)
}

fn decode_c_beqz(
    addr: u64,
    hw: u16,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = c_branch_imm(hw);
    let target = (addr as i64 + imm as i64) as u64;
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_c_bnez(
    addr: u64,
    hw: u16,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let imm = c_branch_imm(hw);
    let target = (addr as i64 + imm as i64) as u64;
    (vec![target], None, FlowType::ConditionalBranch)
}

fn decode_c_jr_jalr(
    hw: u16,
) -> (Vec<u64>, Option<u64>, FlowType) {
    let rs2 = (hw >> 2) & 0x1F;
    let rs1 = (hw >> 7) & 0x1F;
    let bit12 = (hw >> 12) & 1;
    if rs2 != 0 {
        return (Vec::new(), None, FlowType::Normal);
    }
    if rs1 == 0 {
        return (Vec::new(), None, FlowType::Normal);
    }
    let flow = if bit12 == 0 {
        if rs1 == 1 {
            FlowType::Return
        } else {
            FlowType::IndirectBranch
        }
    } else {
        FlowType::IndirectCall
    };
    (Vec::new(), None, flow)
}

fn jal_imm(w: u32) -> i32 {
    let b20 = ((w >> 31) & 1) as i32;
    let b10_1 = ((w >> 21) & 0x3FF) as i32;
    let b11 = ((w >> 20) & 1) as i32;
    let b19_12 = ((w >> 12) & 0xFF) as i32;
    let raw = (b20 << 20)
        | (b19_12 << 12)
        | (b11 << 11)
        | (b10_1 << 1);
    sign_extend(raw, 21)
}

fn branch_imm(w: u32) -> i32 {
    let b12 = ((w >> 31) & 1) as i32;
    let b10_5 = ((w >> 25) & 0x3F) as i32;
    let b4_1 = ((w >> 8) & 0xF) as i32;
    let b11 = ((w >> 7) & 1) as i32;
    let raw =
        (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    sign_extend(raw, 13)
}

fn c_j_imm(hw: u16) -> i32 {
    let bits = ((hw >> 2) & 0x7FF) as u32;
    let b5 = (bits >> 0) & 1;
    let b3_1 = (bits >> 1) & 0x7;
    let b7 = (bits >> 4) & 1;
    let b6 = (bits >> 5) & 1;
    let b10 = (bits >> 6) & 1;
    let b9_8 = (bits >> 7) & 0x3;
    let b4 = (bits >> 9) & 1;
    let b11 = (bits >> 10) & 1;
    let raw = (b11 << 11)
        | (b10 << 10)
        | (b9_8 << 8)
        | (b7 << 7)
        | (b6 << 6)
        | (b5 << 5)
        | (b4 << 4)
        | (b3_1 << 1);
    sign_extend(raw as i32, 12)
}

fn c_branch_imm(hw: u16) -> i32 {
    let lo = ((hw >> 2) & 0x1F) as u32;
    let hi = ((hw >> 10) & 0x07) as u32;
    let b5 = (lo >> 0) & 1;
    let b2_1 = (lo >> 1) & 0x3;
    let b7_6 = (lo >> 3) & 0x3;
    let b4_3 = (hi >> 0) & 0x3;
    let b8 = (hi >> 2) & 1;
    let raw = (b8 << 8)
        | (b7_6 << 6)
        | (b5 << 5)
        | (b4_3 << 3)
        | (b2_1 << 1);
    sign_extend(raw as i32, 9)
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
