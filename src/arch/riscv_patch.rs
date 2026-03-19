use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, Section};

/// Check if a byte is RISC-V padding (0x00 = c.unimp).
pub fn is_padding_riscv(b: u8) -> bool {
    b == 0x00
}

/// Patch branch offsets in RISC-V instructions after dead code
/// removal shifts addresses.
pub fn patch_branches(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    patch_auipc_pairs(data, instrs, intervals, sections, ts, te);
    for instr in instrs {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        patch_one(data, instr, intervals, sections, ts, te);
    }
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}

/// Encode a J-type immediate for JAL.
fn encode_jal_imm(offset: i32) -> u32 {
    let imm = offset as u32;
    let b20 = (imm >> 20) & 1;
    let b10_1 = (imm >> 1) & 0x3FF;
    let b11 = (imm >> 11) & 1;
    let b19_12 = (imm >> 12) & 0xFF;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12)
}

/// Encode a B-type immediate for BEQ/BNE/BLT/BGE/BLTU/BGEU.
fn encode_branch_imm(offset: i32) -> u32 {
    let imm = offset as u32;
    let b12 = (imm >> 12) & 1;
    let b10_5 = (imm >> 5) & 0x3F;
    let b4_1 = (imm >> 1) & 0xF;
    let b11 = (imm >> 11) & 1;
    (b12 << 31) | (b10_5 << 25) | (b4_1 << 8) | (b11 << 7)
}

/// Encode a C.J compressed jump immediate (11-bit).
fn encode_c_j_imm(offset: i32) -> u16 {
    let imm = offset as u32;
    let b5 = (imm >> 5) & 1;
    let b3_1 = (imm >> 1) & 0x7;
    let b7 = (imm >> 7) & 1;
    let b6 = (imm >> 6) & 1;
    let b10 = (imm >> 10) & 1;
    let b9_8 = (imm >> 8) & 0x3;
    let b4 = (imm >> 4) & 1;
    let b11 = (imm >> 11) & 1;
    let bits = b5
        | (b3_1 << 1)
        | (b7 << 4)
        | (b6 << 5)
        | (b10 << 6)
        | (b9_8 << 7)
        | (b4 << 9)
        | (b11 << 10);
    (bits as u16) << 2
}

/// Encode a C.BEQZ/C.BNEZ compressed branch immediate (8-bit).
fn encode_c_branch_imm(offset: i32) -> u16 {
    let imm = offset as u32;
    let b5 = (imm >> 5) & 1;
    let b2_1 = (imm >> 1) & 0x3;
    let b7_6 = (imm >> 6) & 0x3;
    let b4_3 = (imm >> 3) & 0x3;
    let b8 = (imm >> 8) & 1;
    let lo = b5 | (b2_1 << 1) | (b7_6 << 3);
    let hi = b4_3 | (b8 << 2);
    ((hi as u16) << 10) | ((lo as u16) << 2)
}

/// Decode J-type immediate from a JAL instruction word.
fn jal_imm(w: u32) -> i32 {
    let b20 = ((w >> 31) & 1) as i32;
    let b10_1 = ((w >> 21) & 0x3FF) as i32;
    let b11 = ((w >> 20) & 1) as i32;
    let b19_12 = ((w >> 12) & 0xFF) as i32;
    let raw =
        (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    sign_extend(raw, 21)
}

/// Decode B-type immediate from a branch instruction word.
fn branch_imm(w: u32) -> i32 {
    let b12 = ((w >> 31) & 1) as i32;
    let b10_5 = ((w >> 25) & 0x3F) as i32;
    let b4_1 = ((w >> 8) & 0xF) as i32;
    let b11 = ((w >> 7) & 1) as i32;
    let raw =
        (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    sign_extend(raw, 13)
}

/// Decode C.J / C.JAL compressed jump immediate.
fn c_j_imm(hw: u16) -> i32 {
    let bits = ((hw >> 2) & 0x7FF) as u32;
    let b5 = bits & 1;
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

/// Decode C.BEQZ/C.BNEZ compressed branch immediate.
fn c_branch_imm(hw: u16) -> i32 {
    let lo = ((hw >> 2) & 0x1F) as u32;
    let hi = ((hw >> 10) & 0x07) as u32;
    let b5 = lo & 1;
    let b2_1 = (lo >> 1) & 0x3;
    let b7_6 = (lo >> 3) & 0x3;
    let b4_3 = hi & 0x3;
    let b8 = (hi >> 2) & 1;
    let raw =
        (b8 << 8) | (b7_6 << 6) | (b5 << 5) | (b4_3 << 3) | (b2_1 << 1);
    sign_extend(raw as i32, 9)
}

fn patch_one(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let foff = match vaddr_to_offset(instr.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };

    if instr.len == 4 {
        patch_one_32(data, instr, foff, intervals, ts, te);
    } else if instr.len == 2 {
        patch_one_16(data, instr, foff, intervals, ts, te);
    }
}

fn patch_one_32(
    data: &mut [u8],
    instr: &DecodedInstr,
    foff: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if instr.raw.len() < 4 || foff + 4 > data.len() {
        return;
    }
    let w = u32::from_le_bytes(
        instr.raw[..4].try_into().unwrap_or([0; 4]),
    );
    let opcode = w & 0x7F;

    match opcode {
        // JAL (J-type)
        0x6F => {
            let old_imm = jal_imm(w);
            let target =
                (instr.addr as i64 + old_imm as i64) as u64;
            let shift_src =
                total_shift(instr.addr, intervals, ts, te) as i64;
            let shift_tgt =
                total_shift(target, intervals, ts, te) as i64;
            let delta = shift_src - shift_tgt;
            if delta == 0 {
                return;
            }
            let new_addr = instr.addr as i64 - shift_src;
            let new_target = target as i64 - shift_tgt;
            let new_offset = (new_target - new_addr) as i32;
            // Preserve rd and opcode (bits 11:0)
            let new_word =
                (w & 0x0000_0FFF) | encode_jal_imm(new_offset);
            data[foff..foff + 4]
                .copy_from_slice(&new_word.to_le_bytes());
        }
        // B-type branches (BEQ, BNE, BLT, BGE, BLTU, BGEU)
        0x63 => {
            let old_imm = branch_imm(w);
            let target =
                (instr.addr as i64 + old_imm as i64) as u64;
            let shift_src =
                total_shift(instr.addr, intervals, ts, te) as i64;
            let shift_tgt =
                total_shift(target, intervals, ts, te) as i64;
            let delta = shift_src - shift_tgt;
            if delta == 0 {
                return;
            }
            let new_addr = instr.addr as i64 - shift_src;
            let new_target = target as i64 - shift_tgt;
            let new_offset = (new_target - new_addr) as i32;
            // Preserve opcode, funct3, rs1, rs2
            let new_word = (w & 0x01FFF07F)
                | encode_branch_imm(new_offset);
            data[foff..foff + 4]
                .copy_from_slice(&new_word.to_le_bytes());
        }
        // AUIPC handled separately in patch_auipc_pairs()
        0x17 => {}
        _ => {}
    }
}

fn patch_one_16(
    data: &mut [u8],
    instr: &DecodedInstr,
    foff: usize,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    if instr.raw.len() < 2 || foff + 2 > data.len() {
        return;
    }
    let hw = u16::from_le_bytes(
        instr.raw[..2].try_into().unwrap_or([0; 2]),
    );
    let op = hw & 0x03;
    let funct3 = (hw >> 13) & 0x07;

    match (op, funct3) {
        // C.J (op=01, funct3=101) or C.JAL (op=01, funct3=001)
        (0x01, 0x05) | (0x01, 0x01) => {
            let old_imm = c_j_imm(hw);
            let target =
                (instr.addr as i64 + old_imm as i64) as u64;
            let shift_src =
                total_shift(instr.addr, intervals, ts, te) as i64;
            let shift_tgt =
                total_shift(target, intervals, ts, te) as i64;
            let delta = shift_src - shift_tgt;
            if delta == 0 {
                return;
            }
            let new_addr = instr.addr as i64 - shift_src;
            let new_target = target as i64 - shift_tgt;
            let new_offset = (new_target - new_addr) as i32;
            let new_hw =
                (hw & 0xE003) | encode_c_j_imm(new_offset);
            data[foff..foff + 2]
                .copy_from_slice(&new_hw.to_le_bytes());
        }
        // C.BEQZ (op=01, funct3=110) or C.BNEZ (op=01, funct3=111)
        (0x01, 0x06) | (0x01, 0x07) => {
            let old_imm = c_branch_imm(hw);
            let target =
                (instr.addr as i64 + old_imm as i64) as u64;
            let shift_src =
                total_shift(instr.addr, intervals, ts, te) as i64;
            let shift_tgt =
                total_shift(target, intervals, ts, te) as i64;
            let delta = shift_src - shift_tgt;
            if delta == 0 {
                return;
            }
            let new_addr = instr.addr as i64 - shift_src;
            let new_target = target as i64 - shift_tgt;
            let new_offset = (new_target - new_addr) as i32;
            let new_hw = (hw & 0xE383)
                | encode_c_branch_imm(new_offset);
            data[foff..foff + 2]
                .copy_from_slice(&new_hw.to_le_bytes());
        }
        _ => {}
    }
}

// ---- AUIPC + paired instruction patching --------------------------

/// Decode the AUIPC upper offset: bits[31:12] placed at [31:12].
fn auipc_offset(w: u32) -> i64 {
    // U-type: imm[31:12] at instruction bits[31:12], lower 12 zero.
    // Treating as signed i32 gives sign-extension automatically.
    ((w & 0xFFFFF000) as i32) as i64
}

/// Decode I-type immediate (bits[31:20] sign-extended).
fn i_type_imm(w: u32) -> i64 {
    sign_extend((w >> 20) as i32, 12) as i64
}

/// Decode S-type immediate (bits[31:25] || bits[11:7]).
fn s_type_imm(w: u32) -> i64 {
    let hi = ((w >> 25) & 0x7F) as i32;
    let lo = ((w >> 7) & 0x1F) as i32;
    sign_extend((hi << 5) | lo, 12) as i64
}

/// Encode I-type immediate into instruction word.
fn encode_i_type_imm(w: u32, imm12: i32) -> u32 {
    (w & 0x000FFFFF) | (((imm12 as u32) & 0xFFF) << 20)
}

/// Encode S-type immediate into instruction word.
fn encode_s_type_imm(w: u32, imm12: i32) -> u32 {
    let imm = imm12 as u32;
    let hi = (imm >> 5) & 0x7F;
    let lo = imm & 0x1F;
    (w & 0x01FFF07F) | (hi << 25) | (lo << 7)
}

/// Patch AUIPC + paired instruction pairs.
///
/// RISC-V uses AUIPC+JALR/ADDI/LD/SD pairs for PC-relative
/// addressing beyond ±4KB. Both instructions must be patched
/// together: AUIPC provides upper 20 bits, the paired instruction
/// provides lower 12 bits (sign-extended).
fn patch_auipc_pairs(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    for (idx, instr) in instrs.iter().enumerate() {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        if instr.len != 4 || instr.raw.len() < 4 {
            continue;
        }
        let w = u32::from_le_bytes(
            instr.raw[..4].try_into().unwrap_or([0; 4]),
        );
        if (w & 0x7F) != 0x17 {
            continue;
        }
        let rd = (w >> 7) & 0x1F;
        if rd == 0 {
            continue;
        }
        if let Some(pair_idx) =
            find_auipc_pair(instrs, idx, rd)
        {
            do_patch_auipc_pair(
                data, instr, &instrs[pair_idx], intervals,
                sections, ts, te,
            );
        }
    }
}

/// Look ahead up to 4 instructions for one using rd as rs1.
fn find_auipc_pair(
    instrs: &[DecodedInstr],
    auipc_idx: usize,
    rd: u32,
) -> Option<usize> {
    let limit = 4.min(instrs.len().saturating_sub(auipc_idx + 1));
    for off in 1..=limit {
        let i = auipc_idx + off;
        let instr = &instrs[i];
        if instr.len != 4 || instr.raw.len() < 4 {
            continue;
        }
        let w = u32::from_le_bytes(
            instr.raw[..4].try_into().unwrap_or([0; 4]),
        );
        let opcode = w & 0x7F;
        let rs1 = (w >> 15) & 0x1F;
        let i_rd = (w >> 7) & 0x1F;
        // I-type: JALR(0x67), loads(0x03), ADDI etc(0x13)
        // S-type: stores(0x23)
        if rs1 == rd {
            match opcode {
                0x67 | 0x03 | 0x13 | 0x23 => {
                    return Some(i);
                }
                _ => {}
            }
        }
        // If this instruction clobbers rd, stop looking
        if i_rd == rd && opcode != 0x23 {
            break;
        }
    }
    None
}

fn do_patch_auipc_pair(
    data: &mut [u8],
    auipc: &DecodedInstr,
    paired: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let auipc_foff = match vaddr_to_offset(auipc.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };
    let pair_foff = match vaddr_to_offset(paired.addr, sections) {
        Some(o) => o as usize,
        None => return,
    };
    if auipc_foff + 4 > data.len() || pair_foff + 4 > data.len() {
        return;
    }
    let aw = u32::from_le_bytes(
        auipc.raw[..4].try_into().unwrap_or([0; 4]),
    );
    let pw = u32::from_le_bytes(
        paired.raw[..4].try_into().unwrap_or([0; 4]),
    );
    let p_opcode = pw & 0x7F;
    let hi_off = auipc_offset(aw);
    let lo_off = if p_opcode == 0x23 {
        s_type_imm(pw)
    } else {
        i_type_imm(pw)
    };
    let old_target =
        (auipc.addr as i64 + hi_off + lo_off) as u64;
    let shift_src =
        total_shift(auipc.addr, intervals, ts, te) as i64;
    let shift_tgt =
        total_shift(old_target, intervals, ts, te) as i64;
    let delta = shift_src - shift_tgt;
    if delta == 0 {
        return;
    }
    let new_addr = auipc.addr as i64 - shift_src;
    let new_target = old_target as i64 - shift_tgt;
    let new_full_offset = new_target - new_addr;
    // Split into hi20 and lo12 with sign-extension compensation
    let hi20 = ((new_full_offset + 0x800) >> 12) as i32;
    let lo12 =
        (new_full_offset - ((hi20 as i64) << 12)) as i32;
    // Encode AUIPC: preserve rd and opcode (bits[11:0])
    let new_aw =
        (aw & 0x0000_0FFF) | ((hi20 as u32) << 12);
    data[auipc_foff..auipc_foff + 4]
        .copy_from_slice(&new_aw.to_le_bytes());
    // Encode paired instruction
    let new_pw = if p_opcode == 0x23 {
        encode_s_type_imm(pw, lo12)
    } else {
        encode_i_type_imm(pw, lo12)
    };
    data[pair_foff..pair_foff + 4]
        .copy_from_slice(&new_pw.to_le_bytes());
}
