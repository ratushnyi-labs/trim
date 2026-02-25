use crate::types::DecodedInstr;

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
        let (targets, pc_rel, is_call) =
            decode_a64_word(addr, word);
        instrs.push(DecodedInstr {
            addr,
            raw,
            len: 4,
            targets,
            pc_rel_target: pc_rel,
            is_call,
        });
        offset += 4;
    }
    instrs
}

fn decode_a64_word(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, bool) {
    let mut targets = Vec::new();
    let mut pc_rel = None;
    let mut is_call = false;
    let op = w >> 26;
    match op {
        0b000101 => {
            // B imm26
            let t = branch26_target(addr, w);
            targets.push(t);
        }
        0b100101 => {
            // BL imm26
            let t = branch26_target(addr, w);
            targets.push(t);
            is_call = true;
        }
        _ => {
            decode_a64_other(
                addr,
                w,
                &mut targets,
                &mut pc_rel,
            );
        }
    }
    if let Some(t) = pc_rel {
        if !targets.contains(&t) {
            targets.push(t);
        }
    }
    (targets, pc_rel, is_call)
}

fn decode_a64_other(
    addr: u64,
    w: u32,
    targets: &mut Vec<u64>,
    pc_rel: &mut Option<u64>,
) {
    // B.cond: 0101_0100 imm19[23:5] 0 cond[3:0]
    if (w & 0xFF00_0010) == 0x5400_0000 {
        let t = branch19_target(addr, w);
        targets.push(t);
        return;
    }
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    if (w & 0x7E00_0000) == 0x3400_0000 {
        let t = branch19_target(addr, w);
        targets.push(t);
        return;
    }
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if (w & 0x7E00_0000) == 0x3600_0000 {
        let t = branch14_target(addr, w);
        targets.push(t);
        return;
    }
    // ADRP: 1 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
    if (w & 0x9F00_0000) == 0x9000_0000 {
        *pc_rel = Some(adrp_target(addr, w));
        return;
    }
    // ADR: 0 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
    if (w & 0x9F00_0000) == 0x1000_0000 {
        *pc_rel = Some(adr_target(addr, w));
        return;
    }
    // LDR literal: opc[31:30] 011 V[26] 00 imm19[23:5] Rt
    if (w & 0x3B00_0000) == 0x1800_0000 {
        let t = branch19_target(addr, w);
        *pc_rel = Some(t);
    }
}

fn branch26_target(addr: u64, w: u32) -> u64 {
    let imm26 = (w & 0x03FF_FFFF) as i32;
    let offset = sign_extend(imm26, 26) << 2;
    (addr as i64 + offset as i64) as u64
}

fn branch19_target(addr: u64, w: u32) -> u64 {
    let imm19 = ((w >> 5) & 0x7FFFF) as i32;
    let offset = sign_extend(imm19, 19) << 2;
    (addr as i64 + offset as i64) as u64
}

fn branch14_target(addr: u64, w: u32) -> u64 {
    let imm14 = ((w >> 5) & 0x3FFF) as i32;
    let offset = sign_extend(imm14, 14) << 2;
    (addr as i64 + offset as i64) as u64
}

fn adrp_target(addr: u64, w: u32) -> u64 {
    let immhi = ((w >> 5) & 0x7FFFF) as i64;
    let immlo = ((w >> 29) & 0x3) as i64;
    let imm = (immhi << 2) | immlo;
    let offset = sign_extend(imm as i32, 21) as i64;
    let page = (addr & !0xFFF) as i64;
    (page + (offset << 12)) as u64
}

fn adr_target(addr: u64, w: u32) -> u64 {
    let immhi = ((w >> 5) & 0x7FFFF) as i64;
    let immlo = ((w >> 29) & 0x3) as i64;
    let imm = (immhi << 2) | immlo;
    let offset = sign_extend(imm as i32, 21) as i64;
    (addr as i64 + offset) as u64
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
