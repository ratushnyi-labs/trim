use crate::types::DecodedInstr;

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
        let (targets, pc_rel, is_call) =
            decode_arm32_word(addr, word);
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

fn decode_arm32_word(
    addr: u64,
    w: u32,
) -> (Vec<u64>, Option<u64>, bool) {
    let mut targets = Vec::new();
    let is_call;
    // BLX (immediate): 1111 101 H imm24
    if (w & 0xFE00_0000) == 0xFA00_0000 {
        let imm24 = (w & 0x00FF_FFFF) as i32;
        let h = ((w >> 24) & 1) as i64;
        let offset = (sign_extend(imm24, 24) as i64) << 2 | h << 1;
        // ARM pipeline: PC = addr + 8
        let t = (addr as i64 + 8 + offset) as u64;
        targets.push(t);
        return (targets, None, true);
    }
    // B/BL: cond 101 L imm24
    let top = (w >> 25) & 0x7F;
    if top == 0b0000101 || top == 0b0001101
        || top == 0b0010101 || top == 0b0011101
        || top == 0b0100101 || top == 0b0101101
        || top == 0b0110101 || top == 0b0111101
        || top == 0b1000101 || top == 0b1001101
        || top == 0b1010101 || top == 0b1011101
        || top == 0b1100101 || top == 0b1101101
        || top == 0b1110101
    {
        is_call = (w >> 24) & 1 == 1;
        let imm24 = (w & 0x00FF_FFFF) as i32;
        let offset = (sign_extend(imm24, 24) as i64) << 2;
        let t = (addr as i64 + 8 + offset) as u64;
        targets.push(t);
        return (targets, None, is_call);
    }
    (targets, None, false)
}

fn sign_extend(val: i32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (val << shift) >> shift
}
