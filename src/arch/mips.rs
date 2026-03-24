use crate::types::{DecodedInstr, FlowType};

/// Decode MIPS instructions (fixed 32-bit).
/// Endianness is detected from ELF EI_DATA byte.
pub fn decode_text_mips(
    data: &[u8],
    text_offset: u64,
    text_vaddr: u64,
    text_size: u64,
    big_endian: bool,
) -> Vec<DecodedInstr> {
    let end = text_offset as usize + text_size as usize;
    let slice =
        &data[text_offset as usize..end.min(data.len())];
    let mut instrs = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= slice.len() {
        let addr = text_vaddr + offset as u64;
        let raw = slice[offset..offset + 4].to_vec();
        let word = if big_endian {
            u32::from_be_bytes(
                raw[..4].try_into().unwrap_or([0; 4]),
            )
        } else {
            u32::from_le_bytes(
                raw[..4].try_into().unwrap_or([0; 4]),
            )
        };
        let (targets, flow) = decode_mips_word(addr, word);
        instrs.push(DecodedInstr {
            addr,
            raw,
            len: 4,
            targets,
            pc_rel_target: None,
            is_call: matches!(flow, FlowType::Call),
            flow,
        });
        offset += 4;
    }
    instrs
}

fn decode_mips_word(
    addr: u64,
    w: u32,
) -> (Vec<u64>, FlowType) {
    let op = w >> 26;
    match op {
        0x02 => decode_j(addr, w),
        0x03 => decode_jal(addr, w),
        0x00 => decode_special(w),
        0x01 => decode_regimm(addr, w),
        0x04 | 0x05 | 0x06 | 0x07 => {
            decode_branch_i(addr, w)
        }
        _ => (Vec::new(), FlowType::Normal),
    }
}

fn decode_j(addr: u64, w: u32) -> (Vec<u64>, FlowType) {
    let target = j_target(addr, w);
    (vec![target], FlowType::UnconditionalBranch)
}

fn decode_jal(addr: u64, w: u32) -> (Vec<u64>, FlowType) {
    let target = j_target(addr, w);
    (vec![target], FlowType::Call)
}

fn decode_special(w: u32) -> (Vec<u64>, FlowType) {
    let funct = w & 0x3F;
    match funct {
        0x08 => {
            let rs = (w >> 21) & 0x1F;
            if rs == 31 {
                (Vec::new(), FlowType::Return)
            } else {
                (Vec::new(), FlowType::IndirectBranch)
            }
        }
        0x09 => (Vec::new(), FlowType::IndirectCall),
        0x0C => (Vec::new(), FlowType::Halt),
        0x0D => (Vec::new(), FlowType::Halt),
        _ => (Vec::new(), FlowType::Normal),
    }
}

fn decode_regimm(
    addr: u64,
    w: u32,
) -> (Vec<u64>, FlowType) {
    let rt = (w >> 16) & 0x1F;
    match rt {
        0x00 | 0x01 => {
            let target = branch_target(addr, w);
            (vec![target], FlowType::ConditionalBranch)
        }
        _ => (Vec::new(), FlowType::Normal),
    }
}

fn decode_branch_i(
    addr: u64,
    w: u32,
) -> (Vec<u64>, FlowType) {
    let target = branch_target(addr, w);
    (vec![target], FlowType::ConditionalBranch)
}

fn j_target(addr: u64, w: u32) -> u64 {
    let index = (w & 0x03FF_FFFF) as u64;
    (addr & 0xFFFF_FFFF_F000_0000) | (index << 2)
}

fn branch_target(addr: u64, w: u32) -> u64 {
    let imm16 = (w & 0xFFFF) as i16 as i64;
    (addr as i64 + 4 + (imm16 << 2)) as u64
}
