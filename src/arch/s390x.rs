use crate::types::{DecodedInstr, FlowType};

/// Decode s390x (z/Architecture) instructions.
/// Variable length: 2/4/6 bytes, big-endian.
/// Length determined by first 2 bits of opcode byte.
pub fn decode_text_s390x(
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
        let ilen = instr_len(slice[offset]);
        if offset + ilen > slice.len() {
            break;
        }
        let addr = text_vaddr + offset as u64;
        let raw = slice[offset..offset + ilen].to_vec();
        let (targets, flow) = decode_s390x_instr(addr, &raw);
        instrs.push(DecodedInstr {
            addr,
            raw,
            len: ilen,
            targets,
            pc_rel_target: None,
            is_call: matches!(flow, FlowType::Call),
            flow,
        });
        offset += ilen;
    }
    instrs
}

fn instr_len(first_byte: u8) -> usize {
    match first_byte >> 6 {
        0b00 => 2,
        0b01 | 0b10 => 4,
        _ => 6,
    }
}

fn decode_s390x_instr(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    match raw.len() {
        2 => decode_2byte(raw),
        4 => decode_4byte(addr, raw),
        6 => decode_6byte(addr, raw),
        _ => (Vec::new(), FlowType::Normal),
    }
}

fn decode_2byte(raw: &[u8]) -> (Vec<u64>, FlowType) {
    let op = raw[0];
    match op {
        0x07 => decode_bcr(raw),
        0x0D => decode_basr(raw),
        _ => (Vec::new(), FlowType::Normal),
    }
}

fn decode_bcr(raw: &[u8]) -> (Vec<u64>, FlowType) {
    let mask = (raw[1] >> 4) & 0x0F;
    let r2 = raw[1] & 0x0F;
    if mask == 0 {
        return (Vec::new(), FlowType::Normal);
    }
    if mask == 15 {
        if r2 == 14 {
            return (Vec::new(), FlowType::Return);
        }
        return (Vec::new(), FlowType::IndirectBranch);
    }
    (Vec::new(), FlowType::ConditionalBranch)
}

fn decode_basr(raw: &[u8]) -> (Vec<u64>, FlowType) {
    let r2 = raw[1] & 0x0F;
    if r2 == 0 {
        return (Vec::new(), FlowType::Normal);
    }
    (Vec::new(), FlowType::IndirectCall)
}

fn decode_4byte(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let op_hi = raw[0];
    let op_lo = raw[1];
    if op_hi == 0xA7 {
        let op4 = op_lo & 0x0F;
        return match op4 {
            0x04 => decode_brc(addr, raw),
            0x05 => decode_bras(addr, raw),
            _ => (Vec::new(), FlowType::Normal),
        };
    }
    (Vec::new(), FlowType::Normal)
}

fn decode_brc(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let mask = (raw[1] >> 4) & 0x0F;
    let imm16 = i16::from_be_bytes(
        raw[2..4].try_into().unwrap_or([0; 2]),
    );
    let target =
        (addr as i64 + (imm16 as i64) * 2) as u64;
    let flow = if mask == 15 {
        FlowType::UnconditionalBranch
    } else if mask == 0 {
        return (Vec::new(), FlowType::Normal);
    } else {
        FlowType::ConditionalBranch
    };
    (vec![target], flow)
}

fn decode_bras(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let imm16 = i16::from_be_bytes(
        raw[2..4].try_into().unwrap_or([0; 2]),
    );
    let target =
        (addr as i64 + (imm16 as i64) * 2) as u64;
    (vec![target], FlowType::Call)
}

fn decode_6byte(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let op_hi = raw[0];
    let op_lo = raw[1];
    if op_hi == 0xC0 {
        let op4 = op_lo & 0x0F;
        return match op4 {
            0x04 => decode_brcl(addr, raw),
            0x05 => decode_brasl(addr, raw),
            _ => (Vec::new(), FlowType::Normal),
        };
    }
    (Vec::new(), FlowType::Normal)
}

fn decode_brcl(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let mask = (raw[1] >> 4) & 0x0F;
    let imm32 = i32::from_be_bytes(
        raw[2..6].try_into().unwrap_or([0; 4]),
    );
    let target =
        (addr as i64 + (imm32 as i64) * 2) as u64;
    let flow = if mask == 15 {
        FlowType::UnconditionalBranch
    } else if mask == 0 {
        return (Vec::new(), FlowType::Normal);
    } else {
        FlowType::ConditionalBranch
    };
    (vec![target], flow)
}

fn decode_brasl(
    addr: u64,
    raw: &[u8],
) -> (Vec<u64>, FlowType) {
    let imm32 = i32::from_be_bytes(
        raw[2..6].try_into().unwrap_or([0; 4]),
    );
    let target =
        (addr as i64 + (imm32 as i64) * 2) as u64;
    (vec![target], FlowType::Call)
}
