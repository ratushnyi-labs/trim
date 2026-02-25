use crate::format::dotnet::metadata::read_u32;
use std::collections::{HashMap, HashSet};

/// CIL opcodes that reference methods.
const OP_CALL: u8 = 0x28;
const OP_CALLVIRT: u8 = 0x6F;
const OP_NEWOBJ: u8 = 0x73;
const OP_LDFTN_PREFIX: u8 = 0xFE;
const OP_LDFTN: u8 = 0x06;
const OP_LDVIRTFTN: u8 = 0x07;

/// Build call graph from IL method bodies.
/// Returns map: caller method index -> set of callee
/// method tokens (MethodDef or MemberRef).
pub fn build_il_call_graph(
    data: &[u8],
    method_rvas: &[u32],
    pe_rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> HashMap<usize, HashSet<u32>> {
    let mut graph: HashMap<usize, HashSet<u32>> =
        HashMap::new();
    for (idx, &rva) in method_rvas.iter().enumerate() {
        if rva == 0 {
            continue;
        }
        let off = match pe_rva_to_offset(rva) {
            Some(o) => o,
            None => continue,
        };
        let calls = parse_method_body(data, off);
        if !calls.is_empty() {
            graph.insert(idx, calls);
        }
    }
    graph
}

/// Parse a single IL method body, extract tokens.
fn parse_method_body(
    data: &[u8],
    offset: usize,
) -> HashSet<u32> {
    let mut tokens = HashSet::new();
    if offset >= data.len() {
        return tokens;
    }
    let header = data[offset];
    let (code_off, code_size) = if header & 0x03 == 0x02 {
        (offset + 1, (header >> 2) as usize)
    } else if header & 0x03 == 0x03 {
        parse_fat_header(data, offset)
    } else {
        return tokens;
    };
    if code_off + code_size > data.len() {
        return tokens;
    }
    scan_il_opcodes(
        data, code_off, code_size, &mut tokens,
    );
    tokens
}

fn parse_fat_header(
    data: &[u8],
    offset: usize,
) -> (usize, usize) {
    if offset + 12 > data.len() {
        return (0, 0);
    }
    let flags_size = data[offset] as u16
        | ((data[offset + 1] as u16) << 8);
    let hdr_size = ((flags_size >> 12) & 0x0F) * 4;
    let code_size = read_u32(data, offset + 4) as usize;
    (offset + hdr_size as usize, code_size)
}

/// Scan IL opcodes for method call tokens.
fn scan_il_opcodes(
    data: &[u8],
    start: usize,
    size: usize,
    tokens: &mut HashSet<u32>,
) {
    let end = start + size;
    let mut pos = start;
    while pos < end {
        let op = data[pos];
        pos += 1;
        if op == OP_CALL
            || op == OP_CALLVIRT
            || op == OP_NEWOBJ
        {
            if pos + 4 <= end {
                let token = read_u32(data, pos);
                tokens.insert(token);
            }
            pos += 4;
        } else if op == OP_LDFTN_PREFIX && pos < end {
            let op2 = data[pos];
            pos += 1;
            if (op2 == OP_LDFTN || op2 == OP_LDVIRTFTN)
                && pos + 4 <= end
            {
                let token = read_u32(data, pos);
                tokens.insert(token);
            }
            pos += op2_size(op2);
        } else {
            pos += opcode_operand_size(op);
        }
    }
}

/// Operand size for single-byte opcodes.
fn opcode_operand_size(op: u8) -> usize {
    match op {
        0x00..=0x1F | 0x25..=0x26 | 0x2A..=0x2B => 0,
        0x20 | 0x22 | 0x27..=0x29 => 4,
        0x21 | 0x23 => 8,
        0x2C..=0x37 => 1,
        0x38..=0x43 | 0x45 => 4,
        0x44 | 0x46..=0x6E => 0,
        0x6F..=0x75 | 0x79 | 0x7F..=0x8D => 4,
        0x76..=0x78 | 0x7A..=0x7E | 0x8E..=0x99 => 0,
        0xA2..=0xA5 | 0xD6..=0xDC => 0,
        0xD0..=0xD3 | 0xE0 => 4,
        _ => 0,
    }
}

/// Operand size for two-byte opcodes (0xFE prefix).
fn op2_size(op2: u8) -> usize {
    match op2 {
        0x00..=0x01 => 0,
        0x02..=0x05 => 0,
        0x06..=0x07 => 4,
        0x09..=0x0F => 0,
        0x12 => 0,
        0x15..=0x1A => 0,
        0x1C..=0x1E => 0,
        _ => 0,
    }
}
