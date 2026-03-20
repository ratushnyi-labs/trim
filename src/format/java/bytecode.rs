/// Java bytecode analysis: call graph and dead branch detection.
use super::classfile::{cp_utf8, ClassFile, CpEntry};
use crate::analysis::cfg::DeadBlock;
use std::collections::{HashMap, HashSet};

/// Build call graph: method_index -> set of called method_indices.
/// Only tracks calls to methods within the same class.
pub fn build_call_graph(
    cf: &ClassFile,
) -> HashMap<usize, HashSet<usize>> {
    let mut graph: HashMap<usize, HashSet<usize>> =
        HashMap::new();
    for (idx, m) in cf.methods.iter().enumerate() {
        let callees = scan_calls(cf, m.code_offset, m.code_length);
        graph.insert(idx, callees);
    }
    graph
}

fn scan_calls(
    cf: &ClassFile,
    code_offset: Option<usize>,
    code_length: usize,
) -> HashSet<usize> {
    let callees = HashSet::new();
    let (off, len) = match code_offset {
        Some(o) => (o, code_length),
        None => return callees,
    };
    // We need to read from the classfile data, but we
    // only have the parsed structure. Instead, resolve
    // by matching method names via the constant pool.
    // This is set up in the caller via the ClassFile.
    let _ = (cf, off, len);
    callees
}

/// Scan bytecode for invoke* instructions, returning
/// indices of called internal methods.
pub fn scan_bytecode_calls(
    data: &[u8],
    cf: &ClassFile,
    code_offset: usize,
    code_length: usize,
) -> HashSet<usize> {
    let mut callees = HashSet::new();
    let end = code_offset + code_length;
    if end > data.len() {
        return callees;
    }
    let mut pos = code_offset;
    while pos < end {
        let op = data[pos];
        match op {
            // invokevirtual, invokespecial, invokestatic
            0xB6 | 0xB7 | 0xB8 => {
                if pos + 3 <= end {
                    let idx = read_u16_be(data, pos + 1);
                    if let Some(mi) =
                        resolve_method_idx(cf, idx)
                    {
                        callees.insert(mi);
                    }
                }
                pos += 3;
            }
            // invokeinterface
            0xB9 => {
                if pos + 3 <= end {
                    let idx = read_u16_be(data, pos + 1);
                    if let Some(mi) =
                        resolve_method_idx(cf, idx)
                    {
                        callees.insert(mi);
                    }
                }
                pos += 5;
            }
            // invokedynamic
            0xBA => {
                pos += 5;
            }
            _ => {
                pos += opcode_length(op, data, pos, end);
            }
        }
    }
    callees
}

/// Resolve a Methodref/InterfaceMethodref CP index to a
/// local method index, if the target is in this class.
fn resolve_method_idx(
    cf: &ClassFile,
    cp_idx: u16,
) -> Option<usize> {
    let pool = &cf.constant_pool;
    let i = cp_idx as usize;
    if i >= pool.len() {
        return None;
    }
    let (class_idx, nat_idx) = match &pool[i] {
        CpEntry::Methodref(c, n)
        | CpEntry::InterfaceMethodref(c, n) => {
            (*c, *n)
        }
        _ => return None,
    };
    // Check if class matches this_class (simplified:
    // check if the class name matches any method we have)
    let _ = class_idx;
    let nat_i = nat_idx as usize;
    if nat_i >= pool.len() {
        return None;
    }
    let (name_idx, desc_idx) = match &pool[nat_i] {
        CpEntry::NameAndType(n, d) => (*n, *d),
        _ => return None,
    };
    let name = cp_utf8(pool, name_idx);
    let desc = cp_utf8(pool, desc_idx);
    // Match against this class's methods
    cf.methods.iter().position(|m| {
        cp_utf8(pool, m.name_index) == name
            && cp_utf8(pool, m.descriptor_index) == desc
    })
}

/// Find dead branches within live methods' bytecodes.
pub fn find_dead_branches(
    data: &[u8],
    cf: &ClassFile,
    live: &HashSet<usize>,
) -> Vec<DeadBlock> {
    let mut blocks = Vec::new();
    for (idx, m) in cf.methods.iter().enumerate() {
        if !live.contains(&idx) {
            continue;
        }
        let (off, len) = match m.code_offset {
            Some(o) => (o, m.code_length),
            None => continue,
        };
        scan_dead_in_method(
            data, cf, off, len, m.name_index,
            &mut blocks,
        );
    }
    blocks
}

fn scan_dead_in_method(
    data: &[u8],
    cf: &ClassFile,
    code_offset: usize,
    code_length: usize,
    name_idx: u16,
    blocks: &mut Vec<DeadBlock>,
) {
    let end = code_offset + code_length;
    if end > data.len() {
        return;
    }
    // Collect branch targets and exception handler entries
    let targets = collect_branch_targets(
        data, code_offset, code_length,
    );
    let name = cp_utf8(&cf.constant_pool, name_idx);
    let mut pos = code_offset;
    let mut dead_start: Option<usize> = None;
    while pos < end {
        if let Some(ds) = dead_start {
            // In dead region — check if this is a branch target
            if targets.contains(
                &((pos - code_offset) as u32),
            ) {
                let dead_sz = pos - ds;
                if dead_sz >= 2 {
                    blocks.push(DeadBlock {
                        func_name: name.to_string(),
                        addr: ds as u64,
                        size: dead_sz as u64,
                    });
                }
                dead_start = None;
            } else {
                pos += opcode_length(
                    data[pos], data, pos, end,
                );
                continue;
            }
        }
        let op = data[pos];
        let is_terminator = matches!(
            op,
            0xAC  // ireturn
            | 0xAD  // lreturn
            | 0xAE  // freturn
            | 0xAF  // dreturn
            | 0xB0  // areturn
            | 0xB1  // return
            | 0xBF  // athrow
            | 0xA7  // goto
            | 0xC8  // goto_w
        );
        let ilen =
            opcode_length(op, data, pos, end);
        pos += ilen;
        if is_terminator && pos < end {
            dead_start = Some(pos);
        }
    }
    // Flush trailing dead region
    if let Some(ds) = dead_start {
        let dead_sz = end - ds;
        if dead_sz >= 2 {
            blocks.push(DeadBlock {
                func_name: name.to_string(),
                addr: ds as u64,
                size: dead_sz as u64,
            });
        }
    }
}

fn collect_branch_targets(
    data: &[u8],
    code_offset: usize,
    code_length: usize,
) -> HashSet<u32> {
    let mut targets = HashSet::new();
    let end = code_offset + code_length;
    let mut pos = code_offset;
    while pos < end {
        let op = data[pos];
        let rel_pc = (pos - code_offset) as i32;
        match op {
            // Conditional branches (2-byte offset)
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA8 => {
                if pos + 3 <= end {
                    let off = read_i16_be(data, pos + 1)
                        as i32;
                    let tgt = (rel_pc + off) as u32;
                    targets.insert(tgt);
                }
            }
            // goto (2-byte offset)
            0xA7 => {
                if pos + 3 <= end {
                    let off = read_i16_be(data, pos + 1)
                        as i32;
                    let tgt = (rel_pc + off) as u32;
                    targets.insert(tgt);
                }
            }
            // goto_w, jsr_w (4-byte offset)
            0xC8 | 0xC9 => {
                if pos + 5 <= end {
                    let off = read_i32_be(data, pos + 1);
                    let tgt = (rel_pc + off) as u32;
                    targets.insert(tgt);
                }
            }
            // tableswitch
            0xAA => {
                let base = pos - code_offset;
                let pad = (4 - ((base + 1) % 4)) % 4;
                let p = pos + 1 + pad;
                if p + 12 <= end {
                    let def =
                        read_i32_be(data, p);
                    targets.insert(
                        (rel_pc + def) as u32,
                    );
                    let low =
                        read_i32_be(data, p + 4);
                    let high =
                        read_i32_be(data, p + 8);
                    let n =
                        (high - low + 1).max(0) as usize;
                    for j in 0..n {
                        let o = p + 12 + j * 4;
                        if o + 4 <= end {
                            let off =
                                read_i32_be(data, o);
                            targets.insert(
                                (rel_pc + off) as u32,
                            );
                        }
                    }
                }
            }
            // lookupswitch
            0xAB => {
                let base = pos - code_offset;
                let pad = (4 - ((base + 1) % 4)) % 4;
                let p = pos + 1 + pad;
                if p + 8 <= end {
                    let def =
                        read_i32_be(data, p);
                    targets.insert(
                        (rel_pc + def) as u32,
                    );
                    let n =
                        read_i32_be(data, p + 4) as usize;
                    for j in 0..n {
                        let o = p + 8 + j * 8 + 4;
                        if o + 4 <= end {
                            let off =
                                read_i32_be(data, o);
                            targets.insert(
                                (rel_pc + off) as u32,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        pos += opcode_length(op, data, pos, end);
    }
    targets
}

/// Return the length of a JVM bytecode instruction.
fn opcode_length(
    op: u8,
    data: &[u8],
    pos: usize,
    end: usize,
) -> usize {
    match op {
        // 1-byte instructions (no operands)
        0x00..=0x0F | 0x1A..=0x35 | 0x46..=0x83
        | 0x85..=0x98 | 0xAC..=0xB1 | 0xBE | 0xBF
        | 0xC2 | 0xC3 | 0xCA => 1,
        // 2-byte (1 operand byte)
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A
        | 0xA9 | 0xBC => 2,
        // 3-byte (2 operand bytes)
        0x11 | 0x13 | 0x14 | 0x84 | 0x99..=0xA8
        | 0xB2..=0xB8 | 0xBB | 0xBD | 0xC0 | 0xC1
        | 0xC6 | 0xC7 => 3,
        // 4-byte
        0xC8 | 0xC9 => 5, // goto_w, jsr_w
        // 5-byte
        0xB9 | 0xBA => 5, // invokeinterface, invokedynamic
        // multinewarray
        0xC5 => 4,
        // wide prefix
        0xC4 => {
            if pos + 1 < end {
                if data[pos + 1] == 0x84 {
                    6 // wide iinc
                } else {
                    4 // wide load/store
                }
            } else {
                2
            }
        }
        // tableswitch (variable)
        0xAA => {
            let base = if pos >= end { 0 } else { pos };
            let pad = (4 - ((base + 1) % 4)) % 4;
            let p = pos + 1 + pad;
            if p + 12 <= end {
                let low = read_i32_be(data, p + 4);
                let high = read_i32_be(data, p + 8);
                let n =
                    (high - low + 1).max(0) as usize;
                1 + pad + 12 + n * 4
            } else {
                1
            }
        }
        // lookupswitch (variable)
        0xAB => {
            let base = if pos >= end { 0 } else { pos };
            let pad = (4 - ((base + 1) % 4)) % 4;
            let p = pos + 1 + pad;
            if p + 8 <= end {
                let n =
                    read_i32_be(data, p + 4) as usize;
                1 + pad + 8 + n * 8
            } else {
                1
            }
        }
        _ => 1,
    }
}

fn read_u16_be(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(
        data[off..off + 2].try_into().unwrap_or([0; 2]),
    )
}

fn read_i16_be(data: &[u8], off: usize) -> i16 {
    i16::from_be_bytes(
        data[off..off + 2].try_into().unwrap_or([0; 2]),
    )
}

fn read_i32_be(data: &[u8], off: usize) -> i32 {
    i32::from_be_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    )
}
