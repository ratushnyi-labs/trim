//! CIL (Common Intermediate Language) bytecode scanning, opcode tables,
//! dead branch detection, and physical compaction for .NET methods.
//!
//! Provides three main capabilities:
//! 1. **Call-graph construction** -- scans IL method bodies for `call`,
//!    `callvirt`, `newobj`, `ldftn`, and `ldvirtftn` opcodes to extract
//!    callee method tokens (MethodDef / MemberRef).
//! 2. **Dead branch detection** -- identifies unreachable bytecode regions
//!    after `ret`, `throw`, unconditional `br`, and `rethrow` up to the
//!    next branch target.
//! 3. **Physical compaction** -- removes dead byte ranges from method
//!    bodies, patches short/long branch offsets and switch tables, then
//!    updates the method header `code_size`. Bails out to NOP-fill if the
//!    method has exception handlers (fat header MoreSects flag).
//!
//! Key functions:
//! - `build_il_call_graph` -- produces caller-index to callee-token map.
//! - `find_il_dead_blocks` -- returns `Vec<DeadBlock>` for live methods.
//! - `compact_il_dead_blocks` -- in-place compaction with branch patching.

use crate::analysis::cfg::DeadBlock;
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

/// Parse a single IL method body (tiny or fat header) and extract
/// all method-call tokens found in its bytecode.
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

/// Parse a fat method header and return `(code_offset, code_size)`.
/// Returns `(0, 0)` if the header is truncated.
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

// ---- IL dead branch physical compaction -------------------------

/// Physically compact dead branches within live methods.
/// Returns (compacted_count, bytes_saved).
/// Falls back to nop-fill if method has exception handlers.
pub fn compact_il_dead_blocks(
    data: &mut [u8],
    dead_blocks: &[DeadBlock],
    method_rvas: &[u32],
    sections: &[crate::types::Section],
) -> (usize, u64) {
    if dead_blocks.is_empty() {
        return (0, 0);
    }
    let rva_fn = |rva: u32| -> Option<usize> {
        rva_to_offset(sections, rva)
    };
    // Group dead blocks by method
    let mut method_blocks: HashMap<usize, Vec<&DeadBlock>> =
        HashMap::new();
    for db in dead_blocks {
        if let Some(idx) = find_method_for_rva(
            method_rvas, db.addr as u32, data, &rva_fn,
        ) {
            method_blocks.entry(idx).or_default().push(db);
        }
    }
    let mut count = 0usize;
    let mut saved = 0u64;
    for (&idx, blocks) in &method_blocks {
        let rva = method_rvas[idx];
        let off = match rva_fn(rva) {
            Some(o) => o,
            None => continue,
        };
        let (code_off, code_size) =
            match parse_method_header(data, off) {
                Some(v) => v,
                None => continue,
            };
        // Convert dead block RVAs to code-relative ranges
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for db in blocks {
            let db_off = match rva_fn(db.addr as u32) {
                Some(o) => o,
                None => continue,
            };
            let rel_s = db_off.saturating_sub(code_off);
            let rel_e = rel_s + db.size as usize;
            if rel_e <= code_size {
                ranges.push((rel_s, rel_e));
            }
        }
        if ranges.is_empty() { continue; }
        ranges.sort_by_key(|&(s, _)| s);
        let s = compact_one_method(
            data, off, code_off, code_size, &ranges,
        );
        if s > 0 {
            count += blocks.len();
            saved += s;
        } else {
            // Fallback: nop-fill
            for db in blocks {
                if let Some(o) = rva_fn(db.addr as u32) {
                    let sz = db.size as usize;
                    if o + sz <= data.len() {
                        data[o..o + sz].fill(0x00);
                    }
                }
            }
        }
    }
    (count, saved)
}

/// Convert RVA to file offset using section headers.
fn rva_to_offset(
    sections: &[crate::types::Section],
    rva: u32,
) -> Option<usize> {
    let rva64 = rva as u64;
    for s in sections {
        let end = s.vaddr + s.size;
        if rva64 >= s.vaddr && rva64 < end {
            return Some(
                (rva64 - s.vaddr + s.offset) as usize,
            );
        }
    }
    None
}

/// Find which method index a given RVA belongs to.
fn find_method_for_rva(
    method_rvas: &[u32],
    rva: u32,
    data: &[u8],
    rva_fn: &dyn Fn(u32) -> Option<usize>,
) -> Option<usize> {
    for (idx, &mrva) in method_rvas.iter().enumerate() {
        if mrva == 0 { continue; }
        let off = rva_fn(mrva)?;
        let (_, code_size) = parse_method_header(data, off)?;
        let hdr_size = method_header_size(data, off)?;
        let method_end_rva = mrva + hdr_size as u32
            + code_size as u32;
        if rva >= mrva && rva < method_end_rva {
            return Some(idx);
        }
    }
    None
}

/// Parse a method header (tiny or fat) and return `(code_offset, code_size)`.
fn parse_method_header(
    data: &[u8],
    off: usize,
) -> Option<(usize, usize)> {
    if off >= data.len() { return None; }
    let header = data[off];
    if header & 0x03 == 0x02 {
        Some((off + 1, (header >> 2) as usize))
    } else if header & 0x03 == 0x03 {
        let (co, cs) = parse_fat_header(data, off);
        if co == 0 { None } else { Some((co, cs)) }
    } else {
        None
    }
}

/// Return the byte size of a method header (1 for tiny, variable for fat).
fn method_header_size(
    data: &[u8],
    off: usize,
) -> Option<usize> {
    if off >= data.len() { return None; }
    let header = data[off];
    if header & 0x03 == 0x02 {
        Some(1)
    } else if header & 0x03 == 0x03 {
        if off + 2 > data.len() { return None; }
        let fs = data[off] as u16
            | ((data[off + 1] as u16) << 8);
        Some((((fs >> 12) & 0x0F) * 4) as usize)
    } else {
        None
    }
}

/// Compact dead blocks from one method. Returns bytes saved
/// or 0 if compaction was skipped (e.g. exception handlers).
/// `ranges` are code-relative (relative to code_off).
fn compact_one_method(
    data: &mut [u8],
    off: usize,
    code_off: usize,
    code_size: usize,
    ranges: &[(usize, usize)],
) -> u64 {
    if off >= data.len() { return 0; }
    if code_off + code_size > data.len() || code_size == 0 {
        return 0;
    }
    let header = data[off];
    let is_fat = header & 0x03 == 0x03;
    // Bail: fat header with MoreSects (exception handlers)
    if is_fat && off + 1 < data.len() {
        let flags = data[off] as u16
            | ((data[off + 1] as u16) << 8);
        if flags & 0x08 != 0 { return 0; }
    }
    // Patch branch offsets in-place
    patch_il_branches(data, code_off, code_size, ranges);
    // Build compacted bytecode
    let code = &data[code_off..code_off + code_size];
    let compacted = excise_il_ranges(code, ranges);
    let saved = code_size - compacted.len();
    if saved == 0 { return 0; }
    // Write compacted code + zero-fill remainder
    data[code_off..code_off + compacted.len()]
        .copy_from_slice(&compacted);
    data[code_off + compacted.len()..code_off + code_size]
        .fill(0x00);
    // Update header code_size
    let new_size = compacted.len();
    if !is_fat {
        if new_size > 63 { return 0; }
        data[off] = ((new_size as u8) << 2) | 0x02;
    } else if off + 8 <= data.len() {
        let sz_bytes = (new_size as u32).to_le_bytes();
        data[off + 4..off + 8].copy_from_slice(&sz_bytes);
    }
    saved as u64
}

/// Shift function: total dead bytes before `offset`.
fn il_shift(
    offset: usize,
    ranges: &[(usize, usize)],
) -> usize {
    let mut shift = 0;
    for &(s, e) in ranges {
        if s < offset {
            shift += e.min(offset) - s;
        }
    }
    shift
}

/// Patch all branch offsets in IL bytecode, accounting for
/// dead ranges that will be removed.
fn patch_il_branches(
    data: &mut [u8],
    code_off: usize,
    code_size: usize,
    ranges: &[(usize, usize)],
) {
    let end = code_off + code_size;
    let mut pos = code_off;
    while pos < end {
        let op = data[pos];
        let instr_start = pos;
        pos += 1;
        match op {
            // Short branches (1-byte signed offset)
            0x2B..=0x37 => {
                if pos < end {
                    let old =
                        data[pos] as i8 as i32;
                    let src_rel = pos + 1 - code_off;
                    let tgt_rel =
                        src_rel as i32 + old;
                    let new_src =
                        src_rel - il_shift(src_rel, ranges);
                    let new_tgt = tgt_rel as usize
                        - il_shift(tgt_rel as usize, ranges);
                    let new_off =
                        new_tgt as i32 - new_src as i32;
                    data[pos] = new_off as i8 as u8;
                    pos += 1;
                }
            }
            // Long branches (4-byte signed offset)
            0x38..=0x43 => {
                if pos + 4 <= end {
                    let old = i32::from_le_bytes([
                        data[pos], data[pos + 1],
                        data[pos + 2], data[pos + 3],
                    ]);
                    let src_rel = pos + 4 - code_off;
                    let tgt_rel =
                        src_rel as i32 + old;
                    let new_src =
                        src_rel - il_shift(src_rel, ranges);
                    let new_tgt = tgt_rel as usize
                        - il_shift(tgt_rel as usize, ranges);
                    let new_off =
                        new_tgt as i32 - new_src as i32;
                    let bytes = new_off.to_le_bytes();
                    data[pos..pos + 4]
                        .copy_from_slice(&bytes);
                }
                pos += 4;
            }
            // switch
            0x45 => {
                if pos + 4 <= end {
                    let n =
                        read_u32(data, pos) as usize;
                    pos += 4;
                    let base_rel =
                        pos + n * 4 - code_off;
                    for _ in 0..n {
                        if pos + 4 <= end {
                            let old = i32::from_le_bytes([
                                data[pos], data[pos + 1],
                                data[pos + 2], data[pos + 3],
                            ]);
                            let tgt_rel =
                                base_rel as i32 + old;
                            let new_base = base_rel
                                - il_shift(base_rel, ranges);
                            let new_tgt = tgt_rel as usize
                                - il_shift(
                                    tgt_rel as usize,
                                    ranges,
                                );
                            let new_off = new_tgt as i32
                                - new_base as i32;
                            let bytes =
                                new_off.to_le_bytes();
                            data[pos..pos + 4]
                                .copy_from_slice(&bytes);
                        }
                        pos += 4;
                    }
                }
            }
            0xFE if pos < end => {
                pos += 1 + op2_size(data[pos]);
            }
            _ => {
                pos = instr_start + 1
                    + opcode_operand_size(op);
            }
        }
    }
}

/// Remove dead ranges from IL bytecode.
fn excise_il_ranges(
    code: &[u8],
    ranges: &[(usize, usize)],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(code.len());
    let mut pos = 0usize;
    for &(start, end) in ranges {
        if start > pos {
            result.extend_from_slice(&code[pos..start]);
        }
        pos = end;
    }
    if pos < code.len() {
        result.extend_from_slice(&code[pos..]);
    }
    result
}

// ---- Dead branch detection in IL --------------------------------

/// Detect dead branches within live IL method bodies.
/// Finds unreachable code after `throw`, `ret`, unconditional
/// `br`, and `rethrow` until the next branch target.
pub fn find_il_dead_blocks(
    data: &[u8],
    method_rvas: &[u32],
    live_methods: &HashSet<usize>,
    dead_methods: &HashSet<usize>,
    pe_rva_to_offset: &dyn Fn(u32) -> Option<usize>,
    method_names: &[String],
) -> Vec<DeadBlock> {
    let mut blocks = Vec::new();
    for (idx, &rva) in method_rvas.iter().enumerate() {
        if rva == 0 {
            continue;
        }
        if !live_methods.contains(&idx) {
            continue;
        }
        if dead_methods.contains(&idx) {
            continue;
        }
        let off = match pe_rva_to_offset(rva) {
            Some(o) => o,
            None => continue,
        };
        let name = if idx < method_names.len() {
            &method_names[idx]
        } else {
            continue;
        };
        scan_method_dead_blocks(
            data, off, rva, name, &mut blocks,
        );
    }
    blocks
}

/// Scan a single IL method body for dead code regions. Collects branch
/// targets in a first pass, then identifies unreachable bytes after
/// terminators (`ret`, `throw`, `br`, `rethrow`) in a second pass.
fn scan_method_dead_blocks(
    data: &[u8],
    offset: usize,
    rva: u32,
    name: &str,
    blocks: &mut Vec<DeadBlock>,
) {
    if offset >= data.len() {
        return;
    }
    let header = data[offset];
    let (code_off, code_size) = if header & 0x03 == 0x02 {
        (offset + 1, (header >> 2) as usize)
    } else if header & 0x03 == 0x03 {
        parse_fat_header(data, offset)
    } else {
        return;
    };
    if code_off == 0 || code_size == 0 {
        return;
    }
    if code_off + code_size > data.len() {
        return;
    }
    // First pass: collect all branch targets
    let targets = collect_il_branch_targets(
        data, code_off, code_size,
    );
    // Second pass: find dead regions
    let end = code_off + code_size;
    let mut pos = code_off;
    while pos < end {
        let op = data[pos];
        let instr_start = pos;
        pos += 1;
        let is_terminator = match op {
            0x2A => true, // ret
            0x7A => true, // throw
            0x2B => {
                // br.s (short branch)
                pos += 1;
                true
            }
            0x38 => {
                // br (long branch)
                pos += 4;
                true
            }
            0xFE if pos < end && data[pos] == 0x1A => {
                // rethrow
                pos += 1;
                true
            }
            _ => {
                if op == OP_LDFTN_PREFIX && pos < end {
                    pos += 1 + op2_size(data[pos - 1]);
                    // We already consumed the prefix, fix up
                    let p2 = instr_start + 1;
                    if p2 < end {
                        pos = p2 + 1 + op2_size(data[p2]);
                    }
                    false
                } else {
                    pos = instr_start + 1
                        + opcode_operand_size(op);
                    false
                }
            }
        };
        if !is_terminator {
            continue;
        }
        // Skip the operand if we haven't yet
        if op == 0x2A || op == 0x7A {
            // no operand — pos already advanced past opcode
        }
        // pos is now at the start of potentially dead code
        let dead_start = pos;
        if dead_start >= end {
            break;
        }
        // Check if next byte is a branch target — if so, not dead
        if targets.contains(&(dead_start - code_off)) {
            continue;
        }
        // Scan forward until we hit a branch target or end
        let mut dead_end = dead_start;
        while dead_end < end {
            let rel = dead_end - code_off;
            if rel > 0 && targets.contains(&rel) {
                break;
            }
            let skip_op = data[dead_end];
            dead_end += 1 + opcode_operand_size(skip_op);
        }
        // Clamp to actual branch target
        let mut final_end = dead_end.min(end);
        for &t in &targets {
            let abs_t = code_off + t;
            if abs_t > dead_start && abs_t < final_end {
                final_end = abs_t;
            }
        }
        let size = final_end - dead_start;
        if size >= 2 {
            // Use RVA-based addressing for .NET methods
            let rva_off = dead_start - offset;
            blocks.push(DeadBlock {
                func_name: name.to_string(),
                addr: rva as u64 + rva_off as u64,
                size: size as u64,
            });
        }
        pos = final_end;
    }
}

/// Collect all branch target offsets (relative to code_off).
fn collect_il_branch_targets(
    data: &[u8],
    code_off: usize,
    code_size: usize,
) -> HashSet<usize> {
    let mut targets = HashSet::new();
    let end = code_off + code_size;
    let mut pos = code_off;
    while pos < end {
        let op = data[pos];
        pos += 1;
        match op {
            // Short conditional branches
            0x2C..=0x37 => {
                if pos < end {
                    let offset =
                        data[pos] as i8 as i32;
                    pos += 1;
                    let tgt =
                        pos as i32 + offset - code_off as i32;
                    if tgt >= 0 && (tgt as usize) < code_size {
                        targets.insert(tgt as usize);
                    }
                }
            }
            // Short unconditional branch
            0x2B => {
                if pos < end {
                    let offset =
                        data[pos] as i8 as i32;
                    pos += 1;
                    let tgt =
                        pos as i32 + offset - code_off as i32;
                    if tgt >= 0 && (tgt as usize) < code_size {
                        targets.insert(tgt as usize);
                    }
                }
            }
            // Long conditional branches
            0x38..=0x43 => {
                if pos + 4 <= end {
                    let offset = read_u32(data, pos) as i32;
                    let tgt = (pos + 4) as i32 + offset
                        - code_off as i32;
                    if tgt >= 0 && (tgt as usize) < code_size {
                        targets.insert(tgt as usize);
                    }
                }
                pos += 4;
            }
            // switch
            0x45 => {
                if pos + 4 <= end {
                    let n = read_u32(data, pos) as usize;
                    pos += 4;
                    let base = pos + n * 4;
                    for _ in 0..n {
                        if pos + 4 <= end {
                            let offset =
                                read_u32(data, pos) as i32;
                            let tgt = base as i32 + offset
                                - code_off as i32;
                            if tgt >= 0
                                && (tgt as usize) < code_size
                            {
                                targets.insert(tgt as usize);
                            }
                        }
                        pos += 4;
                    }
                }
            }
            0xFE if pos < end => {
                let op2 = data[pos];
                pos += 1 + op2_size(op2);
            }
            _ => {
                pos += opcode_operand_size(op);
            }
        }
    }
    targets
}
