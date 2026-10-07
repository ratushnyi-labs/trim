//! x86-64/32 branch and reference patching after dead code compaction.
//!
//! Rewrites relative CALL (E8), JMP (E9/EB), and Jcc (0F 8x / 7x)
//! displacements, RIP-relative memory operand displacements, and
//! switch jump table entries to account for address shifts caused
//! by dead code removal.

use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, FlowType, Section};
use iced_x86::{
    Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register,
};
use std::collections::BTreeMap;

/// Check if a byte is x86 padding (INT3 or NOP).
pub fn is_padding_x86(b: u8) -> bool {
    b == 0xCC || b == 0x90
}

/// Legacy prefixes that leave a relative branch's displacement encoding
/// unchanged: branch hints / NOTRACK (2E, 3E), address-size (67, emitted
/// by linkers relaxing `call *f@GOTPCREL(%rip)` into `addr32 call f`),
/// and BND (F2).
const BRANCH_PREFIXES: &[u8] = &[0x2E, 0x3E, 0x67, 0xF2];

/// Decode call/jmp displacement: (offset_in_instr, size, old_rel).
pub fn decode_rel_ref(
    raw: &[u8],
) -> Option<(usize, usize, i64)> {
    let p = raw
        .iter()
        .take_while(|b| BRANCH_PREFIXES.contains(b))
        .count();
    let (doff, dsz, rel) = decode_rel_opcode(&raw[p..])?;
    Some((p + doff, dsz, rel))
}

/// Decode an unprefixed call/jmp/jcc displacement.
fn decode_rel_opcode(
    raw: &[u8],
) -> Option<(usize, usize, i64)> {
    if raw.is_empty() {
        return None;
    }
    let op = raw[0];
    if (op == 0xE8 || op == 0xE9) && raw.len() >= 5 {
        let rel = i32::from_le_bytes(
            raw[1..5].try_into().ok()?,
        ) as i64;
        return Some((1, 4, rel));
    }
    if op == 0xEB && raw.len() >= 2 {
        return Some((1, 1, raw[1] as i8 as i64));
    }
    if op == 0x0F
        && raw.len() >= 6
        && (0x80..=0x8F).contains(&raw[1])
    {
        let rel = i32::from_le_bytes(
            raw[2..6].try_into().ok()?,
        ) as i64;
        return Some((2, 4, rel));
    }
    if (0x70..=0x7F).contains(&op) && raw.len() >= 2 {
        return Some((1, 1, raw[1] as i8 as i64));
    }
    None
}

/// Patch relative call/jmp offsets for compacted addresses.
pub fn patch_call_jmp(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    for instr in instrs {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        patch_one_rel(data, instr, intervals, sections, ts, te);
    }
}

/// Patch one relative call/jmp displacement for address shifts.
fn patch_one_rel(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let (doff, dsz, old_rel) = match decode_rel_ref(&instr.raw) {
        Some(v) => v,
        None => return,
    };
    let target =
        (instr.addr as i64 + instr.len as i64 + old_rel) as u64;
    let delta = total_shift(instr.addr, intervals, ts, te) as i64
        - total_shift(target, intervals, ts, te) as i64;
    if delta == 0 {
        return;
    }
    let new_rel = old_rel + delta;
    if let Some(foff) = vaddr_to_offset(instr.addr, sections) {
        let pos = foff as usize + doff;
        if dsz == 4 && pos + 4 <= data.len() {
            let bytes = (new_rel as i32).to_le_bytes();
            data[pos..pos + 4].copy_from_slice(&bytes);
        } else if dsz == 1 && pos + 1 <= data.len() {
            data[pos] = new_rel as i8 as u8;
        }
    }
}

/// Patch PC-relative displacements for shifted references.
pub fn patch_pc_rel(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    for instr in instrs {
        if in_dead_range(instr.addr, intervals) {
            continue;
        }
        patch_one_pc_rel(data, instr, intervals, sections, ts, te);
    }
}

/// Patch one RIP-relative displacement for address shifts.
fn patch_one_pc_rel(
    data: &mut [u8],
    instr: &DecodedInstr,
    intervals: &[(u64, u64)],
    sections: &[Section],
    ts: u64,
    te: u64,
) {
    let pc_target = match instr.pc_rel_target {
        Some(t) => t,
        None => return,
    };
    let old_disp = pc_target as i64
        - (instr.addr + instr.len as u64) as i64;
    let shift_src = total_shift(instr.addr, intervals, ts, te);
    let shift_tgt = total_shift(pc_target, intervals, ts, te);
    let delta = shift_src as i64 - shift_tgt as i64;
    if delta == 0 {
        return;
    }
    let new_disp = old_disp + delta;
    let pos = find_disp_pos(&instr.raw, old_disp as i32);
    if let (Some(pos), Some(foff)) =
        (pos, vaddr_to_offset(instr.addr, sections))
    {
        let abs_pos = foff as usize + pos;
        if abs_pos + 4 <= data.len() {
            let bytes = (new_disp as i32).to_le_bytes();
            data[abs_pos..abs_pos + 4].copy_from_slice(&bytes);
        }
    }
}

/// Find the byte offset of a 32-bit displacement value within raw bytes.
fn find_disp_pos(raw: &[u8], disp_val: i32) -> Option<usize> {
    let packed = disp_val.to_le_bytes();
    raw.windows(4).position(|w| w == packed)
}

/// Upper bound on entries for a table whose size could not be derived.
const MAX_TABLE_ENTRIES: usize = 4096;

/// Find switch jump tables: [(base, count)], one entry per table base.
/// `count` is None when no bounding CMP was found near the dispatch.
pub fn find_jump_tables(
    instrs: &[DecodedInstr],
) -> Vec<(u64, Option<usize>)> {
    let mut tables: BTreeMap<u64, Option<usize>> = BTreeMap::new();
    let n = instrs.len();
    for i in 0..n {
        let base_reg = match movslq_base_reg(&instrs[i]) {
            Some(r) => r,
            None => continue,
        };
        if let Some((base, count)) =
            detect_one_table(instrs, i, base_reg, n)
        {
            let e = tables.entry(base).or_insert(count);
            *e = (*e).max(count);
        }
    }
    tables.into_iter().collect()
}

/// Detect a single jump table from a MOVSXD+ADD+JMP pattern. The table
/// base comes from the LEA that loads the MOVSXD's base register, not
/// from whichever RIP-relative operand happens to be nearest.
fn detect_one_table(
    instrs: &[DecodedInstr],
    i: usize,
    base_reg: u8,
    n: usize,
) -> Option<(u64, Option<usize>)> {
    let mut has_add = false;
    let mut has_jmp = false;
    for j in (i + 1)..((i + 4).min(n)) {
        if instrs[j].targets.is_empty() {
            has_add = true;
        }
        if instrs[j].flow == FlowType::IndirectBranch {
            has_jmp = true;
        }
    }
    if !(has_add && has_jmp) {
        return None;
    }
    let base = base_defining_lea(instrs, i, base_reg)?;
    let mut count = None;
    for k in (i.saturating_sub(12))..i {
        if let Some(c) = extract_cmp_imm(&instrs[k]) {
            count = Some(c + 1);
        }
    }
    Some((base, count))
}

/// Instructions to scan back from a dispatch for its table-base LEA.
const MAX_LEA_BACK: usize = 64;

/// Walk back from the dispatch at `i` to the `LEA base_reg, [rip+disp]`
/// that loads the table base, and return that base address. Stops at an
/// unconditional transfer or return, after MAX_LEA_BACK instructions, or
/// if `base_reg` is redefined by anything other than that LEA (in which
/// case the table is skipped rather than patched from a wrong base).
fn base_defining_lea(
    instrs: &[DecodedInstr],
    i: usize,
    base_reg: u8,
) -> Option<u64> {
    let start = i.saturating_sub(MAX_LEA_BACK);
    for j in (start..i).rev() {
        let instr = &instrs[j];
        if lea_rip_dest_reg(instr) == Some(base_reg) {
            return instr.pc_rel_target;
        }
        if matches!(
            instr.flow,
            FlowType::UnconditionalBranch
                | FlowType::IndirectBranch
                | FlowType::Return
                | FlowType::Halt
        ) {
            return None;
        }
        if writes_gpr(&instr.raw, base_reg) {
            return None;
        }
    }
    None
}

/// Patch relative jump table entries. Each table is patched once and
/// never past the start of the next detected table.
pub fn patch_jump_tables(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let tables = find_jump_tables(instrs);
    for (i, &(base, count)) in tables.iter().enumerate() {
        let room = tables
            .get(i + 1)
            .map(|&(next, _)| ((next - base) / 4) as usize)
            .unwrap_or(MAX_TABLE_ENTRIES);
        let limit = count.unwrap_or(MAX_TABLE_ENTRIES).min(room);
        patch_one_table(
            data, base, limit, count.is_none(), intervals, ts, te,
        );
    }
}

/// Patch entries of a single jump table for address shifts. Only
/// entries targeting .text are touched; when the size is unknown the
/// first entry that does not target .text ends the table.
fn patch_one_table(
    data: &mut [u8],
    base: u64,
    count: usize,
    size_unknown: bool,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let base_shift = total_shift(base, intervals, ts, te) as i64;
    for idx in 0..count {
        let off = base as usize + idx * 4;
        if off + 4 > data.len() {
            break;
        }
        let entry = i32::from_le_bytes(
            data[off..off + 4].try_into().unwrap_or([0; 4]),
        );
        let target = (base as i64 + entry as i64) as u64;
        if !(ts <= target && target < te) {
            if size_unknown {
                break;
            }
            continue;
        }
        let tgt_shift =
            total_shift(target, intervals, ts, te) as i64;
        let delta = base_shift - tgt_shift;
        if delta != 0 {
            let new_entry = entry + delta as i32;
            data[off..off + 4]
                .copy_from_slice(&new_entry.to_le_bytes());
        }
    }
}

/// Base register (0-15) of a REX.W `MOVSXD reg, [base + idx*4]` jump
/// table entry load, or None if the instruction is not that pattern.
/// The base is `SIB.base` plus `REX.B`; a disp32-only form (SIB.base==5
/// with mod==00) has no base register and is rejected.
fn movslq_base_reg(instr: &DecodedInstr) -> Option<u8> {
    let raw = &instr.raw;
    if raw.len() < 4 || raw[0] & 0xF8 != 0x48 || raw[1] != 0x63 {
        return None;
    }
    let (modrm, sib) = (raw[2], raw[3]);
    if modrm >> 6 != 0 || modrm & 7 != 4 || sib >> 6 != 2 {
        return None;
    }
    if sib & 7 == 5 {
        return None;
    }
    Some((sib & 7) | ((raw[0] & 1) << 3))
}

/// Destination register (0-15) of a `LEA reg, [rip+disp]`, or None if
/// the instruction is not a RIP-relative LEA. The register is the ModRM
/// reg field plus `REX.R`.
fn lea_rip_dest_reg(instr: &DecodedInstr) -> Option<u8> {
    let raw = &instr.raw;
    let (rex, rest) = match raw.first() {
        Some(&b) if b & 0xF0 == 0x40 => (b, &raw[1..]),
        _ => (0u8, &raw[..]),
    };
    if rest.len() < 2 || rest[0] != 0x8D {
        return None;
    }
    let modrm = rest[1];
    if modrm >> 6 != 0 || modrm & 7 != 5 {
        return None;
    }
    Some(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3))
}

/// Check whether `raw` writes general-purpose register `gpr` (0-15).
/// Partial and conditional writes count. An undecodable instruction is
/// treated as a write, so detection errs toward skipping a table.
fn writes_gpr(raw: &[u8], gpr: u8) -> bool {
    let mut dec = Decoder::new(64, raw, DecoderOptions::NONE);
    if !dec.can_decode() {
        return true;
    }
    let instr = dec.decode();
    if instr.is_invalid() {
        return true;
    }
    let mut factory = InstructionInfoFactory::new();
    for reg in factory.info(&instr).used_registers() {
        let writes = matches!(
            reg.access(),
            OpAccess::Write
                | OpAccess::CondWrite
                | OpAccess::ReadWrite
                | OpAccess::ReadCondWrite
        );
        if writes && gpr64_num(reg.register()) == Some(gpr) {
            return true;
        }
    }
    false
}

/// Map an x86 register to its 64-bit GPR number (0-15), or None for a
/// non-GPR (via the full 64-bit register, so EAX/R14D map to RAX/R14).
fn gpr64_num(reg: Register) -> Option<u8> {
    use Register as R;
    match reg.full_register() {
        R::RAX => Some(0),
        R::RCX => Some(1),
        R::RDX => Some(2),
        R::RBX => Some(3),
        R::RSP => Some(4),
        R::RBP => Some(5),
        R::RSI => Some(6),
        R::RDI => Some(7),
        R::R8 => Some(8),
        R::R9 => Some(9),
        R::R10 => Some(10),
        R::R11 => Some(11),
        R::R12 => Some(12),
        R::R13 => Some(13),
        R::R14 => Some(14),
        R::R15 => Some(15),
        _ => None,
    }
}

/// Extract the immediate from a `CMP reg, imm` (for jump table size),
/// with or without a REX prefix.
fn extract_cmp_imm(instr: &DecodedInstr) -> Option<usize> {
    let mut raw: &[u8] = &instr.raw;
    if raw.first().is_some_and(|b| b & 0xF0 == 0x40) {
        raw = &raw[1..];
    }
    if raw.len() >= 3
        && raw[0] == 0x83
        && (0xF8..=0xFF).contains(&raw[1])
    {
        return Some(raw[2] as usize);
    }
    if raw.len() >= 6
        && raw[0] == 0x81
        && (0xF8..=0xFF).contains(&raw[1])
    {
        let val = u32::from_le_bytes(
            raw[2..6].try_into().ok()?,
        );
        return Some(val as usize);
    }
    if raw.len() >= 5 && raw[0] == 0x3D {
        let val = u32::from_le_bytes(
            raw[1..5].try_into().ok()?,
        );
        return Some(val as usize);
    }
    None
}
