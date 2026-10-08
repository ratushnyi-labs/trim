//! x86-64/32 branch and reference patching after dead code compaction.
//!
//! Rewrites relative CALL (E8), JMP (E9/EB), and Jcc (0F 8x / 7x)
//! displacements, RIP-relative memory operand displacements, and
//! switch jump table entries to account for address shifts caused
//! by dead code removal.

use crate::constants::MAX_TABLE_ENTRIES;
use crate::patch::relocs::{in_dead_range, total_shift};
use crate::types::{vaddr_to_offset, DecodedInstr, FlowType, Section};
use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// Most instructions between a dispatch's MOVSXD and its `jmp reg`.
const MAX_DISPATCH_GAP: usize = 8;

/// Most instructions the backward reaching-definition walk may visit.
const MAX_WALK: usize = 8192;

/// GPRs a call may clobber: the union of the System V and Win64
/// caller-saved sets (RAX, RCX, RDX, RSI, RDI, R8-R11).
const CALLER_SAVED: &[u8] = &[0, 1, 2, 6, 7, 8, 9, 10, 11];

/// A switch dispatch `movsxd e,[b+i*4]` .. `add e,b` .. `jmp e` in a
/// code run: indices of the MOVSXD and of the JMP, and the base register.
struct Dispatch {
    load: usize,
    jmp: usize,
    base_reg: u8,
}

/// Direct-branch predecessors of a code run, and the addresses entered
/// from outside it: direct call targets and RIP-relative code references
/// (address-taken functions).
struct RunCfg {
    preds: HashMap<u64, Vec<usize>>,
    entries: HashSet<u64>,
}

/// Switch case address -> indices of the dispatch JMPs whose tables
/// target it (indirect CFG edges).
type CaseEdges = HashMap<u64, Vec<usize>>;

/// Effect of one instruction on a register.
enum RegDef {
    Kept,
    Lea(u64),
    Other,
}

/// Find switch jump tables: [(base, count)], one entry per table base.
/// `count` is None when no bounding CMP was found near the dispatch.
/// Entries are read through `sections` (see `table_span`).
pub fn find_jump_tables(
    data: &[u8],
    instrs: &[DecodedInstr],
    sections: &[Section],
) -> Vec<(u64, Option<usize>)> {
    let mut tables: BTreeMap<u64, Option<usize>> = BTreeMap::new();
    for run in code_runs(instrs) {
        for (base, count) in run_tables(data, sections, run) {
            let e = tables.entry(base).or_insert(count);
            *e = (*e).max(count);
        }
    }
    tables.into_iter().collect()
}

/// Split decoded instructions into runs of address-contiguous code (one
/// per decoded section), each sorted by address.
fn code_runs(instrs: &[DecodedInstr]) -> Vec<&[DecodedInstr]> {
    let mut runs = Vec::new();
    let mut start = 0;
    for k in 1..=instrs.len() {
        let prev = &instrs[k - 1];
        let next = prev.addr + prev.len as u64;
        if k == instrs.len() || instrs[k].addr != next {
            runs.push(&instrs[start..k]);
            start = k;
        }
    }
    runs
}

/// Jump tables of one code run. A lenient first pass proposes a base per
/// dispatch; the case targets of those tables become indirect CFG edges
/// for the exact second pass, which keeps a table only if its base
/// register is loaded by one and the same LEA on every path.
fn run_tables(
    data: &[u8],
    sections: &[Section],
    run: &[DecodedInstr],
) -> Vec<(u64, Option<usize>)> {
    let dispatches: Vec<Dispatch> = (0..run.len())
        .filter_map(|i| match_dispatch(run, i))
        .collect();
    if dispatches.is_empty() {
        return Vec::new();
    }
    let cfg = RunCfg::new(run);
    let mut edges = CaseEdges::new();
    for d in &dispatches {
        if let Some(base) = reaching_lea(run, &cfg, None, d) {
            let count = table_count(run, d.load);
            for t in case_targets(data, sections, run, base, count) {
                edges.entry(t).or_default().push(d.jmp);
            }
        }
    }
    dispatches
        .iter()
        .filter_map(|d| {
            let base = reaching_lea(run, &cfg, Some(&edges), d)?;
            Some((base, table_count(run, d.load)))
        })
        .collect()
}

/// Match the dispatch whose MOVSXD is `run[i]`: within MAX_DISPATCH_GAP
/// straight-line instructions an `add` must sum the loaded entry and the
/// base register, then `jmp` must go to that sum. The entry and the base
/// may not be written before the `add`, nor the sum before the `jmp`.
fn match_dispatch(run: &[DecodedInstr], i: usize) -> Option<Dispatch> {
    let (base_reg, entry_reg) = movslq_regs(&run[i])?;
    if base_reg == entry_reg {
        return None;
    }
    let mut sum = None;
    let end = (i + 1 + MAX_DISPATCH_GAP).min(run.len());
    for (j, ins) in run.iter().enumerate().take(end).skip(i + 1) {
        if ins.flow == FlowType::IndirectBranch {
            let hit = sum.is_some() && jmp_reg(&ins.raw) == sum;
            return hit.then_some(Dispatch { load: i, jmp: j, base_reg });
        }
        if ins.flow != FlowType::Normal {
            return None;
        }
        match (sum, add_regs(&ins.raw)) {
            (None, Some(ab)) if ab == (entry_reg, base_reg) => {
                sum = Some(entry_reg)
            }
            (None, Some(ab)) if ab == (base_reg, entry_reg) => {
                sum = Some(base_reg)
            }
            (None, _) => {
                if writes_gpr(&ins.raw, entry_reg)
                    || writes_gpr(&ins.raw, base_reg)
                {
                    return None;
                }
            }
            (Some(s), _) => {
                if writes_gpr(&ins.raw, s) {
                    return None;
                }
            }
        }
    }
    None
}

impl RunCfg {
    /// Index the direct branches, direct calls and RIP-relative code
    /// references of `run`.
    fn new(run: &[DecodedInstr]) -> Self {
        let lo = run.first().map_or(0, |x| x.addr);
        let hi = run.last().map_or(0, |x| x.addr + x.len as u64);
        let mut cfg = RunCfg {
            preds: HashMap::new(),
            entries: HashSet::new(),
        };
        for (k, ins) in run.iter().enumerate() {
            let target = ins.targets.first().copied();
            match (ins.flow, target) {
                (
                    FlowType::UnconditionalBranch
                    | FlowType::ConditionalBranch,
                    Some(t),
                ) => cfg.preds.entry(t).or_default().push(k),
                (FlowType::Call, Some(t)) => {
                    cfg.entries.insert(t);
                }
                _ => {}
            }
            if let Some(t) = ins.pc_rel_target {
                if lo <= t && t < hi {
                    cfg.entries.insert(t);
                }
            }
        }
        cfg
    }
}

/// Walk back from dispatch `d` over its predecessors to the definitions
/// of its base register that reach the MOVSXD. Returns the table base
/// when every path loads the register with the same `LEA reg,[rip+disp]`;
/// None if any path writes it otherwise or leaves the modelled CFG (see
/// `predecessors`), or after MAX_WALK instructions. `edges` selects the
/// exact pass; without it, unexplained blocks are tolerated.
fn reaching_lea(
    run: &[DecodedInstr],
    cfg: &RunCfg,
    edges: Option<&CaseEdges>,
    d: &Dispatch,
) -> Option<u64> {
    let mut base = None;
    let mut seen = HashSet::new();
    let mut todo = vec![d.load];
    while let Some(j) = todo.pop() {
        if !seen.insert(j) {
            continue;
        }
        if seen.len() > MAX_WALK {
            return None;
        }
        for p in predecessors(run, cfg, edges, j)? {
            match reg_def(&run[p], d.base_reg) {
                RegDef::Kept => todo.push(p),
                RegDef::Lea(t) if base.is_none() || base == Some(t) => {
                    base = Some(t)
                }
                RegDef::Lea(_) | RegDef::Other => return None,
            }
        }
    }
    base
}

/// Predecessors of `run[j]`: fall-through, direct branches and, in the
/// exact pass, the dispatches whose tables target it. None when `run[j]`
/// is entered from outside the modelled CFG: the run start, a call
/// target, an address-taken label, an `endbr64`, or (exact pass) a block
/// with no known predecessor that is not padding.
fn predecessors(
    run: &[DecodedInstr],
    cfg: &RunCfg,
    edges: Option<&CaseEdges>,
    j: usize,
) -> Option<Vec<usize>> {
    let addr = run[j].addr;
    if j == 0 || cfg.entries.contains(&addr) || is_endbr64(&run[j].raw) {
        return None;
    }
    let mut preds = cfg.preds.get(&addr).cloned().unwrap_or_default();
    if run[j - 1].flow.falls_through() {
        preds.push(j - 1);
    }
    let Some(edges) = edges else {
        return Some(preds);
    };
    if let Some(jmps) = edges.get(&addr) {
        preds.extend(jmps);
    }
    if preds.is_empty() && !is_padding_instr(&run[j].raw) {
        return None;
    }
    Some(preds)
}

/// Classify an instruction's effect on GPR `reg`: untouched, loaded by a
/// 64-bit RIP-relative LEA (with its target), or written otherwise.
/// Calls clobber the caller-saved registers.
fn reg_def(instr: &DecodedInstr, reg: u8) -> RegDef {
    if lea_rip_dest_reg(instr) == Some(reg) {
        return instr.pc_rel_target.map_or(RegDef::Other, RegDef::Lea);
    }
    let clobbered = instr.is_call && CALLER_SAVED.contains(&reg);
    if clobbered || writes_gpr(&instr.raw, reg) {
        RegDef::Other
    } else {
        RegDef::Kept
    }
}

/// True for `endbr64`, which marks an indirect branch or call target.
fn is_endbr64(raw: &[u8]) -> bool {
    raw.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA])
}

/// True for alignment padding (NOP or INT3 of any length). Padding with
/// no predecessor is unreachable, so it constrains no register.
fn is_padding_instr(raw: &[u8]) -> bool {
    decode_one(raw).is_some_and(|i| {
        matches!(i.mnemonic(), Mnemonic::Nop | Mnemonic::Int3)
    })
}

/// Entry-count bound from a `CMP reg, imm` in the 12 instructions before
/// the dispatch load at `run[load]`.
fn table_count(run: &[DecodedInstr], load: usize) -> Option<usize> {
    let mut count = None;
    for instr in &run[load.saturating_sub(12)..load] {
        if let Some(c) = extract_cmp_imm(instr) {
            count = Some(c + 1);
        }
    }
    count
}

/// Case targets of the table at `base` that start an instruction of
/// `run`. With an unknown size the first other entry ends the table.
fn case_targets(
    data: &[u8],
    sections: &[Section],
    run: &[DecodedInstr],
    base: u64,
    count: Option<usize>,
) -> Vec<u64> {
    let Some((off, fit)) = table_span(sections, base) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for idx in 0..count.unwrap_or(MAX_TABLE_ENTRIES).min(fit) {
        let Some(entry) = read_entry(data, off, idx) else {
            break;
        };
        let t = (base as i64 + entry as i64) as u64;
        if run.binary_search_by_key(&t, |x| x.addr).is_ok() {
            out.push(t);
        } else if count.is_none() {
            break;
        }
    }
    out
}

/// Where the table at vaddr `base` lies in the file: the file offset of
/// its first entry and how many 4-byte entries fit before the end of the
/// section holding it. None when no section holds `base`. The vaddr is
/// mapped through that section because it equals the file offset only
/// in some layouts (PIE ELF), not in PE (RVA vs raw data offset) nor in
/// Mach-O (vmaddr vs fileoff).
fn table_span(sections: &[Section], base: u64) -> Option<(usize, usize)> {
    let sec = sections
        .iter()
        .find(|s| s.vaddr <= base && base - s.vaddr < s.size)?;
    let rel = base - sec.vaddr;
    let off = usize::try_from(sec.offset.checked_add(rel)?).ok()?;
    let fit = usize::try_from((sec.size - rel) / 4).ok()?;
    Some((off, fit))
}

/// File range of entry `idx` of a table whose first entry is at file
/// offset `off`.
fn entry_range(off: usize, idx: usize) -> Option<std::ops::Range<usize>> {
    let at = off.checked_add(idx.checked_mul(4)?)?;
    Some(at..at.checked_add(4)?)
}

/// Entry `idx` of the table whose first entry is at file offset `off`.
fn read_entry(data: &[u8], off: usize, idx: usize) -> Option<i32> {
    let bytes = data.get(entry_range(off, idx)?)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

/// Overwrite entry `idx` of the table whose first entry is at file
/// offset `off`; out-of-file entries are left alone.
fn write_entry(data: &mut [u8], off: usize, idx: usize, entry: i32) {
    if let Some(bytes) = entry_range(off, idx).and_then(|r| data.get_mut(r))
    {
        bytes.copy_from_slice(&entry.to_le_bytes());
    }
}

/// A detected jump table: its vaddr, the file offset of its first entry,
/// how many entries to visit, and whether that count is a bound found at
/// the dispatch (otherwise the first entry not targeting .text ends it).
struct Table {
    base: u64,
    off: usize,
    len: usize,
    sized: bool,
}

/// Patch relative jump table entries. Each table is patched once and
/// never past the start of the next detected table nor the end of the
/// section holding it; a table no section holds is skipped.
pub fn patch_jump_tables(
    data: &mut [u8],
    instrs: &[DecodedInstr],
    sections: &[Section],
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let tables = find_jump_tables(data, instrs, sections);
    for (i, &(base, count)) in tables.iter().enumerate() {
        let Some((off, fit)) = table_span(sections, base) else {
            continue;
        };
        let room = tables
            .get(i + 1)
            .map(|&(next, _)| ((next - base) / 4) as usize)
            .unwrap_or(MAX_TABLE_ENTRIES);
        let len = count.unwrap_or(MAX_TABLE_ENTRIES).min(room).min(fit);
        let table = Table { base, off, len, sized: count.is_some() };
        patch_one_table(data, &table, intervals, ts, te);
    }
}

/// Patch entries of a single jump table for address shifts. Only
/// entries targeting .text are touched; when the size is unknown the
/// first entry that does not target .text ends the table.
fn patch_one_table(
    data: &mut [u8],
    table: &Table,
    intervals: &[(u64, u64)],
    ts: u64,
    te: u64,
) {
    let base = table.base;
    let base_shift = total_shift(base, intervals, ts, te) as i64;
    for idx in 0..table.len {
        let Some(entry) = read_entry(data, table.off, idx) else {
            break;
        };
        let target = (base as i64 + entry as i64) as u64;
        if !(ts <= target && target < te) {
            if !table.sized {
                break;
            }
            continue;
        }
        let tgt_shift =
            total_shift(target, intervals, ts, te) as i64;
        let delta = base_shift - tgt_shift;
        if delta != 0 {
            write_entry(data, table.off, idx, entry.wrapping_add(delta as i32));
        }
    }
}

/// Base and entry registers (0-15) of a REX.W `MOVSXD reg, [base +
/// idx*4]` jump table entry load, or None if the instruction is not that
/// pattern. The base is `SIB.base` plus `REX.B`. A zero disp8/disp32 is
/// accepted, since `[rbp/r13 + idx*4]` can only be encoded with one. A
/// disp32-only form (mod 00, SIB.base 5) has no base, and a non-zero
/// displacement puts the table away from the base its entries are
/// relative to, so both are rejected.
fn movslq_regs(instr: &DecodedInstr) -> Option<(u8, u8)> {
    let raw = &instr.raw;
    if raw.len() < 4 || raw[0] & 0xF8 != 0x48 || raw[1] != 0x63 {
        return None;
    }
    let (rex, modrm, sib) = (raw[0], raw[2], raw[3]);
    if modrm & 7 != 4 || sib >> 6 != 2 {
        return None;
    }
    if (sib >> 3) & 7 == 4 && rex & 2 == 0 {
        return None;
    }
    let zero_disp = match modrm >> 6 {
        0 => sib & 7 != 5,
        1 => raw.get(4) == Some(&0),
        2 => raw.get(4..8) == Some(&[0u8; 4][..]),
        _ => false,
    };
    if !zero_disp {
        return None;
    }
    let base = (sib & 7) | ((rex & 1) << 3);
    let entry = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3);
    Some((base, entry))
}

/// Destination register (0-15) of a 64-bit `LEA reg, [rip+disp]`, or
/// None if the instruction is not one. The register is the ModRM reg
/// field plus `REX.R`; without `REX.W` the LEA truncates the address, so
/// it does not count as a table base load.
fn lea_rip_dest_reg(instr: &DecodedInstr) -> Option<u8> {
    let raw = &instr.raw;
    let (rex, rest) = match raw.first() {
        Some(&b) if b & 0xF0 == 0x40 => (b, &raw[1..]),
        _ => return None,
    };
    if rex & 8 == 0 || rest.len() < 2 || rest[0] != 0x8D {
        return None;
    }
    let modrm = rest[1];
    if modrm >> 6 != 0 || modrm & 7 != 5 {
        return None;
    }
    Some(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3))
}

/// Destination and source GPRs (0-15) of a 64-bit register-register
/// `ADD`, or None for any other instruction.
fn add_regs(raw: &[u8]) -> Option<(u8, u8)> {
    let i = decode_one(raw)?;
    if i.mnemonic() != Mnemonic::Add
        || i.op_count() != 2
        || i.op0_kind() != OpKind::Register
        || i.op1_kind() != OpKind::Register
        || !i.op0_register().is_gpr64()
        || !i.op1_register().is_gpr64()
    {
        return None;
    }
    Some((gpr64_num(i.op0_register())?, gpr64_num(i.op1_register())?))
}

/// Target GPR (0-15) of a `jmp reg64`, or None for any other instruction.
fn jmp_reg(raw: &[u8]) -> Option<u8> {
    let i = decode_one(raw)?;
    if i.mnemonic() != Mnemonic::Jmp
        || i.op0_kind() != OpKind::Register
        || !i.op0_register().is_gpr64()
    {
        return None;
    }
    gpr64_num(i.op0_register())
}

/// Decode one 64-bit instruction from `raw`, or None if it is invalid.
fn decode_one(raw: &[u8]) -> Option<Instruction> {
    let mut dec = Decoder::new(64, raw, DecoderOptions::NONE);
    if !dec.can_decode() {
        return None;
    }
    let instr = dec.decode();
    (!instr.is_invalid()).then_some(instr)
}

/// Check whether `raw` writes general-purpose register `gpr` (0-15).
/// Partial and conditional writes count. An undecodable instruction is
/// treated as a write, so detection errs toward skipping a table.
fn writes_gpr(raw: &[u8], gpr: u8) -> bool {
    let Some(instr) = decode_one(raw) else {
        return true;
    };
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
/// with or without a REX prefix. Immediates are sign-extended, so a
/// negative one (e.g. `cmp $-7, %rdx`) is no table bound and gives None.
fn extract_cmp_imm(instr: &DecodedInstr) -> Option<usize> {
    let mut raw: &[u8] = &instr.raw;
    if raw.first().is_some_and(|b| b & 0xF0 == 0x40) {
        raw = &raw[1..];
    }
    let imm = if raw.len() >= 3
        && raw[0] == 0x83
        && (0xF8..=0xFF).contains(&raw[1])
    {
        raw[2] as i8 as i64
    } else if raw.len() >= 6
        && raw[0] == 0x81
        && (0xF8..=0xFF).contains(&raw[1])
    {
        i32::from_le_bytes(raw[2..6].try_into().ok()?) as i64
    } else if raw.len() >= 5 && raw[0] == 0x3D {
        i32::from_le_bytes(raw[1..5].try_into().ok()?) as i64
    } else {
        return None;
    };
    usize::try_from(imm).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Arch;

    /// Start of case `i` of `dispatcher`, from the dispatcher's start.
    const CASES: [u64; 4] = [0x17, 0x1d, 0x23, 0x29];

    /// Bytes `dispatcher` occupies.
    const DISPATCH_LEN: u64 = 0x32;

    /// Code of a 4-case switch at vaddr `at` whose table is at vaddr
    /// `table`: `cmp edi,3; ja def; mov ecx,edi; lea rdx,[rip+T];
    /// movsxd rcx,[rdx+rcx*4]; add rcx,rdx; jmp rcx`, four `mov eax,k;
    /// ret` cases at `CASES`, and a `xor eax,eax; ret` default.
    fn dispatcher(at: u64, table: u64) -> Vec<u8> {
        let disp = (table as i64 - (at as i64 + 0x0e)) as i32;
        let mut code = vec![0x83, 0xff, 0x03, 0x77, 0x2a, 0x89, 0xf9];
        code.extend_from_slice(&[0x48, 0x8d, 0x15]);
        code.extend_from_slice(&disp.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x63, 0x0c, 0x8a]);
        code.extend_from_slice(&[0x48, 0x01, 0xd1, 0xff, 0xe1]);
        for k in 1..=4u8 {
            code.extend_from_slice(&[0xb8, k, 0, 0, 0, 0xc3]);
        }
        code.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        code
    }

    /// Table entries for `dispatcher` at `at`, relative to `table`.
    fn table_bytes(at: u64, table: u64) -> Vec<u8> {
        CASES
            .iter()
            .map(|c| ((at + c) as i64 - table as i64) as i32)
            .flat_map(i32::to_le_bytes)
            .collect()
    }

    /// The four entries of the table at file offset `off`.
    fn entries(data: &[u8], off: usize) -> Vec<Option<i32>> {
        (0..4).map(|i| read_entry(data, off, i)).collect()
    }

    /// The entries `table_bytes` gives, each moved by `delta`.
    fn expected(at: u64, table: u64, delta: i64) -> Vec<Option<i32>> {
        CASES
            .iter()
            .map(|c| Some(((at + c) as i64 - table as i64 + delta) as i32))
            .collect()
    }

    /// A section named `name` at `vaddr`, file offset `offset`.
    fn section(name: &str, vaddr: u64, offset: u64, size: u64) -> Section {
        let name = name.to_string();
        Section { name, size, vaddr, offset, align: 1 }
    }

    /// Run `patch_jump_tables` on `data` with `.text` = `text` and the
    /// one dead interval `dead`.
    fn patch(
        data: &mut [u8],
        text: &Section,
        secs: &[Section],
        dead: (u64, u64),
    ) {
        let instrs = crate::arch::decode_text(
            data, text.offset, text.vaddr, text.size, Arch::X86_64,
        );
        let (ts, te) = (text.vaddr, text.vaddr + text.size);
        patch_jump_tables(data, &instrs, secs, &[dead], ts, te);
    }

    /// PE-like layout: .text at `(0x1000, text_off)`, 0x20 dead bytes
    /// before the dispatcher, the table in .rdata at `(0x3000, rdata_off)`.
    /// Returns the image and its sections; bytes at file offset 0x3000
    /// (the table's vaddr) hold the sentinel 0xAB.
    fn pe_like(text_off: u64, rdata_off: u64) -> (Vec<u8>, Vec<Section>) {
        let (at, table) = (0x1020, 0x3000);
        let text = section(".text", 0x1000, text_off, 0x20 + DISPATCH_LEN);
        let rdata = section(".rdata", table, rdata_off, 16);
        let mut data = vec![0xAB; 0x3010];
        let t = text_off as usize;
        data[t..t + 0x20].fill(0xcc);
        let code = dispatcher(at, table);
        data[t + 0x20..t + 0x20 + code.len()].copy_from_slice(&code);
        let r = rdata_off as usize;
        data[r..r + 16].copy_from_slice(&table_bytes(at, table));
        (data, vec![text, rdata])
    }

    /// PE: the table is read and patched at its raw data offset; the
    /// bytes at the file offset equal to its RVA stay untouched.
    #[test]
    fn pe_table_patched_at_raw_offset() {
        let (mut data, secs) = pe_like(0x400, 0x600);
        patch(&mut data, &secs[0], &secs, (0x1000, 0x1020));
        assert_eq!(entries(&data, 0x600), expected(0x1020, 0x3000, -0x20));
        assert!(data[0x3000..0x3010].iter().all(|&b| b == 0xAB));
    }

    /// PIE ELF: vaddr equals file offset, and the table is patched there
    /// as before.
    #[test]
    fn identity_layout_patched_in_place() {
        let (mut data, secs) = pe_like(0x1000, 0x3000);
        patch(&mut data, &secs[0], &secs, (0x1000, 0x1020));
        assert_eq!(entries(&data, 0x3000), expected(0x1020, 0x3000, -0x20));
    }

    /// A table no section holds is skipped: nothing is written.
    #[test]
    fn unmapped_table_skipped() {
        let (mut data, secs) = pe_like(0x400, 0x600);
        let before = data.clone();
        patch(&mut data, &secs[0], &secs[..1], (0x1000, 0x1020));
        assert_eq!(data, before);
    }

    /// Mach-O: the table follows the dispatcher in __text, at a vmaddr
    /// above 4 GiB; dead code between the cases and the table moves the
    /// table but not the cases, so every entry grows by the dead size.
    #[test]
    fn macho_inline_table_patched_at_fileoff() {
        let (va, off, dead) = (0x1_0000_0330u64, 0x330usize, 0x22u64);
        let table = va + DISPATCH_LEN + dead;
        let size = DISPATCH_LEN + dead + 16;
        let text = section(".text", va, off as u64, size);
        let mut data = vec![0xcc; off + size as usize];
        let code = dispatcher(va, table);
        data[off..off + code.len()].copy_from_slice(&code);
        let t = off + (table - va) as usize;
        data[t..t + 16].copy_from_slice(&table_bytes(va, table));
        let secs = [text.clone()];
        let dead_ivl = (va + DISPATCH_LEN, table);
        patch(&mut data, &text, &secs, dead_ivl);
        assert_eq!(entries(&data, t), expected(va, table, dead as i64));
    }
}
