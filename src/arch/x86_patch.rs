//! x86-64/32 branch and reference patching after dead code compaction.
//!
//! Rewrites relative CALL (E8), JMP (E9/EB), and Jcc (0F 8x / 7x)
//! displacements, RIP-relative memory operand displacements, and
//! switch jump table entries to account for address shifts caused
//! by dead code removal.

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

/// Upper bound on entries for a table whose size could not be derived.
const MAX_TABLE_ENTRIES: usize = 4096;

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
pub fn find_jump_tables(
    data: &[u8],
    instrs: &[DecodedInstr],
) -> Vec<(u64, Option<usize>)> {
    let mut tables: BTreeMap<u64, Option<usize>> = BTreeMap::new();
    for run in code_runs(instrs) {
        for (base, count) in run_tables(data, run) {
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
            for t in case_targets(data, run, base, count) {
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
    if falls_through(&run[j - 1]) {
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

/// True if execution can continue from `instr` to the next instruction.
fn falls_through(instr: &DecodedInstr) -> bool {
    !matches!(
        instr.flow,
        FlowType::UnconditionalBranch
            | FlowType::IndirectBranch
            | FlowType::Return
            | FlowType::Halt
    )
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
    run: &[DecodedInstr],
    base: u64,
    count: Option<usize>,
) -> Vec<u64> {
    let mut out = Vec::new();
    for idx in 0..count.unwrap_or(MAX_TABLE_ENTRIES) {
        let Some(entry) = read_entry(data, base, idx) else {
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

/// Entry `idx` of the table at `base`, whose vaddr is used as its file
/// offset (as in the PIE layouts whose tables are patched).
fn read_entry(data: &[u8], base: u64, idx: usize) -> Option<i32> {
    let off = usize::try_from(base).ok()?.checked_add(idx * 4)?;
    let bytes = data.get(off..off.checked_add(4)?)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
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
    let tables = find_jump_tables(data, instrs);
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
        let Some(entry) = read_entry(data, base, idx) else {
            break;
        };
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
            let off = base as usize + idx * 4;
            let new_entry = entry + delta as i32;
            data[off..off + 4]
                .copy_from_slice(&new_entry.to_le_bytes());
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
