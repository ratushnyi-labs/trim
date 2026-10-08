//! Sparse Conditional Constant Propagation (SCCP) for dead branch detection.
//!
//! Performs a worklist-driven forward dataflow analysis over a function's
//! CFG, tracking register values as lattice elements (Bot/Const/Top).
//! When an equality branch (EQ/NE) reads a constant flags value, only
//! the edge its condition selects is propagated, leaving the other
//! successor unreachable. Unreachable blocks are reported as dead
//! branches.

use crate::analysis::cfg::{BasicBlock, DeadBlock, FuncCfg};
use crate::analysis::dominance::compute_dom_tree;
use crate::analysis::lattice::{eval_binop, CondCode, Value};
use crate::analysis::regstate::{
    arch_effects, branch_cond, caller_saved, SsaEffect,
    FLAGS_REG, REG_COUNT,
};
use crate::types::{Arch, DecodedInstr, FlowType, FuncMap};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default instruction limit for SCCP analysis.
pub const DEFAULT_MAX_INSTRS: usize = 10_000;

/// Result of SCCP on a single function.
pub struct SccpResult {
    pub dead: Vec<DeadBlock>,
    pub skipped: bool,
    pub instr_count: usize,
}

/// Run SCCP on a function CFG and return dead blocks.
pub fn sccp_dead_blocks(
    cfg: &FuncCfg,
    instrs: &[DecodedInstr],
    arch: Arch,
    _funcs: &FuncMap,
    max_instrs: usize,
    big_endian: bool,
) -> SccpResult {
    if cfg.blocks.is_empty() {
        return SccpResult { dead: Vec::new(), skipped: false, instr_count: 0 };
    }
    let func_instrs = collect_func_instrs(cfg, instrs);
    let count = func_instrs.len();
    if count > max_instrs {
        return SccpResult { dead: Vec::new(), skipped: true, instr_count: count };
    }
    let block_effects =
        build_block_effects(cfg, &func_instrs, arch, big_endian);
    let terms =
        build_cond_terms(cfg, &func_instrs, arch, big_endian);
    let n = cfg.blocks.len();
    let succs: Vec<Vec<usize>> =
        cfg.blocks.iter().map(|b| b.successors.clone()).collect();
    let dom = compute_dom_tree(&succs, cfg.entry_block, n);
    let mut state = SccpState::new(n);
    state.mark_edge_exec(cfg.entry_block);
    let flow = SccpFlow { succs: &succs, terms: &terms };
    if !run_sccp(&mut state, cfg, &block_effects, &flow, &dom) {
        // Not converged: unvisited blocks are not proven dead.
        return SccpResult { dead: Vec::new(), skipped: true, instr_count: count };
    }
    let dead = find_sccp_dead(cfg, &state, arch);
    SccpResult { dead, skipped: false, instr_count: count }
}

/// A block ending in a two-way conditional branch with a decoded
/// condition: the successor block when taken and when not taken.
#[derive(Debug, Clone, Copy)]
struct CondTerm {
    cc: CondCode,
    taken: usize,
    fallthrough: usize,
}

/// Successor lists plus the foldable conditional terminators.
struct SccpFlow<'a> {
    succs: &'a [Vec<usize>],
    terms: &'a [Option<CondTerm>],
}

/// Find the foldable conditional terminator of every block. Blocks
/// ending in anything else (including indirect jumps) are never
/// folded and keep all their successors.
fn build_cond_terms(
    cfg: &FuncCfg,
    instrs: &[&DecodedInstr],
    arch: Arch,
    big_endian: bool,
) -> Vec<Option<CondTerm>> {
    let by_addr: HashMap<u64, usize> = cfg
        .blocks
        .iter()
        .map(|b| (b.start_addr, b.id))
        .collect();
    cfg.blocks
        .iter()
        .map(|b| cond_term(b, instrs, &by_addr, arch, big_endian))
        .collect()
}

/// Decode a block's conditional terminator into its condition and
/// its taken/fall-through successors, if all three are known.
fn cond_term(
    block: &BasicBlock,
    instrs: &[&DecodedInstr],
    by_addr: &HashMap<u64, usize>,
    arch: Arch,
    big_endian: bool,
) -> Option<CondTerm> {
    let last = instrs.iter().rev().find(|i| {
        i.addr >= block.start_addr && i.addr < block.end_addr
    })?;
    if last.flow != FlowType::ConditionalBranch
        || block.successors.len() != 2
    {
        return None;
    }
    let ft_addr = last.addr + last.len as u64;
    let fallthrough = *by_addr.get(&ft_addr)?;
    let mut taken_ids =
        last.targets.iter().filter_map(|t| by_addr.get(t));
    let taken = *taken_ids.next()?;
    let cc = branch_cond(&last.raw, arch, big_endian)?;
    let unique = taken_ids.next().is_none() && taken != fallthrough;
    let matches = block.successors.contains(&taken)
        && block.successors.contains(&fallthrough);
    (unique && matches).then_some(CondTerm { cc, taken, fallthrough })
}

/// Collect all instructions that fall within the function's address range.
fn collect_func_instrs<'a>(
    cfg: &FuncCfg,
    instrs: &'a [DecodedInstr],
) -> Vec<&'a DecodedInstr> {
    let end = cfg.func_addr + cfg.func_size;
    instrs
        .iter()
        .filter(|i| i.addr >= cfg.func_addr && i.addr < end)
        .collect()
}

/// Build per-block SSA effects from decoded instructions and architecture.
fn build_block_effects(
    cfg: &FuncCfg,
    instrs: &[&DecodedInstr],
    arch: Arch,
    big_endian: bool,
) -> Vec<Vec<SsaEffect>> {
    cfg.blocks
        .iter()
        .map(|b| {
            let mut effects = Vec::new();
            for instr in instrs.iter() {
                if instr.addr >= b.start_addr
                    && instr.addr < b.end_addr
                {
                    add_instr_effects(
                        &mut effects,
                        instr,
                        arch,
                        big_endian,
                    );
                }
            }
            effects
        })
        .collect()
}

/// Append effects for one instruction (call sites, direct or indirect,
/// clobber caller-saved regs).
fn add_instr_effects(
    effects: &mut Vec<SsaEffect>,
    instr: &DecodedInstr,
    arch: Arch,
    big_endian: bool,
) {
    if instr.is_call || instr.flow == FlowType::IndirectCall {
        for &r in caller_saved(arch) {
            effects.push(SsaEffect::Clobber(r));
        }
        return;
    }
    let effs = arch_effects(
        &instr.raw, instr.addr, arch, big_endian,
    );
    effects.extend(effs);
}

/// Internal state for the SCCP worklist solver.
struct SccpState {
    reg_vals: Vec<Vec<Value>>,
    exec_edges: HashSet<(usize, usize)>,
    block_exec: Vec<bool>,
}

impl SccpState {
    /// Create initial state with all registers at Bot (unreachable).
    fn new(n: usize) -> Self {
        Self {
            reg_vals: vec![
                vec![Value::Bot; REG_COUNT]; n
            ],
            exec_edges: HashSet::new(),
            block_exec: vec![false; n],
        }
    }

    /// Mark a block as executable (reachable).
    fn mark_edge_exec(&mut self, block: usize) {
        self.block_exec[block] = true;
    }

    /// Check if a block has been marked executable.
    fn is_exec(&self, block: usize) -> bool {
        self.block_exec[block]
    }
}

/// Main SCCP worklist loop: propagate register values through the CFG.
/// Returns false if the iteration limit stopped it before a fixpoint.
fn run_sccp(
    state: &mut SccpState,
    cfg: &FuncCfg,
    block_effects: &[Vec<SsaEffect>],
    flow: &SccpFlow,
    _dom: &crate::analysis::dominance::DomTree,
) -> bool {
    let n = cfg.blocks.len();
    init_entry_regs(state, cfg.entry_block);
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(cfg.entry_block);
    let mut iterations = 0;
    let max_iter = n * 20;
    while let Some(b) = worklist.pop_front() {
        iterations += 1;
        if iterations > max_iter {
            return false;
        }
        if !state.is_exec(b) {
            continue;
        }
        let new_vals = eval_block(state, b, block_effects);
        propagate_succs(state, b, &new_vals, flow, &mut worklist);
    }
    true
}

/// Initialize entry block registers to Top (unknown incoming values).
fn init_entry_regs(state: &mut SccpState, entry: usize) {
    for r in 0..REG_COUNT {
        state.reg_vals[entry][r] = Value::Top;
    }
}

/// Evaluate all effects in a block, producing output register values.
fn eval_block(
    state: &SccpState,
    b: usize,
    block_effects: &[Vec<SsaEffect>],
) -> Vec<Value> {
    let mut vals = state.reg_vals[b].clone();
    for eff in &block_effects[b] {
        apply_effect(&mut vals, eff);
    }
    vals
}

/// Apply a single SSA effect to the register value vector.
fn apply_effect(vals: &mut [Value], eff: &SsaEffect) {
    match eff {
        SsaEffect::MovConst(d, c) => {
            vals[*d as usize] = Value::Const(*c);
        }
        SsaEffect::MovReg(d, s) => {
            vals[*d as usize] = vals[*s as usize].clone();
        }
        SsaEffect::BinOp(d, op, a, b) => {
            let r = eval_binop(
                *op,
                &vals[*a as usize],
                &vals[*b as usize],
            );
            vals[*d as usize] = r;
        }
        SsaEffect::BinOpImm(d, op, a, imm) => {
            let r = eval_binop(
                *op,
                &vals[*a as usize],
                &Value::Const(*imm),
            );
            vals[*d as usize] = r;
        }
        SsaEffect::CmpReg(a, b) => {
            apply_cmp_reg(vals, *a, *b);
        }
        SsaEffect::CmpImm(a, imm) => {
            apply_cmp_imm(vals, *a, *imm);
        }
        SsaEffect::TestReg(a, b) => {
            apply_test_reg(vals, *a, *b);
        }
        SsaEffect::TestImm(a, imm) => {
            apply_test_imm(vals, *a, *imm);
        }
        SsaEffect::Clobber(d) => {
            vals[*d as usize] = Value::Top;
        }
        SsaEffect::Nop => {}
    }
}

/// Set FLAGS to the difference of two register values (CMP semantics).
fn apply_cmp_reg(
    vals: &mut [Value],
    a: u8,
    b: u8,
) {
    let va = &vals[a as usize];
    let vb = &vals[b as usize];
    let result = match (va, vb) {
        (Value::Bot, _) | (_, Value::Bot) => Value::Bot,
        (Value::Top, _) | (_, Value::Top) => Value::Top,
        (Value::Const(x), Value::Const(y)) => {
            Value::Const((*x).wrapping_sub(*y))
        }
    };
    vals[FLAGS_REG as usize] = result;
}

/// Set FLAGS to reg minus immediate (CMP reg, imm).
fn apply_cmp_imm(vals: &mut [Value], a: u8, imm: i64) {
    let va = &vals[a as usize];
    let result = match va {
        Value::Bot => Value::Bot,
        Value::Top => Value::Top,
        Value::Const(x) => Value::Const(x.wrapping_sub(imm)),
    };
    vals[FLAGS_REG as usize] = result;
}

/// Set FLAGS to the bitwise AND of two registers (TEST semantics).
fn apply_test_reg(vals: &mut [Value], a: u8, b: u8) {
    let va = &vals[a as usize];
    let vb = &vals[b as usize];
    let result = match (va, vb) {
        (Value::Bot, _) | (_, Value::Bot) => Value::Bot,
        (Value::Top, _) | (_, Value::Top) => Value::Top,
        (Value::Const(x), Value::Const(y)) => {
            Value::Const(x & y)
        }
    };
    vals[FLAGS_REG as usize] = result;
}

/// Set FLAGS to reg AND immediate (TEST reg, imm).
fn apply_test_imm(vals: &mut [Value], a: u8, imm: i64) {
    let va = &vals[a as usize];
    let result = match va {
        Value::Bot => Value::Bot,
        Value::Top => Value::Top,
        Value::Const(x) => Value::Const(x & imm),
    };
    vals[FLAGS_REG as usize] = result;
}

/// Propagate register values to successor blocks, respecting branch resolution.
fn propagate_succs(
    state: &mut SccpState,
    b: usize,
    vals: &[Value],
    flow: &SccpFlow,
    worklist: &mut VecDeque<usize>,
) {
    let flags = &vals[FLAGS_REG as usize];
    let only = flow.terms[b].and_then(|t| {
        match resolve_branch(t.cc, flags) {
            BranchResult::AlwaysTaken => Some(t.taken),
            BranchResult::NeverTaken => Some(t.fallthrough),
            BranchResult::Unknown => None,
        }
    });
    match only {
        Some(s) => merge_and_enqueue(state, b, s, vals, worklist),
        None => {
            for &s in &flow.succs[b] {
                merge_and_enqueue(state, b, s, vals, worklist);
            }
        }
    }
}

/// Result of resolving a conditional branch from FLAGS value.
enum BranchResult {
    AlwaysTaken,
    NeverTaken,
    Unknown,
}

/// Resolve a branch from its condition and FLAGS. Only EQ/NE are
/// folded: FLAGS holds the compare difference (or test AND) without
/// the operand width or carry/overflow that ordered conditions need.
fn resolve_branch(cc: CondCode, flags: &Value) -> BranchResult {
    let zero = match flags_zero(flags) {
        Some(z) => z,
        None => return BranchResult::Unknown,
    };
    let taken = match cc {
        CondCode::Eq => zero,
        CondCode::Ne => !zero,
        _ => return BranchResult::Unknown,
    };
    if taken {
        BranchResult::AlwaysTaken
    } else {
        BranchResult::NeverTaken
    }
}

/// Zero flag of a compare/test result whose width is unknown. Zero is
/// zero at every width; a nonzero low byte is nonzero at every width
/// (8 bits is the narrowest compare). Anything else stays unknown.
fn flags_zero(flags: &Value) -> Option<bool> {
    match flags {
        Value::Const(0) => Some(true),
        Value::Const(v) if v & 0xFF != 0 => Some(false),
        _ => None,
    }
}

/// Merge register values into a successor block and enqueue if changed.
fn merge_and_enqueue(
    state: &mut SccpState,
    from: usize,
    to: usize,
    vals: &[Value],
    worklist: &mut VecDeque<usize>,
) {
    if to >= state.reg_vals.len() {
        return;
    }
    let edge = (from, to);
    let new_exec = state.exec_edges.insert(edge);
    let mut changed = new_exec;
    for r in 0..REG_COUNT {
        let old = &state.reg_vals[to][r];
        let new_val = old.meet(&vals[r]);
        if new_val != *old {
            state.reg_vals[to][r] = new_val;
            changed = true;
        }
    }
    if changed {
        state.block_exec[to] = true;
        worklist.push_back(to);
    }
}

/// Collect blocks that were never marked executable as dead blocks.
fn find_sccp_dead(
    cfg: &FuncCfg,
    state: &SccpState,
    arch: Arch,
) -> Vec<DeadBlock> {
    // MIPS has mandatory branch delay slots: the instruction after
    // a branch/return is always executed. The CFG creates a separate
    // block for it that appears unreachable. Filter these out by
    // requiring dead blocks to be at least 2 instructions (8 bytes).
    let min_size: u64 = match arch {
        Arch::Mips32 | Arch::Mips64 => 8,
        _ => 2,
    };
    cfg.blocks
        .iter()
        .filter(|b| !state.is_exec(b.id))
        .filter(|b| b.end_addr - b.start_addr >= min_size)
        .map(|b| DeadBlock {
            func_name: cfg.func_name.clone(),
            addr: b.start_addr,
            size: b.end_addr - b.start_addr,
        })
        .collect()
}
