//! Sparse Conditional Constant Propagation (SCCP) for dead branch detection.
//!
//! Performs a worklist-driven forward dataflow analysis over a function's
//! CFG, tracking register values as lattice elements (Bot/Const/Top).
//! When a conditional branch's flags register resolves to a constant,
//! only the taken edge is propagated, leaving the other successor
//! unreachable. Unreachable blocks are reported as dead branches.

use crate::analysis::cfg::{DeadBlock, FuncCfg};
use crate::analysis::dominance::compute_dom_tree;
use crate::analysis::lattice::{eval_binop, Value};
use crate::analysis::regstate::{
    arch_effects, caller_saved, SsaEffect, FLAGS_REG,
    REG_COUNT,
};
use crate::types::{Arch, DecodedInstr, FlowType, FuncMap};
use std::collections::{HashSet, VecDeque};

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
    let n = cfg.blocks.len();
    let succs: Vec<Vec<usize>> =
        cfg.blocks.iter().map(|b| b.successors.clone()).collect();
    let dom = compute_dom_tree(&succs, cfg.entry_block, n);
    let mut state = SccpState::new(n);
    state.mark_edge_exec(cfg.entry_block);
    run_sccp(&mut state, cfg, &block_effects, &succs, &dom);
    let dead = find_sccp_dead(cfg, &state, arch);
    SccpResult { dead, skipped: false, instr_count: count }
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

/// Append effects for one instruction (call sites clobber caller-saved regs).
fn add_instr_effects(
    effects: &mut Vec<SsaEffect>,
    instr: &DecodedInstr,
    arch: Arch,
    big_endian: bool,
) {
    if instr.is_call {
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
fn run_sccp(
    state: &mut SccpState,
    cfg: &FuncCfg,
    block_effects: &[Vec<SsaEffect>],
    succs: &[Vec<usize>],
    _dom: &crate::analysis::dominance::DomTree,
) {
    let n = cfg.blocks.len();
    init_entry_regs(state, cfg.entry_block);
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(cfg.entry_block);
    let mut iterations = 0;
    let max_iter = n * 20;
    while let Some(b) = worklist.pop_front() {
        iterations += 1;
        if iterations > max_iter {
            break;
        }
        if !state.is_exec(b) {
            continue;
        }
        let new_vals = eval_block(state, b, block_effects);
        propagate_succs(
            state, cfg, b, &new_vals, succs, &mut worklist,
        );
    }
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
    cfg: &FuncCfg,
    b: usize,
    vals: &[Value],
    succs: &[Vec<usize>],
    worklist: &mut VecDeque<usize>,
) {
    let term_flow = block_terminator_flow(cfg, b);
    match term_flow {
        Some(FlowType::ConditionalBranch) => {
            propagate_cond(
                state, cfg, b, vals, succs, worklist,
            );
        }
        _ => {
            propagate_all(state, b, vals, succs, worklist);
        }
    }
}

/// Determine the terminator flow type for a block.
fn block_terminator_flow(
    cfg: &FuncCfg,
    b: usize,
) -> Option<FlowType> {
    let block = &cfg.blocks[b];
    if block.successors.is_empty() {
        return Some(FlowType::Return);
    }
    if block.successors.len() == 1 {
        return Some(FlowType::UnconditionalBranch);
    }
    Some(FlowType::ConditionalBranch)
}

/// Propagate along a conditional branch, resolving direction from FLAGS.
fn propagate_cond(
    state: &mut SccpState,
    _cfg: &FuncCfg,
    b: usize,
    vals: &[Value],
    succs: &[Vec<usize>],
    worklist: &mut VecDeque<usize>,
) {
    let flags = &vals[FLAGS_REG as usize];
    let resolved = resolve_branch(flags);
    match resolved {
        BranchResult::AlwaysTaken => {
            propagate_taken(state, b, vals, succs, worklist);
        }
        BranchResult::NeverTaken => {
            propagate_fallthrough(
                state, b, vals, succs, worklist,
            );
        }
        BranchResult::Unknown => {
            propagate_all(state, b, vals, succs, worklist);
        }
    }
}

/// Result of resolving a conditional branch from FLAGS value.
enum BranchResult {
    AlwaysTaken,
    NeverTaken,
    Unknown,
}

/// Resolve branch direction from FLAGS: zero means not-taken, nonzero means taken.
fn resolve_branch(flags: &Value) -> BranchResult {
    match flags {
        Value::Bot => BranchResult::Unknown,
        Value::Top => BranchResult::Unknown,
        Value::Const(v) => {
            if *v == 0 {
                BranchResult::NeverTaken
            } else {
                BranchResult::AlwaysTaken
            }
        }
    }
}

/// Propagate values only to the taken branch target.
fn propagate_taken(
    state: &mut SccpState,
    b: usize,
    vals: &[Value],
    succs: &[Vec<usize>],
    worklist: &mut VecDeque<usize>,
) {
    if succs[b].len() >= 2 {
        let tgt = succs[b][1];
        merge_and_enqueue(state, b, tgt, vals, worklist);
    }
}

/// Propagate values only to the fallthrough successor.
fn propagate_fallthrough(
    state: &mut SccpState,
    b: usize,
    vals: &[Value],
    succs: &[Vec<usize>],
    worklist: &mut VecDeque<usize>,
) {
    if !succs[b].is_empty() {
        let ft = succs[b][0];
        merge_and_enqueue(state, b, ft, vals, worklist);
    }
}

/// Propagate values to all successors (unknown branch direction).
fn propagate_all(
    state: &mut SccpState,
    b: usize,
    vals: &[Value],
    succs: &[Vec<usize>],
    worklist: &mut VecDeque<usize>,
) {
    for &s in &succs[b] {
        merge_and_enqueue(state, b, s, vals, worklist);
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
