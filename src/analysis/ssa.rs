//! SSA (Static Single Assignment) form construction.
//!
//! Builds SSA from per-block register effects and dominance information.
//! Inserts phi-nodes at dominance frontiers and renames values using a
//! dominator-tree walk. The resulting SSA form is consumed by the SCCP
//! solver for precise constant propagation across branches.

use crate::analysis::dominance::DomTree;
use crate::analysis::regstate::{RegId, SsaEffect, REG_COUNT};
use std::collections::{HashSet, VecDeque};

/// SSA value ID.
pub type ValId = usize;

/// A phi-node at a block entry.
#[derive(Debug, Clone)]
pub struct PhiNode {
    pub block: usize,
    pub reg: RegId,
    pub val: ValId,
    pub operands: Vec<(usize, ValId)>,
}

/// An SSA definition.
#[derive(Debug, Clone)]
pub enum SsaDef {
    Effect(SsaEffect, usize),
    Phi(usize, RegId),
    Entry(RegId),
}

/// Complete SSA form for a function.
pub struct SsaForm {
    pub defs: Vec<SsaDef>,
    pub phis: Vec<PhiNode>,
    pub block_defs: Vec<Vec<(ValId, SsaEffect)>>,
    pub block_phis: Vec<Vec<usize>>,
}

/// Build SSA from per-block effects and dominance info.
pub fn build_ssa(
    block_effects: &[Vec<SsaEffect>],
    dom: &DomTree,
    n_blocks: usize,
) -> SsaForm {
    let mut form = SsaForm {
        defs: Vec::new(),
        phis: Vec::new(),
        block_defs: vec![Vec::new(); n_blocks],
        block_phis: vec![Vec::new(); n_blocks],
    };
    create_entry_defs(&mut form);
    insert_phi_nodes(&mut form, block_effects, dom, n_blocks);
    rename_values(&mut form, block_effects, dom, n_blocks);
    form
}

/// Create initial SSA definitions for entry block registers.
fn create_entry_defs(form: &mut SsaForm) {
    for reg in 0..REG_COUNT as RegId {
        let vid = form.defs.len();
        form.defs.push(SsaDef::Entry(reg));
        let _ = vid;
    }
}

/// Insert phi-nodes at dominance frontiers for each register.
fn insert_phi_nodes(
    form: &mut SsaForm,
    block_effects: &[Vec<SsaEffect>],
    dom: &DomTree,
    n_blocks: usize,
) {
    for reg in 0..REG_COUNT as RegId {
        let def_blocks = find_def_blocks(
            block_effects, reg, n_blocks,
        );
        let phi_blocks =
            place_phis(&def_blocks, &dom.frontiers, n_blocks);
        for &b in &phi_blocks {
            let vid = form.defs.len();
            form.defs.push(SsaDef::Phi(b, reg));
            form.phis.push(PhiNode {
                block: b,
                reg,
                val: vid,
                operands: Vec::new(),
            });
            form.block_phis[b].push(form.phis.len() - 1);
        }
    }
}

/// Find blocks that define (write to) a given register.
fn find_def_blocks(
    block_effects: &[Vec<SsaEffect>],
    reg: RegId,
    n_blocks: usize,
) -> HashSet<usize> {
    let mut defs = HashSet::new();
    for b in 0..n_blocks {
        for eff in &block_effects[b] {
            if defines_reg(eff, reg) {
                defs.insert(b);
                break;
            }
        }
    }
    defs
}

/// Check if an SSA effect defines (writes to) the given register.
fn defines_reg(eff: &SsaEffect, reg: RegId) -> bool {
    match eff {
        SsaEffect::MovConst(d, _)
        | SsaEffect::MovReg(d, _)
        | SsaEffect::Clobber(d) => *d == reg,
        SsaEffect::BinOp(d, _, _, _)
        | SsaEffect::BinOpImm(d, _, _, _) => *d == reg,
        SsaEffect::CmpReg(_, _)
        | SsaEffect::CmpImm(_, _)
        | SsaEffect::TestReg(_, _)
        | SsaEffect::TestImm(_, _) => {
            reg == crate::analysis::regstate::FLAGS_REG
        }
        SsaEffect::Nop => false,
    }
}

/// Place phi-nodes using iterated dominance frontier.
fn place_phis(
    def_blocks: &HashSet<usize>,
    frontiers: &[HashSet<usize>],
    n_blocks: usize,
) -> Vec<usize> {
    let mut has_phi = vec![false; n_blocks];
    let mut work: VecDeque<usize> =
        def_blocks.iter().copied().collect();
    while let Some(b) = work.pop_front() {
        if b >= frontiers.len() {
            continue;
        }
        for &f in &frontiers[b] {
            if !has_phi[f] {
                has_phi[f] = true;
                if !def_blocks.contains(&f) {
                    work.push_back(f);
                }
            }
        }
    }
    has_phi
        .iter()
        .enumerate()
        .filter(|(_, &h)| h)
        .map(|(i, _)| i)
        .collect()
}

/// Rename SSA values using dominator tree walk.
fn rename_values(
    form: &mut SsaForm,
    block_effects: &[Vec<SsaEffect>],
    dom: &DomTree,
    n_blocks: usize,
) {
    let mut stacks: Vec<Vec<ValId>> = (0..REG_COUNT)
        .map(|r| vec![r])
        .collect();
    let dom_children = build_dom_children(&dom.idom, n_blocks);
    let mut worklist: Vec<(usize, bool)> = vec![(0, false)];
    let mut snap: Vec<Vec<usize>> =
        vec![Vec::new(); n_blocks];
    while let Some((b, restore)) = worklist.pop() {
        if restore {
            restore_stacks(&mut stacks, &snap[b]);
            continue;
        }
        snap[b] = save_stack_lens(&stacks);
        rename_block_phis(form, b, &mut stacks);
        rename_block_effects(
            form, b, block_effects, &mut stacks,
        );
        fill_succ_phis(form, b, n_blocks, &stacks);
        worklist.push((b, true));
        for &c in dom_children[b].iter().rev() {
            worklist.push((c, false));
        }
    }
}

/// Build a children list from the immediate dominator array.
fn build_dom_children(
    idom: &[Option<usize>],
    n: usize,
) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); n];
    for b in 0..n {
        if let Some(d) = idom[b] {
            if d != b {
                children[d].push(b);
            }
        }
    }
    children
}

/// Snapshot current stack depths for restoration after subtree walk.
fn save_stack_lens(
    stacks: &[Vec<ValId>],
) -> Vec<usize> {
    stacks.iter().map(|s| s.len()).collect()
}

/// Restore stacks to saved depths after processing a dominator subtree.
fn restore_stacks(
    stacks: &mut [Vec<ValId>],
    lens: &[usize],
) {
    for (s, &l) in stacks.iter_mut().zip(lens) {
        s.truncate(l);
    }
}

/// Push phi-node values onto register stacks for the current block.
fn rename_block_phis(
    form: &mut SsaForm,
    b: usize,
    stacks: &mut [Vec<ValId>],
) {
    for &phi_idx in &form.block_phis[b].clone() {
        let phi = &form.phis[phi_idx];
        let reg = phi.reg as usize;
        let vid = phi.val;
        stacks[reg].push(vid);
    }
}

/// Record effects and push new SSA definitions onto register stacks.
fn rename_block_effects(
    form: &mut SsaForm,
    b: usize,
    block_effects: &[Vec<SsaEffect>],
    stacks: &mut [Vec<ValId>],
) {
    for eff in &block_effects[b] {
        let vid = form.defs.len();
        form.defs.push(SsaDef::Effect(eff.clone(), b));
        push_def(eff, vid, stacks);
        form.block_defs[b].push((vid, eff.clone()));
    }
}

/// Push an SSA value ID onto the stack for the register defined by the effect.
fn push_def(
    eff: &SsaEffect,
    vid: ValId,
    stacks: &mut [Vec<ValId>],
) {
    match eff {
        SsaEffect::MovConst(d, _)
        | SsaEffect::MovReg(d, _)
        | SsaEffect::Clobber(d)
        | SsaEffect::BinOp(d, _, _, _)
        | SsaEffect::BinOpImm(d, _, _, _) => {
            stacks[*d as usize].push(vid);
        }
        SsaEffect::CmpReg(_, _)
        | SsaEffect::CmpImm(_, _)
        | SsaEffect::TestReg(_, _)
        | SsaEffect::TestImm(_, _) => {
            let fr =
                crate::analysis::regstate::FLAGS_REG as usize;
            stacks[fr].push(vid);
        }
        SsaEffect::Nop => {}
    }
}

/// Fill phi-node operands from successor blocks (deferred to SCCP).
fn fill_succ_phis(
    _form: &mut SsaForm,
    _b: usize,
    _n_blocks: usize,
    _stacks: &[Vec<ValId>],
) {
    // Phi operand filling is done in SCCP directly
    // using current reaching definitions
}
