//! Dominator tree and dominance frontier computation.
//!
//! Implements the Cooper-Harvey-Kennedy iterative dominator algorithm
//! to compute immediate dominators and dominance frontiers for a CFG.
//! Used by SSA construction to determine phi-node placement.

use std::collections::HashSet;

/// Dominance info for a CFG.
pub struct DomTree {
    pub idom: Vec<Option<usize>>,
    pub frontiers: Vec<HashSet<usize>>,
}

/// Compute dominance tree using Cooper-Harvey-Kennedy
/// iterative algorithm. Takes successors per block and
/// the entry block index.
pub fn compute_dom_tree(
    succs: &[Vec<usize>],
    entry: usize,
    n: usize,
) -> DomTree {
    let preds = build_predecessors(succs, n);
    let order = compute_rpo(succs, entry, n);
    let rpo_num = build_rpo_numbers(&order, n);
    let idom = compute_idoms(&preds, &order, &rpo_num, entry, n);
    let frontiers = compute_frontiers(&idom, &preds, n);
    DomTree { idom, frontiers }
}

/// Build predecessor lists from successor edges.
fn build_predecessors(
    succs: &[Vec<usize>],
    n: usize,
) -> Vec<Vec<usize>> {
    let mut preds = vec![Vec::new(); n];
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            if s < n {
                preds[s].push(b);
            }
        }
    }
    preds
}

/// Reverse post-order via iterative DFS.
fn compute_rpo(
    succs: &[Vec<usize>],
    entry: usize,
    n: usize,
) -> Vec<usize> {
    let mut visited = vec![false; n];
    let mut post_order = Vec::with_capacity(n);
    let mut stack = vec![(entry, false)];
    while let Some((node, processed)) = stack.pop() {
        if node >= n {
            continue;
        }
        if processed {
            post_order.push(node);
            continue;
        }
        if visited[node] {
            continue;
        }
        visited[node] = true;
        stack.push((node, true));
        for &s in succs[node].iter().rev() {
            if s < n && !visited[s] {
                stack.push((s, false));
            }
        }
    }
    post_order.reverse();
    post_order
}

/// Assign reverse post-order numbers to each block.
fn build_rpo_numbers(
    order: &[usize],
    n: usize,
) -> Vec<usize> {
    let mut nums = vec![n; n];
    for (i, &b) in order.iter().enumerate() {
        if b < n {
            nums[b] = i;
        }
    }
    nums
}

/// Iterative dominator computation (CHK algorithm).
fn compute_idoms(
    preds: &[Vec<usize>],
    order: &[usize],
    rpo_num: &[usize],
    entry: usize,
    n: usize,
) -> Vec<Option<usize>> {
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[entry] = Some(entry);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in order.iter() {
            if b == entry {
                continue;
            }
            let new_idom = find_new_idom(
                b, preds, &idom, rpo_num, n,
            );
            if idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

/// Find the new immediate dominator for block `b` from its predecessors.
fn find_new_idom(
    b: usize,
    preds: &[Vec<usize>],
    idom: &[Option<usize>],
    rpo_num: &[usize],
    n: usize,
) -> Option<usize> {
    let mut result: Option<usize> = None;
    for &p in &preds[b] {
        if p >= n || idom[p].is_none() {
            continue;
        }
        result = Some(match result {
            None => p,
            Some(r) => intersect(r, p, idom, rpo_num),
        });
    }
    result
}

/// Find common dominator of two blocks.
fn intersect(
    mut a: usize,
    mut b: usize,
    idom: &[Option<usize>],
    rpo_num: &[usize],
) -> usize {
    while a != b {
        while rpo_num[a] > rpo_num[b] {
            a = idom[a].unwrap_or(a);
        }
        while rpo_num[b] > rpo_num[a] {
            b = idom[b].unwrap_or(b);
        }
    }
    a
}

/// Compute dominance frontiers from idom.
fn compute_frontiers(
    idom: &[Option<usize>],
    preds: &[Vec<usize>],
    n: usize,
) -> Vec<HashSet<usize>> {
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for b in 0..n {
        if preds[b].len() < 2 {
            continue;
        }
        for &p in &preds[b] {
            let mut runner = p;
            while Some(runner) != idom[b]
                && runner < n
            {
                df[runner].insert(b);
                runner = match idom[runner] {
                    Some(d) => d,
                    None => break,
                };
            }
        }
    }
    df
}
