//! Call graph construction from decoded instructions.
//!
//! Builds a directed reference graph mapping each function to the set of
//! functions it calls. Supports both a simple O(n*m) builder and an
//! optimized O(n log m) builder using sorted address indices. Also
//! tracks orphan references — calls from outside any known function —
//! which are treated as additional roots for reachability analysis.

use crate::types::{DecodedInstr, FuncMap, RefGraph};
use std::collections::HashSet;

/// Build a reference graph from decoded instructions.
/// Returns (graph, orphan_refs).
pub fn build_ref_graph(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
) -> (RefGraph, HashSet<String>) {
    let mut graph: RefGraph = funcs
        .keys()
        .map(|k| (k.clone(), HashSet::new()))
        .collect();
    let mut orphan_refs = HashSet::new();
    for instr in instrs {
        let src = resolve_addr(instr.addr, funcs);
        for &tgt_addr in &instr.targets {
            let tgt = resolve_addr(tgt_addr, funcs);
            if let Some(ref tgt_name) = tgt {
                if let Some(ref src_name) = src {
                    if src_name != tgt_name {
                        graph
                            .entry(src_name.clone())
                            .or_default()
                            .insert(tgt_name.clone());
                    }
                } else {
                    orphan_refs.insert(tgt_name.clone());
                }
            }
        }
    }
    (graph, orphan_refs)
}

/// Resolve an address to its containing function name.
fn resolve_addr(
    addr: u64,
    funcs: &FuncMap,
) -> Option<String> {
    // Exact match first
    for (name, fi) in funcs {
        if fi.addr == addr {
            return Some(name.clone());
        }
    }
    // Range match
    for (name, fi) in funcs {
        if fi.addr <= addr && addr < fi.addr + fi.size {
            return Some(name.clone());
        }
    }
    None
}

/// Build a sorted lookup for efficient address resolution.
pub fn build_addr_index(
    funcs: &FuncMap,
) -> Vec<(u64, u64, String)> {
    let mut ranges: Vec<(u64, u64, String)> = funcs
        .iter()
        .map(|(n, fi)| (fi.addr, fi.addr + fi.size, n.clone()))
        .collect();
    ranges.sort_by_key(|r| r.0);
    ranges
}

/// Resolve address using sorted index (binary search).
pub fn resolve_addr_fast(
    addr: u64,
    index: &[(u64, u64, String)],
) -> Option<&str> {
    // Exact match via binary search
    if let Ok(i) =
        index.binary_search_by_key(&addr, |r| r.0)
    {
        return Some(&index[i].2);
    }
    // Range match: find insertion point, check previous
    let i =
        index.partition_point(|r| r.0 <= addr);
    if i > 0 {
        let (start, end, ref name) = index[i - 1];
        if start <= addr && addr < end {
            return Some(name);
        }
    }
    None
}

/// Optimized graph builder using sorted index.
pub fn build_ref_graph_fast(
    funcs: &FuncMap,
    instrs: &[DecodedInstr],
) -> (RefGraph, HashSet<String>) {
    let index = build_addr_index(funcs);
    let mut graph: RefGraph = funcs
        .keys()
        .map(|k| (k.clone(), HashSet::new()))
        .collect();
    let mut orphan_refs = HashSet::new();
    for instr in instrs {
        let src = resolve_addr_fast(instr.addr, &index);
        for &tgt_addr in &instr.targets {
            let tgt = resolve_addr_fast(tgt_addr, &index);
            match (src, tgt) {
                (Some(s), Some(t)) if s != t => {
                    graph
                        .entry(s.to_string())
                        .or_default()
                        .insert(t.to_string());
                }
                (None, Some(t)) => {
                    orphan_refs.insert(t.to_string());
                }
                _ => {}
            }
        }
    }
    (graph, orphan_refs)
}

/// Resolve all functions at a given address (handles aliases).
pub fn funcs_at_addr(
    addr: u64,
    funcs: &FuncMap,
) -> Vec<String> {
    funcs
        .iter()
        .filter(|(_, fi)| fi.addr == addr)
        .map(|(n, _)| n.clone())
        .collect()
}
