//! BFS reachability analysis over the function reference graph.
//!
//! Starting from root functions (entry points, globals, runtime-keep),
//! performs breadth-first traversal of the call/reference graph to
//! compute the live function set. Functions not in the live set are
//! considered dead. Includes alias-aware fixpoint expansion to handle
//! multiple symbols at the same address.

use crate::types::{FuncMap, RefGraph};
use std::collections::{HashMap, HashSet, VecDeque};

/// BFS reachability from roots through the reference graph.
pub fn bfs(
    roots: &HashSet<String>,
    graph: &RefGraph,
) -> HashSet<String> {
    let mut live = HashSet::new();
    let mut queue: VecDeque<String> =
        roots.iter().cloned().collect();
    while let Some(name) = queue.pop_front() {
        if !live.insert(name.clone()) {
            continue;
        }
        if let Some(callees) = graph.get(&name) {
            for callee in callees {
                if !live.contains(callee) {
                    queue.push_back(callee.clone());
                }
            }
        }
    }
    live
}

/// Compute the full live set with alias fixpoint expansion.
pub fn compute_live_set(
    roots: &HashSet<String>,
    graph: &RefGraph,
    funcs: &FuncMap,
) -> HashSet<String> {
    let mut live = bfs(roots, graph);
    // Build addr -> [names] map for alias expansion
    let mut addr_to_names: HashMap<u64, Vec<String>> =
        HashMap::new();
    for (name, fi) in funcs {
        addr_to_names
            .entry(fi.addr)
            .or_default()
            .push(name.clone());
    }
    // Fixpoint: expand live set by address aliases
    loop {
        let prev_size = live.len();
        let live_addrs: HashSet<u64> = live
            .iter()
            .filter_map(|n| funcs.get(n).map(|fi| fi.addr))
            .collect();
        for addr in &live_addrs {
            if let Some(names) = addr_to_names.get(addr) {
                for name in names {
                    live.insert(name.clone());
                }
            }
        }
        live = bfs(&live, graph);
        if live.len() == prev_size {
            break;
        }
    }
    live
}

/// Find dead functions (not in live set, size >= 4).
pub fn find_dead(
    funcs: &FuncMap,
    live: &HashSet<String>,
) -> HashMap<String, (u64, u64)> {
    let mut dead = HashMap::new();
    for (name, fi) in funcs {
        if !live.contains(name) && fi.size >= 4 {
            dead.insert(name.clone(), (fi.addr, fi.size));
        }
    }
    dead
}
