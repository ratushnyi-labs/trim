use crate::constants::RUNTIME_KEEP;
use crate::types::FuncMap;
use std::collections::HashSet;

/// Determine root functions for BFS reachability.
pub fn determine_roots(
    funcs: &FuncMap,
    data_ref_names: &HashSet<String>,
    orphan_refs: &HashSet<String>,
) -> HashSet<String> {
    let mut roots = HashSet::new();
    for (name, fi) in funcs {
        if RUNTIME_KEEP.contains(name.as_str()) || fi.is_global {
            roots.insert(name.clone());
        }
    }
    roots.extend(data_ref_names.iter().cloned());
    roots.extend(orphan_refs.iter().cloned());
    roots
}
