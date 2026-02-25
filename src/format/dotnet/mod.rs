pub mod il;
pub mod metadata;
pub mod patch;
pub mod tables;

use crate::types::{FuncInfo, FuncMap, Section};
use std::collections::{HashMap, HashSet};

struct ParsedDotnet {
    cli: metadata::CliHeader,
    root: metadata::MetadataRoot,
    methods: Vec<tables::MethodDef>,
    types: Vec<tables::TypeDef>,
}

/// Analyze a .NET managed assembly.
pub fn analyze_dotnet(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let parsed = match parse_dotnet_metadata(data) {
        Some(p) => p,
        None => return empty(),
    };
    let funcs = build_func_map(
        &parsed.methods, &parsed.root, data,
    );
    let dead = run_analysis(
        &funcs, &parsed.methods, &parsed.types,
        &parsed.cli, data, &parsed.root,
    );
    (funcs, dead, Vec::new())
}

fn parse_dotnet_metadata(
    data: &[u8],
) -> Option<ParsedDotnet> {
    let cli_off = metadata::cli_header_offset(data)?;
    let cli =
        metadata::parse_cli_header(data, cli_off)?;
    let md_off =
        pe_rva_to_offset(data, cli.metadata_rva)?;
    let root =
        metadata::parse_metadata_root(data, md_off)?;
    let ts = tables::parse_table_stream(data, &root)?;
    let methods = tables::read_method_defs(data, &ts);
    let types = tables::read_type_defs(data, &ts);
    if methods.is_empty() {
        return None;
    }
    Some(ParsedDotnet { cli, root, methods, types })
}

fn build_func_map(
    methods: &[tables::MethodDef],
    root: &metadata::MetadataRoot,
    data: &[u8],
) -> FuncMap {
    let mut funcs = FuncMap::new();
    for (i, m) in methods.iter().enumerate() {
        if m.rva == 0 {
            continue;
        }
        let name = tables::get_string(data, root, m.name_idx);
        if name.is_empty() {
            continue;
        }
        let is_public = (m.flags & 0x0006) == 0x0006;
        let size = estimate_method_size(data, m.rva);
        funcs.insert(
            name,
            FuncInfo {
                addr: m.rva as u64,
                size,
                is_global: is_public,
            },
        );
    }
    funcs
}

fn run_analysis(
    funcs: &FuncMap,
    methods: &[tables::MethodDef],
    types: &[tables::TypeDef],
    cli: &metadata::CliHeader,
    data: &[u8],
    root: &metadata::MetadataRoot,
) -> HashMap<String, (u64, u64)> {
    let rvas: Vec<u32> =
        methods.iter().map(|m| m.rva).collect();
    let rva_fn =
        |rva: u32| -> Option<usize> { pe_rva_to_offset(data, rva) };
    let graph =
        il::build_il_call_graph(data, &rvas, &rva_fn);
    let roots = find_roots(
        methods, types, cli, data, root,
    );
    let live = bfs_live(&roots, &graph, methods.len());
    find_dead_methods(funcs, methods, &live, data, root)
}

fn find_roots(
    methods: &[tables::MethodDef],
    types: &[tables::TypeDef],
    cli: &metadata::CliHeader,
    data: &[u8],
    root: &metadata::MetadataRoot,
) -> HashSet<usize> {
    let mut roots = HashSet::new();
    let ep_token = cli.entry_point_token;
    if (ep_token >> 24) == 0x06 {
        let idx = (ep_token & 0x00FF_FFFF) as usize;
        if idx > 0 && idx <= methods.len() {
            roots.insert(idx - 1);
        }
    }
    mark_public_type_methods(
        &mut roots, types, methods, data, root,
    );
    roots
}

fn mark_public_type_methods(
    roots: &mut HashSet<usize>,
    types: &[tables::TypeDef],
    methods: &[tables::MethodDef],
    data: &[u8],
    root: &metadata::MetadataRoot,
) {
    let total = methods.len() as u32;
    for (i, td) in types.iter().enumerate() {
        let is_public = (td.flags & 0x07) >= 0x01;
        if !is_public {
            continue;
        }
        let start = td.method_list.saturating_sub(1);
        let end = if i + 1 < types.len() {
            types[i + 1].method_list.saturating_sub(1)
        } else {
            total
        };
        for idx in start..end.min(total) {
            roots.insert(idx as usize);
        }
    }
}

fn bfs_live(
    roots: &HashSet<usize>,
    graph: &HashMap<usize, HashSet<u32>>,
    total: usize,
) -> HashSet<usize> {
    let mut live = HashSet::new();
    let mut queue: Vec<usize> =
        roots.iter().copied().collect();
    while let Some(idx) = queue.pop() {
        if !live.insert(idx) {
            continue;
        }
        if let Some(callees) = graph.get(&idx) {
            for &token in callees {
                if let Some(callee) =
                    token_to_method_idx(token, total)
                {
                    if !live.contains(&callee) {
                        queue.push(callee);
                    }
                }
            }
        }
    }
    live
}

fn token_to_method_idx(
    token: u32,
    total: usize,
) -> Option<usize> {
    let table = (token >> 24) as u8;
    let row = (token & 0x00FF_FFFF) as usize;
    if table == 0x06 && row > 0 && row <= total {
        Some(row - 1)
    } else {
        None
    }
}

fn find_dead_methods(
    funcs: &FuncMap,
    methods: &[tables::MethodDef],
    live: &HashSet<usize>,
    data: &[u8],
    root: &metadata::MetadataRoot,
) -> HashMap<String, (u64, u64)> {
    let mut dead = HashMap::new();
    for (i, m) in methods.iter().enumerate() {
        if m.rva == 0 || live.contains(&i) {
            continue;
        }
        let name = tables::get_string(data, root, m.name_idx);
        if name.is_empty() {
            continue;
        }
        let size = estimate_method_size(data, m.rva);
        dead.insert(name, (m.rva as u64, size));
    }
    dead
}

fn estimate_method_size(data: &[u8], rva: u32) -> u64 {
    let off = match pe_rva_to_offset(data, rva) {
        Some(o) => o,
        None => return 0,
    };
    if off >= data.len() {
        return 0;
    }
    let header = data[off];
    if header & 0x03 == 0x02 {
        1 + (header >> 2) as u64
    } else if header & 0x03 == 0x03 {
        if off + 12 > data.len() {
            return 0;
        }
        let fs = data[off] as u16
            | ((data[off + 1] as u16) << 8);
        let hs = (((fs >> 12) & 0x0F) * 4) as u64;
        let cs = metadata::read_u32(data, off + 4) as u64;
        hs + cs
    } else {
        0
    }
}

fn pe_rva_to_offset(
    data: &[u8],
    rva: u32,
) -> Option<usize> {
    if data.len() < 0x3C + 4 {
        return None;
    }
    let pe_off = metadata::read_u32(data, 0x3C) as usize;
    let coff_off = pe_off + 4;
    if coff_off + 20 > data.len() {
        return None;
    }
    let num = metadata::read_u16(data, coff_off + 2) as usize;
    let opt_sz =
        metadata::read_u16(data, coff_off + 16) as usize;
    let sec_off = coff_off + 20 + opt_sz;
    for i in 0..num {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            return None;
        }
        let vs = metadata::read_u32(data, s + 8);
        let va = metadata::read_u32(data, s + 12);
        let ro = metadata::read_u32(data, s + 20);
        if rva >= va && rva < va + vs {
            return Some((rva - va + ro) as usize);
        }
    }
    None
}

/// Reassemble .NET assembly: zero dead IL methods.
pub fn reassemble_dotnet(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
    _sections: &[Section],
) -> (usize, u64) {
    let dead_rvas: Vec<(u32, String)> = dead
        .iter()
        .map(|(n, &(a, _))| (a as u32, n.clone()))
        .collect();
    let orig = data.clone();
    let rva_fn = |rva: u32| -> Option<usize> {
        pe_rva_to_offset(&orig, rva)
    };
    patch::zero_dead_methods(data, &dead_rvas, &rva_fn)
}

fn empty()
-> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}
