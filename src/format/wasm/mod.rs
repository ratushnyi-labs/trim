use crate::types::{FuncInfo, FuncMap, Section};
use std::collections::{HashMap, HashSet, VecDeque};

/// Analyze a WebAssembly module for dead functions.
/// Returns (funcs, dead, sections).
pub fn analyze_wasm(
    data: &[u8],
) -> (FuncMap, HashMap<String, (u64, u64)>, Vec<Section>) {
    let module = match parse_module(data) {
        Some(m) => m,
        None => return empty(),
    };
    let funcs = build_func_map(&module);
    if funcs.is_empty() {
        return empty();
    }
    let dead = find_dead_functions(&module, &funcs);
    (funcs, dead, Vec::new())
}

/// Patch dead Wasm function bodies with `unreachable; end`.
/// Returns (func_count, func_saved, 0, 0).
pub fn reassemble_wasm(
    data: &mut Vec<u8>,
    dead: &HashMap<String, (u64, u64)>,
) -> (usize, u64, usize, u64) {
    let mut count = 0;
    let mut saved = 0u64;
    for (_, &(offset, size)) in dead {
        let off = offset as usize;
        let sz = size as usize;
        if off + sz <= data.len() && sz >= 2 {
            data[off] = 0x00;
            data[off + 1] = 0x0B;
            for b in &mut data[off + 2..off + sz] {
                *b = 0x00;
            }
            count += 1;
            saved += (sz as u64).saturating_sub(2);
        }
    }
    (count, saved, 0, 0)
}

struct WasmModule {
    functions: Vec<WasmFunc>,
    roots: HashSet<u32>,
    call_graph: HashMap<u32, Vec<u32>>,
}

struct WasmFunc {
    index: u32,
    name: String,
    body_offset: u64,
    body_size: u64,
}

fn parse_module(data: &[u8]) -> Option<WasmModule> {
    use wasmparser::{Parser, Payload};
    let parser = Parser::new(0);
    let mut num_imports = 0u32;
    let mut type_indices: Vec<u32> = Vec::new();
    let mut roots = HashSet::new();
    let mut call_graph: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut functions: Vec<WasmFunc> = Vec::new();
    let mut func_names: HashMap<u32, String> = HashMap::new();
    let mut code_idx = 0u32;

    for payload in parser.parse_all(data) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => return None,
        };
        match payload {
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group = match group {
                        Ok(g) => g,
                        Err(_) => return None,
                    };
                    for item in group.into_iter() {
                        let (_, import) = match item {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        if matches!(
                            import.ty,
                            wasmparser::TypeRef::Func(_)
                        ) {
                            num_imports += 1;
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for entry in reader {
                    match entry {
                        Ok(idx) => type_indices.push(idx),
                        Err(_) => return None,
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = match export {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    if matches!(
                        export.kind,
                        wasmparser::ExternalKind::Func
                    ) {
                        roots.insert(export.index);
                        func_names.insert(
                            export.index,
                            export.name.to_string(),
                        );
                    }
                }
            }
            Payload::StartSection { func, .. } => {
                roots.insert(func);
            }
            Payload::ElementSection(reader) => {
                parse_elements(reader, &mut roots);
            }
            Payload::CodeSectionEntry(body) => {
                let func_idx = num_imports + code_idx;
                let range = body.range();
                let body_offset = range.start as u64;
                let body_size =
                    (range.end - range.start) as u64;
                let name = func_names
                    .get(&func_idx)
                    .cloned()
                    .unwrap_or_else(|| {
                        format!("wasm_func_{}", func_idx)
                    });
                functions.push(WasmFunc {
                    index: func_idx,
                    name,
                    body_offset,
                    body_size,
                });
                let callees =
                    extract_calls(body, func_idx);
                call_graph.insert(func_idx, callees);
                code_idx += 1;
            }
            _ => {}
        }
    }
    Some(WasmModule {
        functions,
        roots,
        call_graph,
    })
}

fn parse_elements(
    reader: wasmparser::ElementSectionReader<'_>,
    roots: &mut HashSet<u32>,
) {
    for elem in reader {
        let elem = match elem {
            Ok(e) => e,
            Err(_) => continue,
        };
        match elem.items {
            wasmparser::ElementItems::Functions(r) => {
                for idx in r {
                    if let Ok(i) = idx {
                        roots.insert(i);
                    }
                }
            }
            wasmparser::ElementItems::Expressions(
                _,
                _,
            ) => {}
        }
    }
}

fn extract_calls(
    body: wasmparser::FunctionBody<'_>,
    _func_idx: u32,
) -> Vec<u32> {
    let mut callees = Vec::new();
    let mut reader = match body.get_operators_reader() {
        Ok(r) => r,
        Err(_) => return callees,
    };
    while !reader.eof() {
        match reader.read() {
            Ok(op) => match op {
                wasmparser::Operator::Call {
                    function_index,
                } => {
                    callees.push(function_index);
                }
                wasmparser::Operator::CallIndirect {
                    ..
                } => {}
                _ => {}
            },
            Err(_) => break,
        }
    }
    callees
}

fn build_func_map(module: &WasmModule) -> FuncMap {
    let mut funcs = FuncMap::new();
    for f in &module.functions {
        funcs.insert(
            f.name.clone(),
            FuncInfo {
                addr: f.body_offset,
                size: f.body_size,
                is_global: module.roots.contains(&f.index),
            },
        );
    }
    funcs
}

fn find_dead_functions(
    module: &WasmModule,
    _funcs: &FuncMap,
) -> HashMap<String, (u64, u64)> {
    let live = bfs_live(module);
    let mut dead = HashMap::new();
    for f in &module.functions {
        if !live.contains(&f.index) {
            dead.insert(
                f.name.clone(),
                (f.body_offset, f.body_size),
            );
        }
    }
    dead
}

fn bfs_live(module: &WasmModule) -> HashSet<u32> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for &root in &module.roots {
        if !visited.contains(&root) {
            visited.insert(root);
            queue.push_back(root);
        }
    }
    while let Some(idx) = queue.pop_front() {
        if let Some(callees) = module.call_graph.get(&idx) {
            for &callee in callees {
                if !visited.contains(&callee) {
                    visited.insert(callee);
                    queue.push_back(callee);
                }
            }
        }
    }
    visited
}

fn empty() -> (
    FuncMap,
    HashMap<String, (u64, u64)>,
    Vec<Section>,
) {
    (FuncMap::new(), HashMap::new(), Vec::new())
}
