use crate::types::{FuncInfo, FuncMap};

const N_EXT: u8 = 0x01;
const N_TYPE_MASK: u8 = 0x0E;
const N_SECT: u8 = 0x0E;

/// Extract functions from Mach-O symbol table (nlist).
pub fn get_functions(
    macho: &goblin::mach::MachO,
) -> FuncMap {
    let mut funcs = FuncMap::new();
    for sym in macho.symbols() {
        if let Ok((name, nlist)) = sym {
            add_if_func(&mut funcs, name, &nlist);
        }
    }
    funcs
}

fn add_if_func(
    funcs: &mut FuncMap,
    name: &str,
    nlist: &goblin::mach::symbols::Nlist,
) {
    if (nlist.n_type & N_TYPE_MASK) != N_SECT {
        return;
    }
    let clean = strip_underscore(name);
    if clean.is_empty() {
        return;
    }
    let is_global = (nlist.n_type & N_EXT) != 0;
    funcs.insert(
        clean,
        FuncInfo {
            addr: nlist.n_value,
            size: 0,
            is_global,
        },
    );
}

/// Strip leading underscore (Mach-O C symbol convention).
fn strip_underscore(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('_') {
        rest.to_string()
    } else {
        name.to_string()
    }
}
