use crate::format::dotnet::metadata::read_u32;

/// Zero dead IL method bodies, replacing with `ret`.
/// Returns (count_patched, bytes_saved).
pub fn zero_dead_methods(
    data: &mut Vec<u8>,
    dead_rvas: &[(u32, String)],
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> (usize, u64) {
    let mut count = 0usize;
    let mut saved = 0u64;
    for (rva, _name) in dead_rvas {
        if let Some(off) = rva_to_offset(*rva) {
            let freed = zero_method_body(data, off);
            if freed > 0 {
                count += 1;
                saved += freed;
            }
        }
    }
    (count, saved)
}

/// Zero a single method body, return bytes freed.
fn zero_method_body(
    data: &mut Vec<u8>,
    offset: usize,
) -> u64 {
    if offset >= data.len() {
        return 0;
    }
    let header = data[offset];
    let (code_off, code_size) = if header & 0x03 == 0x02 {
        let sz = (header >> 2) as usize;
        (offset + 1, sz)
    } else if header & 0x03 == 0x03 {
        parse_fat_size(data, offset)
    } else {
        return 0;
    };
    if code_size <= 1 || code_off + code_size > data.len()
    {
        return 0;
    }
    data[code_off] = 0x2A;
    for i in 1..code_size {
        data[code_off + i] = 0x00;
    }
    (code_size - 1) as u64
}

fn parse_fat_size(
    data: &[u8],
    offset: usize,
) -> (usize, usize) {
    if offset + 12 > data.len() {
        return (0, 0);
    }
    let flags_size = data[offset] as u16
        | ((data[offset + 1] as u16) << 8);
    let hdr_size = ((flags_size >> 12) & 0x0F) * 4;
    let code_size = read_u32(data, offset + 4) as usize;
    (offset + hdr_size as usize, code_size)
}
