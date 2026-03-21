/// Java .class file parser (ECMA/JVM spec).

/// Parsed constant pool entry.
#[derive(Clone)]
pub enum CpEntry {
    Utf8(String),
    Integer,
    Float,
    Long,       // takes 2 slots
    Double,     // takes 2 slots
    Class(u16), // name_index
    String(u16),
    Fieldref(u16, u16),       // class, name_and_type
    Methodref(u16, u16),      // class, name_and_type
    InterfaceMethodref(u16, u16),
    NameAndType(u16, u16),    // name, descriptor
    MethodHandle(u8, u16),
    MethodType(u16),
    InvokeDynamic(u16, u16),
    Placeholder, // second slot for Long/Double
}

/// Parsed method info.
pub struct MethodInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub code_offset: Option<usize>, // file offset of Code attribute bytecode
    pub code_length: usize,
    pub code_attr_offset: Option<usize>, // file offset of Code attr header
    pub exception_table_len: u16,
    pub raw_offset: usize, // file offset of method_info start
    pub raw_size: usize,   // total bytes of this method_info
}

/// Parsed class file.
pub struct ClassFile {
    pub constant_pool: Vec<CpEntry>,
    pub access_flags: u16,
    pub methods: Vec<MethodInfo>,
    pub methods_count_offset: usize, // file offset of methods_count u16
    pub total_size: usize,
}

/// Parse a Java .class file.
pub fn parse_classfile(data: &[u8]) -> Option<ClassFile> {
    if data.len() < 10
        || read_u32(data, 0) != 0xCAFE_BABE
    {
        return None;
    }
    let mut pos = 8; // skip magic + version
    let cp_count = read_u16(data, pos) as usize;
    pos += 2;
    let (pool, new_pos) =
        parse_constant_pool(data, pos, cp_count)?;
    pos = new_pos;
    let access_flags = read_u16(data, pos);
    pos += 2; // access_flags
    pos += 2; // this_class
    pos += 2; // super_class
    // interfaces
    let iface_count = read_u16(data, pos) as usize;
    pos += 2 + iface_count * 2;
    // fields
    pos = skip_fields_or_methods(data, pos, &pool)?;
    // methods
    let methods_count_offset = pos;
    let method_count = read_u16(data, pos) as usize;
    pos += 2;
    let mut methods = Vec::with_capacity(method_count);
    for _ in 0..method_count {
        let (m, new_pos) =
            parse_method(data, pos, &pool)?;
        methods.push(m);
        pos = new_pos;
    }
    // Skip class attributes
    pos = skip_attributes(data, pos)?;
    Some(ClassFile {
        constant_pool: pool,
        access_flags,
        methods,
        methods_count_offset,
        total_size: pos,
    })
}

fn parse_constant_pool(
    data: &[u8],
    mut pos: usize,
    cp_count: usize,
) -> Option<(Vec<CpEntry>, usize)> {
    // Pool indices are 1-based; slot 0 is placeholder
    let mut pool = Vec::with_capacity(cp_count);
    pool.push(CpEntry::Placeholder);
    let mut i = 1;
    while i < cp_count {
        if pos >= data.len() {
            return None;
        }
        let tag = data[pos];
        pos += 1;
        match tag {
            1 => {
                // CONSTANT_Utf8
                if pos + 2 > data.len() {
                    return None;
                }
                let len = read_u16(data, pos) as usize;
                pos += 2;
                if pos + len > data.len() {
                    return None;
                }
                let s = String::from_utf8_lossy(
                    &data[pos..pos + len],
                )
                .to_string();
                pos += len;
                pool.push(CpEntry::Utf8(s));
            }
            3 => {
                pos += 4;
                pool.push(CpEntry::Integer);
            }
            4 => {
                pos += 4;
                pool.push(CpEntry::Float);
            }
            5 => {
                pos += 8;
                pool.push(CpEntry::Long);
                pool.push(CpEntry::Placeholder);
                i += 1;
            }
            6 => {
                pos += 8;
                pool.push(CpEntry::Double);
                pool.push(CpEntry::Placeholder);
                i += 1;
            }
            7 => {
                let ni = read_u16(data, pos);
                pos += 2;
                pool.push(CpEntry::Class(ni));
            }
            8 => {
                let si = read_u16(data, pos);
                pos += 2;
                pool.push(CpEntry::String(si));
            }
            9 => {
                let ci = read_u16(data, pos);
                let nti = read_u16(data, pos + 2);
                pos += 4;
                pool.push(CpEntry::Fieldref(ci, nti));
            }
            10 => {
                let ci = read_u16(data, pos);
                let nti = read_u16(data, pos + 2);
                pos += 4;
                pool.push(CpEntry::Methodref(ci, nti));
            }
            11 => {
                let ci = read_u16(data, pos);
                let nti = read_u16(data, pos + 2);
                pos += 4;
                pool.push(
                    CpEntry::InterfaceMethodref(ci, nti),
                );
            }
            12 => {
                let ni = read_u16(data, pos);
                let di = read_u16(data, pos + 2);
                pos += 4;
                pool.push(CpEntry::NameAndType(ni, di));
            }
            15 => {
                let rk = data[pos];
                let ri = read_u16(data, pos + 1);
                pos += 3;
                pool.push(CpEntry::MethodHandle(rk, ri));
            }
            16 => {
                let di = read_u16(data, pos);
                pos += 2;
                pool.push(CpEntry::MethodType(di));
            }
            18 => {
                let bi = read_u16(data, pos);
                let nti = read_u16(data, pos + 2);
                pos += 4;
                pool.push(
                    CpEntry::InvokeDynamic(bi, nti),
                );
            }
            _ => return None,
        }
        i += 1;
    }
    Some((pool, pos))
}

fn parse_method(
    data: &[u8],
    start: usize,
    pool: &[CpEntry],
) -> Option<(MethodInfo, usize)> {
    let mut pos = start;
    if pos + 8 > data.len() {
        return None;
    }
    let access_flags = read_u16(data, pos);
    let name_index = read_u16(data, pos + 2);
    let descriptor_index = read_u16(data, pos + 4);
    let attr_count = read_u16(data, pos + 6) as usize;
    pos += 8;
    let mut code_offset = None;
    let mut code_length = 0usize;
    let mut code_attr_offset = None;
    let mut exception_table_len = 0u16;
    for _ in 0..attr_count {
        if pos + 6 > data.len() {
            return None;
        }
        let attr_name_idx =
            read_u16(data, pos) as usize;
        let attr_len =
            read_u32(data, pos + 2) as usize;
        let attr_data_start = pos + 6;
        // Check if this is a Code attribute
        if attr_name_idx < pool.len() {
            if let CpEntry::Utf8(ref s) =
                pool[attr_name_idx]
            {
                if s == "Code"
                    && attr_data_start + 8
                        <= data.len()
                {
                    let cl = read_u32(
                        data,
                        attr_data_start + 4,
                    ) as usize;
                    code_offset =
                        Some(attr_data_start + 8);
                    code_length = cl;
                    code_attr_offset = Some(pos);
                    // exception_table_length
                    let et_off =
                        attr_data_start + 8 + cl;
                    if et_off + 2 <= data.len() {
                        exception_table_len =
                            read_u16(data, et_off);
                    }
                }
            }
        }
        pos = attr_data_start + attr_len;
        if pos > data.len() {
            return None;
        }
    }
    Some((
        MethodInfo {
            access_flags,
            name_index,
            descriptor_index,
            code_offset,
            code_length,
            code_attr_offset,
            exception_table_len,
            raw_offset: start,
            raw_size: pos - start,
        },
        pos,
    ))
}

fn skip_fields_or_methods(
    data: &[u8],
    mut pos: usize,
    pool: &[CpEntry],
) -> Option<usize> {
    if pos + 2 > data.len() {
        return None;
    }
    let count = read_u16(data, pos) as usize;
    pos += 2;
    for _ in 0..count {
        if pos + 8 > data.len() {
            return None;
        }
        let attr_count =
            read_u16(data, pos + 6) as usize;
        pos += 8;
        for _ in 0..attr_count {
            if pos + 6 > data.len() {
                return None;
            }
            let len =
                read_u32(data, pos + 2) as usize;
            pos += 6 + len;
            if pos > data.len() {
                return None;
            }
        }
    }
    // This is called for fields, then methods are parsed separately
    // so we don't need pool for fields
    let _ = pool;
    Some(pos)
}

fn skip_attributes(
    data: &[u8],
    mut pos: usize,
) -> Option<usize> {
    if pos + 2 > data.len() {
        return Some(pos);
    }
    let count = read_u16(data, pos) as usize;
    pos += 2;
    for _ in 0..count {
        if pos + 6 > data.len() {
            return Some(pos);
        }
        let len = read_u32(data, pos + 2) as usize;
        pos += 6 + len;
    }
    Some(pos)
}

/// Get a UTF-8 string from the constant pool.
pub fn cp_utf8(pool: &[CpEntry], idx: u16) -> &str {
    let i = idx as usize;
    if i < pool.len() {
        if let CpEntry::Utf8(ref s) = pool[i] {
            return s;
        }
    }
    ""
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(
        data[off..off + 2].try_into().unwrap_or([0; 2]),
    )
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(
        data[off..off + 4].try_into().unwrap_or([0; 4]),
    )
}
