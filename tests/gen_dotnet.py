#!/usr/bin/env python3
"""Generate a minimal .NET managed PE assembly for testing.

Methods: Main (entry), LiveHelper (called by Main),
         DeadMethod1, DeadMethod2.
Main's IL body contains a `call` to LiveHelper.
Output: binary PE written to stdout.
"""
import struct
import sys


def le16(v):
    return struct.pack("<H", v & 0xFFFF)


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def le64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def align4(data):
    pad = (4 - len(data) % 4) % 4
    return data + b"\x00" * pad


def build_strings_heap():
    """Build #Strings heap with null-terminated names."""
    heap = b"\x00"
    offsets = {}
    for name in [
        "<Module>",
        "Program",
        "Main",
        "LiveHelper",
        "DeadMethod1",
        "DeadMethod2",
    ]:
        offsets[name] = len(heap)
        heap += name.encode("utf-8") + b"\x00"
    return heap, offsets


def build_blob_heap():
    """Build #Blob heap (minimal: null + one void sig)."""
    return b"\x00\x02\x00\x01"


def build_method_bodies(sec_rva, body_file_off):
    """Build tiny IL method bodies.

    Returns (bodies_bytes, rva_list) where rva_list maps
    method index to its RVA.
    """
    bodies = bytearray()
    rvas = []

    def cur_rva():
        return sec_rva + (body_file_off + len(bodies))

    # Method 0: Main — calls LiveHelper
    # Tiny header: (code_size << 2) | 0x02
    # IL: call <token for MethodDef row 2> + ret
    # call = 0x28, token = 0x06000002 (table 0x06, row 2)
    # ret  = 0x2A
    rvas.append(cur_rva())
    main_code = (
        b"\x28"
        + le32(0x06000002)
        + b"\x2A"
    )
    main_hdr = bytes([(len(main_code) << 2) | 0x02])
    bodies += main_hdr + main_code

    # Method 1: LiveHelper — just ret
    rvas.append(cur_rva())
    live_code = b"\x2A"
    live_hdr = bytes([(len(live_code) << 2) | 0x02])
    bodies += live_hdr + live_code

    # Method 2: DeadMethod1 — just ret
    rvas.append(cur_rva())
    dead1_code = b"\x2A"
    dead1_hdr = bytes([(len(dead1_code) << 2) | 0x02])
    bodies += dead1_hdr + dead1_code

    # Method 3: DeadMethod2 — just ret
    rvas.append(cur_rva())
    dead2_code = b"\x2A"
    dead2_hdr = bytes([(len(dead2_code) << 2) | 0x02])
    bodies += dead2_hdr + dead2_code

    return bytes(bodies), rvas


def build_table_stream(
    method_rvas, str_offsets, typedef_count
):
    """Build #~ table stream with TypeDef and MethodDef."""
    # Header: 4 reserved + 1 major + 1 minor +
    #         1 heap_sizes + 1 reserved +
    #         8 valid + 8 sorted = 24 bytes
    heap_sizes = 0x00  # all indices 2-byte
    valid = (1 << 0x02) | (1 << 0x06)
    sorted_mask = 0

    hdr = (
        le32(0)
        + bytes([2, 0, heap_sizes, 1])
        + le64(valid)
        + le64(sorted_mask)
    )

    method_count = len(method_rvas)
    row_counts = le32(typedef_count) + le32(method_count)

    # TypeDef rows (2 rows):
    # Row format (narrow indices):
    #   flags: u32, name: u16, namespace: u16,
    #   extends: u16 (coded TypeDefOrRef, 2 tag bits),
    #   field_list: u16, method_list: u16
    #   = 4 + 2 + 2 + 2 + 2 + 2 = 14 bytes

    # Row 1: <Module> (flags=0, method_list=1)
    td_row0 = (
        le32(0x00000000)
        + le16(str_offsets["<Module>"])
        + le16(0)
        + le16(0)
        + le16(1)
        + le16(1)
    )

    # Row 2: Program (flags=0x00100000 = sealed+notpublic,
    #   method_list=1 => owns methods 1..4)
    td_row1 = (
        le32(0x00100000)
        + le16(str_offsets["Program"])
        + le16(0)
        + le16(0)
        + le16(1)
        + le16(1)
    )

    typedef_data = td_row0 + td_row1

    # MethodDef rows (4 rows):
    # Row format (narrow):
    #   rva: u32, impl_flags: u16, flags: u16,
    #   name: u16, signature: u16, param_list: u16
    #   = 4 + 2 + 2 + 2 + 2 + 2 = 14 bytes

    md_rows = bytearray()
    names = ["Main", "LiveHelper", "DeadMethod1", "DeadMethod2"]
    # flags: Main=public+static+hidebysig (0x0096),
    #        Live=private+static (0x0091),
    #        Dead=private+static (0x0091)
    flags_list = [0x0096, 0x0091, 0x0091, 0x0091]
    for i, name in enumerate(names):
        md_rows += le32(method_rvas[i])
        md_rows += le16(0)          # impl_flags
        md_rows += le16(flags_list[i])
        md_rows += le16(str_offsets[name])
        md_rows += le16(1)          # signature idx in blob
        md_rows += le16(i + 1)      # param_list (1-based)

    return hdr + row_counts + typedef_data + bytes(md_rows)


def build_metadata_root(streams_data):
    """Build metadata root with BSJB signature."""
    version_str = b"v4.0.30319"
    version_padded = align4(version_str + b"\x00")
    ver_len = len(version_padded)

    num_streams = len(streams_data)

    # Rust parser reads stream count at offset+16+round_up_4(len),
    # immediately after the version string (no flags field).
    root_hdr = (
        le32(0x424A5342)
        + le16(1)
        + le16(1)
        + le32(0)
        + le32(ver_len)
        + version_padded
        + le16(num_streams)
    )

    # First pass: compute stream directory size
    dir_entries = bytearray()
    for name, blob in streams_data:
        name_bytes = name.encode("utf-8") + b"\x00"
        name_padded = align4(name_bytes)
        # offset(4) + size(4) + name
        dir_entries += le32(0) + le32(len(blob)) + name_padded

    dir_size = len(dir_entries)
    data_start = len(root_hdr) + dir_size

    # Second pass: fill in offsets
    dir_entries = bytearray()
    cur_data_off = data_start
    for name, blob in streams_data:
        name_bytes = name.encode("utf-8") + b"\x00"
        name_padded = align4(name_bytes)
        dir_entries += (
            le32(cur_data_off)
            + le32(len(blob))
            + name_padded
        )
        cur_data_off += len(align4(blob))

    # Concatenate stream data
    all_data = bytearray()
    for _, blob in streams_data:
        all_data += align4(blob)

    return bytes(root_hdr) + bytes(dir_entries) + bytes(all_data)


def build_cli_header(md_rva, md_size, entry_token):
    """Build 72-byte CLI header (ECMA-335 II.25.3.3)."""
    cli = bytearray(72)
    struct.pack_into("<I", cli, 0, 72)        # cb
    struct.pack_into("<H", cli, 4, 2)         # major
    struct.pack_into("<H", cli, 6, 5)         # minor
    struct.pack_into("<I", cli, 8, md_rva)
    struct.pack_into("<I", cli, 12, md_size)
    struct.pack_into("<I", cli, 16, 0x01)     # ILONLY
    struct.pack_into("<I", cli, 20, entry_token)
    return bytes(cli)


def build_pe():
    """Build complete minimal .NET PE binary."""
    # Layout:
    # 0x0000: DOS header (64 bytes, e_lfanew at 0x3C)
    # 0x0080: PE signature + COFF header + Optional header
    # 0x0200: .text section start (file-aligned to 0x200)
    #   .text contains: IL bodies, CLI header, metadata

    pe_off = 0x80
    sec_file_off = 0x200
    sec_rva = 0x2000
    file_align = 0x200
    sec_align = 0x2000

    # --- Build section content ---
    # IL method bodies first
    body_off_in_sec = 0
    bodies, method_rvas = build_method_bodies(
        sec_rva, body_off_in_sec
    )
    sec_content = bytearray(align4(bodies))

    # CLI header (aligned)
    cli_off_in_sec = len(sec_content)
    cli_rva = sec_rva + cli_off_in_sec

    # Metadata comes after CLI header
    md_off_in_sec = cli_off_in_sec + 72

    # Build strings/blob heaps
    str_heap, str_offsets = build_strings_heap()
    blob_heap = build_blob_heap()

    # Build #~ stream
    tilde = build_table_stream(
        method_rvas, str_offsets, 2
    )

    # Build metadata root
    streams = [
        ("#~", tilde),
        ("#Strings", str_heap),
        ("#Blob", blob_heap),
    ]
    metadata = build_metadata_root(streams)
    md_rva = sec_rva + md_off_in_sec

    # Entry point token: MethodDef row 1 = 0x06000001
    entry_token = 0x06000001
    cli_header = build_cli_header(
        md_rva, len(metadata), entry_token
    )

    sec_content += bytearray(cli_header)
    sec_content += bytearray(metadata)

    # Pad section to file alignment
    sec_raw_size = (
        (len(sec_content) + file_align - 1)
        // file_align
        * file_align
    )
    sec_content += b"\x00" * (sec_raw_size - len(sec_content))
    sec_vsize = len(sec_content)

    # --- DOS header ---
    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    # --- PE signature ---
    pe_sig = b"PE\x00\x00"

    # --- COFF header (20 bytes) ---
    num_sections = 1
    opt_hdr_size = 0xE0  # PE32 optional header
    # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff_chars = 0x0102
    coff = (
        le16(0x014C)       # Machine: i386
        + le16(num_sections)
        + le32(0)          # TimeDateStamp
        + le32(0)          # PointerToSymbolTable
        + le32(0)          # NumberOfSymbols
        + le16(opt_hdr_size)
        + le16(coff_chars)
    )

    # --- PE32 Optional header ---
    # Standard fields (28 bytes)
    image_size = sec_rva + (
        (sec_vsize + sec_align - 1)
        // sec_align
        * sec_align
    )
    opt_std = (
        le16(0x010B)      # Magic: PE32
        + bytes([14, 0])  # Linker version
        + le32(sec_raw_size)  # SizeOfCode
        + le32(0)         # SizeOfInitializedData
        + le32(0)         # SizeOfUninitializedData
        + le32(sec_rva)   # AddressOfEntryPoint
        + le32(sec_rva)   # BaseOfCode
        + le32(0)         # BaseOfData
    )

    # NT-specific fields (68 bytes)
    opt_nt = (
        le32(0x00400000)  # ImageBase
        + le32(sec_align) # SectionAlignment
        + le32(file_align)  # FileAlignment
        + le16(6) + le16(0)  # OS version
        + le16(0) + le16(0)  # Image version
        + le16(6) + le16(0)  # Subsystem version
        + le32(0)            # Win32VersionValue
        + le32(image_size)   # SizeOfImage
        + le32(sec_file_off) # SizeOfHeaders
        + le32(0)            # CheckSum
        + le16(3)            # Subsystem: CONSOLE
        + le16(0x8160)       # DllCharacteristics
        + le32(0x100000)     # SizeOfStackReserve
        + le32(0x1000)       # SizeOfStackCommit
        + le32(0x100000)     # SizeOfHeapReserve
        + le32(0x1000)       # SizeOfHeapCommit
        + le32(0)            # LoaderFlags
        + le32(16)           # NumberOfRvaAndSizes
    )

    # Data directories (16 entries, 8 bytes each = 128)
    dd = bytearray(16 * 8)
    # DataDirectory[14] = COM_DESCRIPTOR
    struct.pack_into("<I", dd, 14 * 8, cli_rva)
    struct.pack_into("<I", dd, 14 * 8 + 4, 72)

    opt = opt_std + opt_nt + bytes(dd)
    assert len(opt) == opt_hdr_size

    # --- Section header (.text) ---
    sec_name = b".text\x00\x00\x00"
    sec_hdr = (
        sec_name
        + le32(sec_vsize)
        + le32(sec_rva)
        + le32(sec_raw_size)
        + le32(sec_file_off)
        + le32(0)         # PointerToRelocations
        + le32(0)         # PointerToLinenumbers
        + le16(0)         # NumberOfRelocations
        + le16(0)         # NumberOfLinenumbers
        + le32(0x60000020)  # Characteristics: CODE|EXECUTE|READ
    )

    # --- Assemble headers ---
    headers = dos + pe_sig + coff + opt + sec_hdr
    # Pad headers to sec_file_off
    if len(headers) > sec_file_off:
        raise ValueError(
            f"headers too large: {len(headers)} > {sec_file_off}"
        )
    headers += b"\x00" * (sec_file_off - len(headers))

    return bytes(headers) + bytes(sec_content)


def main():
    data = build_pe()
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
