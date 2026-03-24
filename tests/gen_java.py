#!/usr/bin/env python3
"""Generate a minimal Java .class file with dead methods for testing."""
import struct
import sys


def u1(v):
    return struct.pack(">B", v)


def u2(v):
    return struct.pack(">H", v)


def u4(v):
    return struct.pack(">I", v)


def utf8_entry(s):
    b = s.encode("utf-8")
    return u1(1) + u2(len(b)) + b


def class_entry(name_idx):
    return u1(7) + u2(name_idx)


def methodref_entry(class_idx, nat_idx):
    return u1(10) + u2(class_idx) + u2(nat_idx)


def nat_entry(name_idx, desc_idx):
    return u1(12) + u2(name_idx) + u2(desc_idx)


def code_attr(code_idx, max_stack, max_locals, bytecode,
              exc_table=b"", sub_attrs=b"", sub_attr_count=0):
    """Build a Code attribute."""
    code_len = len(bytecode)
    exc_count = len(exc_table) // 8
    body = u2(max_stack) + u2(max_locals) + u4(code_len)
    body += bytecode
    body += u2(exc_count) + exc_table
    body += u2(sub_attr_count) + sub_attrs
    return u2(code_idx) + u4(len(body)) + body


def method_info(access_flags, name_idx, desc_idx, code_idx,
                max_stack, max_locals, bytecode,
                exc_table=b"", sub_attrs=b"", sub_attr_count=0):
    """Build a method_info structure."""
    attr = code_attr(code_idx, max_stack, max_locals, bytecode,
                     exc_table, sub_attrs, sub_attr_count)
    return u2(access_flags) + u2(name_idx) + u2(desc_idx) + u2(1) + attr


def main():
    # Constant pool entries (1-based):
    # 1: Utf8 "TestClass"
    # 2: Utf8 "java/lang/Object"
    # 3: Class #1
    # 4: Class #2
    # 5: Utf8 "main"
    # 6: Utf8 "([Ljava/lang/String;)V"
    # 7: Utf8 "Code"
    # 8: Utf8 "liveHelper"
    # 9: Utf8 "()V"
    # 10: Utf8 "deadMethod1"
    # 11: Utf8 "deadMethod2"
    # 12: NameAndType #8:#9
    # 13: Methodref #3.#12
    # 14: Utf8 "()I"
    # 15: Utf8 "<init>"
    # 16: NameAndType #15:#9
    # 17: Methodref #4.#16  (Object.<init>)

    pool = b""
    pool += utf8_entry("TestClass")        # 1
    pool += utf8_entry("java/lang/Object")  # 2
    pool += class_entry(1)                  # 3
    pool += class_entry(2)                  # 4
    pool += utf8_entry("main")             # 5
    pool += utf8_entry("([Ljava/lang/String;)V")  # 6
    pool += utf8_entry("Code")             # 7
    pool += utf8_entry("liveHelper")       # 8
    pool += utf8_entry("()V")             # 9
    pool += utf8_entry("deadMethod1")      # 10
    pool += utf8_entry("deadMethod2")      # 11
    pool += nat_entry(8, 9)                # 12: liveHelper:()V
    pool += methodref_entry(3, 12)         # 13: TestClass.liveHelper
    pool += utf8_entry("()I")             # 14
    pool += utf8_entry("<init>")           # 15
    pool += nat_entry(15, 9)               # 16: <init>:()V
    pool += methodref_entry(4, 16)         # 17: Object.<init>
    pool += utf8_entry("liveBranch")      # 18
    pool += utf8_entry("deadWithExc")     # 19
    pool += utf8_entry("deadWithSwitch")  # 20
    pool += utf8_entry("StackMapTable")   # 21
    pool += utf8_entry("liveWithSMT")     # 22

    cp_count = 23  # 22 entries + 1 (0-based offset)

    # Methods
    ACC_PUBLIC = 0x0001
    ACC_STATIC = 0x0008
    ACC_PRIVATE = 0x0002

    # <init>: public, calls super.<init>(), return
    init_code = (
        b"\x2A"                 # aload_0
        + b"\xB7\x00\x11"      # invokespecial #17 (Object.<init>)
        + b"\xB1"               # return
    )
    m_init = method_info(ACC_PUBLIC, 15, 9, 7, 1, 1, init_code)

    # main: public static, calls liveHelper, return
    main_code = (
        b"\xB8\x00\x0D"        # invokestatic #13 (liveHelper)
        + b"\xB1"               # return
    )
    m_main = method_info(ACC_PUBLIC | ACC_STATIC, 5, 6, 7, 0, 1, main_code)

    # liveHelper: public static, return
    live_code = b"\xB1"         # return
    m_live = method_info(ACC_PUBLIC | ACC_STATIC, 8, 9, 7, 0, 0, live_code)

    # deadMethod1: private static, ~30 bytes of code
    dead1_code = (
        b"\x03"                 # iconst_0
        + b"\x3C"               # istore_1
        + b"\x04"               # iconst_1
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x68"               # imul
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x68"               # imul
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\xAC"               # ireturn
    )
    m_dead1 = method_info(ACC_PRIVATE | ACC_STATIC, 10, 14, 7, 2, 3, dead1_code)

    # deadMethod2: private static, ~25 bytes of code
    dead2_code = (
        b"\x10\x0A"            # bipush 10
        + b"\x3C"               # istore_1
        + b"\x10\x14"          # bipush 20
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x68"               # imul
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x64"               # isub
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x6C"               # idiv
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\xAC"               # ireturn
    )
    m_dead2 = method_info(ACC_PRIVATE | ACC_STATIC, 11, 14, 7, 2, 3, dead2_code)

    # liveBranch: public static int liveBranch()
    # Has dead code after ireturn (10 bytes unreachable)
    branch_code = (
        b"\x03"                 # iconst_0
        + b"\x3C"               # istore_1
        + b"\x04"               # iconst_1
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\xAC"               # ireturn
        # Dead code below (10 bytes, unreachable):
        + b"\x10\x0A"          # bipush 10
        + b"\x3C"               # istore_1
        + b"\x10\x14"          # bipush 20
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\x1C"               # iload_2
        + b"\x60"               # iadd
        + b"\xAC"               # ireturn
    )
    m_branch = method_info(ACC_PUBLIC | ACC_STATIC, 18, 14, 7,
                           2, 3, branch_code)

    # deadWithExc: private static, has exception handler table
    # Exercises: if m.exception_table_len > 0 { return None; }
    exc_code = (
        b"\x03"                 # iconst_0
        + b"\x3C"               # istore_1
        + b"\x1B"               # iload_1
        + b"\xAC"               # ireturn
    )
    # Exception table: start_pc(2) + end_pc(2) + handler_pc(2) + catch_type(2)
    exc_table = u2(0) + u2(2) + u2(2) + u2(0)  # catch all in [0,2) -> 2
    m_dead_exc = method_info(ACC_PRIVATE | ACC_STATIC, 19, 14, 7,
                             1, 2, exc_code, exc_table=exc_table)

    # deadWithSwitch: private static, has tableswitch opcode
    # Exercises: if has_switch(data, code_off, code_len) { return None; }
    # tableswitch: opcode(1) + pad(0) + default(4) + low(4) + high(4) + offset(4)
    switch_code = (
        b"\x1B"                 # iload_1
        # tableswitch at PC 1, pad to align to 4-byte boundary: (4-(1+1)%4)%4 = 2
        + b"\xAA"               # tableswitch
        + b"\x00\x00"           # 2 bytes padding
        + b"\x00\x00\x00\x0E"  # default: +14 (-> PC 15)
        + b"\x00\x00\x00\x00"  # low: 0
        + b"\x00\x00\x00\x00"  # high: 0
        + b"\x00\x00\x00\x0E"  # offset[0]: +14 (-> PC 15)
        + b"\xAC"               # ireturn (at PC 15)
    )
    m_dead_switch = method_info(ACC_PRIVATE | ACC_STATIC, 20, 14, 7,
                                1, 2, switch_code)

    # liveWithSMT: public static int liveWithSMT()
    # Live method with dead branch AND a StackMapTable attribute.
    # Exercises: if has_stack_map(...) { return None; }
    smt_code = (
        b"\x03"                 # iconst_0
        + b"\xAC"               # ireturn
        # Dead code (8 bytes unreachable):
        + b"\x10\x0A"          # bipush 10
        + b"\x3C"               # istore_1
        + b"\x10\x14"          # bipush 20
        + b"\x3D"               # istore_2
        + b"\x1B"               # iload_1
        + b"\xAC"               # ireturn
    )
    # StackMapTable attribute: name_idx(2) + length(4) + number_of_entries(2)
    smt_attr = u2(21) + u4(2) + u2(0)  # empty StackMapTable
    m_live_smt = method_info(ACC_PUBLIC | ACC_STATIC, 22, 14, 7,
                             1, 3, smt_code,
                             sub_attrs=smt_attr, sub_attr_count=1)

    methods = (m_init + m_main + m_live + m_branch
               + m_live_smt + m_dead1 + m_dead2
               + m_dead_exc + m_dead_switch)
    methods_count = 9

    # Assemble class file
    out = b""
    out += u4(0xCAFEBABE)       # magic
    out += u2(0)                 # minor_version
    out += u2(52)                # major_version (Java 8)
    out += u2(cp_count)
    out += pool
    out += u2(0x0021)            # access_flags: ACC_PUBLIC | ACC_SUPER
    out += u2(3)                 # this_class: #3
    out += u2(4)                 # super_class: #4
    out += u2(0)                 # interfaces_count
    out += u2(0)                 # fields_count
    out += u2(methods_count)
    out += methods
    out += u2(0)                 # class attributes_count

    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()
