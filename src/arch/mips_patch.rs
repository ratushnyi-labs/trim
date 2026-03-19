/// Check if a byte is MIPS padding (0x00 = NOP).
pub fn is_padding_mips(b: u8) -> bool {
    b == 0x00
}
