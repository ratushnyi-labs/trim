/// Check if a byte is AArch64 padding (zero = UDF).
pub fn is_padding_aarch64(b: u8) -> bool {
    b == 0x00
}
