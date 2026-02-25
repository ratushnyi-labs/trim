/// Check if a byte is ARM32 padding (zero = UDF).
pub fn is_padding_arm32(b: u8) -> bool {
    b == 0x00
}
