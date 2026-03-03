/// Common utility functions.

/// Format bytes as a lowercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format bytes as hex, truncated to first N characters for display.
pub fn hex_truncated(bytes: &[u8], max_chars: usize) -> String {
    let full = hex(bytes);
    if full.len() > max_chars {
        full[..max_chars].to_string()
    } else {
        full
    }
}
