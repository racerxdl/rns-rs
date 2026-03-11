/// Common utility functions.

/// Format bytes as a lowercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
