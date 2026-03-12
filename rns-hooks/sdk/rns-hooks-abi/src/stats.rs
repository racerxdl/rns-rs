pub const PACKET_STATS_PAYLOAD_TYPE: &str = "stats.packet.v1";
pub const PACKET_STATS_ENCODED_LEN: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketStatsPayload {
    pub flags: u8,
    pub packet_len: u32,
    pub interface_id: u64,
}

impl PacketStatsPayload {
    pub fn encode(&self) -> [u8; PACKET_STATS_ENCODED_LEN] {
        let mut buf = [0u8; PACKET_STATS_ENCODED_LEN];
        buf[0] = self.flags;
        buf[1..5].copy_from_slice(&self.packet_len.to_le_bytes());
        buf[5..13].copy_from_slice(&self.interface_id.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PACKET_STATS_ENCODED_LEN {
            return None;
        }
        let mut packet_len = [0u8; 4];
        packet_len.copy_from_slice(&bytes[1..5]);
        let mut interface_id = [0u8; 8];
        interface_id.copy_from_slice(&bytes[5..13]);
        Some(Self {
            flags: bytes[0],
            packet_len: u32::from_le_bytes(packet_len),
            interface_id: u64::from_le_bytes(interface_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_stats_roundtrip() {
        let payload = PacketStatsPayload {
            flags: 0x23,
            packet_len: 1024,
            interface_id: 42,
        };
        let encoded = payload.encode();
        assert_eq!(PacketStatsPayload::decode(&encoded), Some(payload));
    }
}
