//! RNode-compatible KISS protocol handler for ESP32.
//!
//! Implements the device side of the RNode protocol: responds to DETECT
//! handshake, accepts radio configuration commands, and bridges data frames
//! between USB serial and the SX1262 LoRa radio.

use std::time::{Duration, Instant};

use esp_idf_hal::uart::UartDriver;

use crate::display::SharedStats;
use crate::lora::SharedRadio;

// KISS framing constants
const FEND: u8 = 0xC0;
const FESC: u8 = 0xDB;
const TFEND: u8 = 0xDC;
const TFESC: u8 = 0xDD;

// RNode command bytes (subset matching rns-net/src/rnode_kiss.rs)
const CMD_DATA: u8 = 0x00;
const CMD_FREQUENCY: u8 = 0x01;
const CMD_BANDWIDTH: u8 = 0x02;
const CMD_TXPOWER: u8 = 0x03;
const CMD_SF: u8 = 0x04;
const CMD_CR: u8 = 0x05;
const CMD_RADIO_STATE: u8 = 0x06;
const CMD_DETECT: u8 = 0x08;
const CMD_LEAVE: u8 = 0x0A;
const CMD_ST_ALOCK: u8 = 0x0B;
const CMD_LT_ALOCK: u8 = 0x0C;
const CMD_READY: u8 = 0x0F;
const CMD_PLATFORM: u8 = 0x48;
const CMD_MCU: u8 = 0x49;
const CMD_FW_VERSION: u8 = 0x50;

const DETECT_REQ: u8 = 0x73;
const DETECT_RESP: u8 = 0x46;
const RADIO_STATE_ON: u8 = 0x01;

// Device identity
const PLATFORM_ESP32: u8 = 0x80;
const MCU_ESP32: u8 = 0x01;
const FW_VERSION_MAJOR: u8 = 0x01;
const FW_VERSION_MINOR: u8 = 0x01;

const DETECT_POLL_MS: u32 = 5;
const FREQ_MIN_HZ: u32 = 137_000_000;
const FREQ_MAX_HZ: u32 = 1_020_000_000;
const TX_POWER_MIN_DBM: i8 = 0;
const TX_POWER_MAX_DBM: i8 = 22;

/// Idle timeout before reverting to standalone mode.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason the bridge loop exited.
pub enum BridgeExit {
    IdleTimeout,
    Leave,
}

/// KISS frame decoded from serial input.
struct KissFrame {
    command: u8,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RadioConfig {
    frequency: u32,
    bandwidth: u32,
    spreading_factor: u8,
    coding_rate: u8,
    tx_power: i8,
}

/// Streaming KISS decoder for serial input.
struct KissDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    buffer: Vec<u8>,
}

impl KissDecoder {
    fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            command: 0xFF,
            buffer: Vec::new(),
        }
    }

    /// Feed bytes and return any complete frames.
    fn feed(&mut self, bytes: &[u8]) -> Vec<KissFrame> {
        let mut frames = Vec::new();

        for &byte in bytes {
            if byte == FEND {
                if self.in_frame && self.command != 0xFF && !self.buffer.is_empty() {
                    frames.push(KissFrame {
                        command: self.command,
                        data: core::mem::take(&mut self.buffer),
                    });
                } else if self.in_frame && self.command != 0xFF && self.command != CMD_DATA {
                    // Command with no payload (e.g. radio state query)
                    frames.push(KissFrame {
                        command: self.command,
                        data: Vec::new(),
                    });
                }
                self.in_frame = true;
                self.command = 0xFF;
                self.buffer.clear();
                self.escape = false;
            } else if self.in_frame {
                if self.command == 0xFF {
                    self.command = byte;
                } else if byte == FESC {
                    self.escape = true;
                } else if self.escape {
                    match byte {
                        TFEND => self.buffer.push(FEND),
                        TFESC => self.buffer.push(FESC),
                        _ => self.buffer.push(byte),
                    }
                    self.escape = false;
                } else {
                    self.buffer.push(byte);
                }
            }
        }

        frames
    }
}

/// KISS-encode a command frame: FEND + cmd + escaped(data) + FEND.
fn kiss_encode(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(FEND);
    out.push(cmd);
    for &b in data {
        match b {
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            _ => out.push(b),
        }
    }
    out.push(FEND);
    out
}

/// RNode bridge: handles serial protocol and bridges data to/from LoRa.
pub struct RNodeBridge<'a, 'b> {
    radio: SharedRadio,
    uart: &'b UartDriver<'a>,
    stats: Option<SharedStats>,
    pending_freq: Option<u32>,
    pending_bw: Option<u32>,
    pending_sf: Option<u8>,
    pending_cr: Option<u8>,
    pending_power: Option<i8>,
}

impl<'a, 'b> RNodeBridge<'a, 'b> {
    pub fn new(radio: SharedRadio, uart: &'b UartDriver<'a>, stats: Option<SharedStats>) -> Self {
        Self {
            radio,
            uart,
            stats,
            pending_freq: None,
            pending_bw: None,
            pending_sf: None,
            pending_cr: None,
            pending_power: None,
        }
    }

    /// Run the RNode bridge loop. Blocks until serial goes idle or host sends LEAVE.
    pub fn run(&mut self) -> BridgeExit {
        log::info!("RNode bridge mode active");

        let mut decoder = KissDecoder::new();
        let mut rx_buf = [0u8; 512];
        let mut last_activity = Instant::now();

        loop {
            // Check idle timeout
            if last_activity.elapsed() > IDLE_TIMEOUT {
                log::info!("RNode bridge: idle timeout, reverting to standalone");
                return BridgeExit::IdleTimeout;
            }

            // Poll serial RX (non-blocking with short timeout)
            match self.uart.read(&mut rx_buf, 10) {
                Ok(n) if n > 0 => {
                    last_activity = Instant::now();
                    let frames = decoder.feed(&rx_buf[..n]);
                    for frame in frames {
                        if self.handle_frame(frame) {
                            return BridgeExit::Leave;
                        }
                    }
                }
                _ => {}
            }

            // Poll LoRa RX
            let received = {
                let mut radio = self.radio.lock().unwrap();
                radio.try_receive()
            };
            if let Some(data) = received {
                log::info!("RNode: LoRa RX {} bytes, forwarding to serial", data.len());
                if let Some(ref stats) = self.stats {
                    stats.lock().unwrap().bridge_rx_bytes += data.len() as u32;
                }
                let frame = kiss_encode(CMD_DATA, &data);
                let _ = self.uart.write(&frame);
            }

            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Handle a decoded KISS frame from serial. Returns true if bridge should exit.
    fn handle_frame(&mut self, frame: KissFrame) -> bool {
        match frame.command {
            CMD_DETECT => {
                if frame.data.first() == Some(&DETECT_REQ) {
                    log::info!("RNode: DETECT handshake received");
                    let resp = kiss_encode(CMD_DETECT, &[DETECT_RESP]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_LEAVE => {
                log::info!("RNode: LEAVE received, exiting bridge mode");
                return true;
            }
            CMD_FW_VERSION => {
                let resp = kiss_encode(CMD_FW_VERSION, &[FW_VERSION_MAJOR, FW_VERSION_MINOR]);
                let _ = self.uart.write(&resp);
            }
            CMD_PLATFORM => {
                let resp = kiss_encode(CMD_PLATFORM, &[PLATFORM_ESP32]);
                let _ = self.uart.write(&resp);
            }
            CMD_MCU => {
                let resp = kiss_encode(CMD_MCU, &[MCU_ESP32]);
                let _ = self.uart.write(&resp);
            }
            CMD_FREQUENCY => {
                if frame.data.len() >= 4 {
                    let freq = (frame.data[0] as u32) << 24
                        | (frame.data[1] as u32) << 16
                        | (frame.data[2] as u32) << 8
                        | frame.data[3] as u32;
                    log::info!("RNode: set frequency {}Hz", freq);
                    self.pending_freq = Some(freq);
                    let resp = kiss_encode(CMD_FREQUENCY, &frame.data[..4]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_BANDWIDTH => {
                if frame.data.len() >= 4 {
                    let bw = (frame.data[0] as u32) << 24
                        | (frame.data[1] as u32) << 16
                        | (frame.data[2] as u32) << 8
                        | frame.data[3] as u32;
                    log::info!("RNode: set bandwidth {}Hz", bw);
                    self.pending_bw = Some(bw);
                    let resp = kiss_encode(CMD_BANDWIDTH, &frame.data[..4]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_TXPOWER => {
                if !frame.data.is_empty() {
                    let power = frame.data[0] as i8;
                    log::info!("RNode: set TX power {}dBm", power);
                    self.pending_power = Some(power);
                    let resp = kiss_encode(CMD_TXPOWER, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_SF => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set SF {}", frame.data[0]);
                    self.pending_sf = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_SF, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_CR => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set CR 4/{}", frame.data[0]);
                    self.pending_cr = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_CR, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_ST_ALOCK => {
                if frame.data.len() >= 2 {
                    log::info!(
                        "RNode: set ST airtime lock {}",
                        ((frame.data[0] as u16) << 8 | frame.data[1] as u16) as f32 / 100.0
                    );
                    let resp = kiss_encode(CMD_ST_ALOCK, &frame.data[..2]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_LT_ALOCK => {
                if frame.data.len() >= 2 {
                    log::info!(
                        "RNode: set LT airtime lock {}",
                        ((frame.data[0] as u16) << 8 | frame.data[1] as u16) as f32 / 100.0
                    );
                    let resp = kiss_encode(CMD_LT_ALOCK, &frame.data[..2]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_RADIO_STATE => {
                if frame.data.first() == Some(&RADIO_STATE_ON) {
                    if self.apply_radio_config() {
                        let resp = kiss_encode(CMD_RADIO_STATE, &[RADIO_STATE_ON]);
                        let _ = self.uart.write(&resp);
                        let ready = kiss_encode(CMD_READY, &[0x01]);
                        let _ = self.uart.write(&ready);
                    }
                }
            }
            CMD_DATA => {
                if !frame.data.is_empty() {
                    log::info!("RNode: TX {} bytes over LoRa", frame.data.len());
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().bridge_tx_bytes += frame.data.len() as u32;
                    }
                    let result = {
                        let mut radio = self.radio.lock().unwrap();
                        let r = radio.transmit(&frame.data);
                        radio.set_rx_continuous();
                        r
                    };
                    match result {
                        Ok(()) => {
                            let resp = kiss_encode(CMD_READY, &[0x01]);
                            let _ = self.uart.write(&resp);
                        }
                        Err(e) => {
                            log::error!("RNode: LoRa TX failed: {}", e);
                        }
                    }
                }
            }
            _ => {
                log::debug!("RNode: ignoring command 0x{:02X}", frame.command);
            }
        }
        false
    }

    /// Apply pending radio configuration to the SX1262.
    fn apply_radio_config(&mut self) -> bool {
        let config = RadioConfig {
            frequency: self.pending_freq.unwrap_or(crate::config::LORA_FREQUENCY),
            bandwidth: self.pending_bw.unwrap_or(crate::config::LORA_BANDWIDTH),
            spreading_factor: self
                .pending_sf
                .unwrap_or(crate::config::LORA_SPREADING_FACTOR),
            coding_rate: self.pending_cr.unwrap_or(crate::config::LORA_CODING_RATE),
            tx_power: self.pending_power.unwrap_or(crate::config::LORA_TX_POWER),
        };

        if let Err(err) = validate_radio_config(config) {
            log::warn!("RNode: rejecting invalid radio config: {}", err);
            if let Some(ref stats) = self.stats {
                stats.lock().unwrap().set_status("Invalid radio cfg");
            }
            return false;
        }

        let mut radio = self.radio.lock().unwrap();
        radio.reconfigure(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );

        if let Some(ref stats) = self.stats {
            let mut s = stats.lock().unwrap();
            s.bridge_freq = Some(config.frequency);
            s.bridge_bw = Some(config.bandwidth);
            s.bridge_sf = Some(config.spreading_factor);
            s.bridge_cr = Some(config.coding_rate);
            s.bridge_power = Some(config.tx_power);
        }

        log::info!("RNode: radio config applied");
        true
    }
}

fn validate_radio_config(config: RadioConfig) -> Result<(), &'static str> {
    if !(FREQ_MIN_HZ..=FREQ_MAX_HZ).contains(&config.frequency) {
        return Err("frequency out of supported range");
    }

    match config.bandwidth {
        7_800 | 10_400 | 15_600 | 20_800 | 31_250 | 41_700 | 62_500 | 125_000 | 250_000
        | 500_000 => {}
        _ => return Err("unsupported bandwidth"),
    }

    if !(5..=12).contains(&config.spreading_factor) {
        return Err("spreading factor out of range");
    }

    if !(5..=8).contains(&config.coding_rate) {
        return Err("coding rate out of range");
    }

    if !(TX_POWER_MIN_DBM..=TX_POWER_MAX_DBM).contains(&config.tx_power) {
        return Err("TX power out of range");
    }

    Ok(())
}

/// Check UART for RNode DETECT handshake with a short polling timeout.
/// Called from the driver's idle path after `recv_timeout` expires.
/// Returns `true` if DETECT was received and responded to.
pub fn wait_for_detect_quick(uart: &UartDriver<'_>) -> bool {
    let mut decoder = KissDecoder::new();
    let mut rx_buf = [0u8; 256];

    match uart.read(&mut rx_buf, DETECT_POLL_MS) {
        Ok(n) if n > 0 => {
            let frames = decoder.feed(&rx_buf[..n]);
            let mut detected = false;

            for frame in &frames {
                if frame.command == CMD_DETECT && frame.data.first() == Some(&DETECT_REQ) {
                    detected = true;
                }
            }

            if detected {
                for frame in frames {
                    match frame.command {
                        CMD_DETECT => {
                            if frame.data.first() == Some(&DETECT_REQ) {
                                log::info!("RNode: DETECT handshake received (quick), responding");
                                let resp = kiss_encode(CMD_DETECT, &[DETECT_RESP]);
                                let _ = uart.write(&resp);
                            }
                        }
                        CMD_FW_VERSION => {
                            let resp =
                                kiss_encode(CMD_FW_VERSION, &[FW_VERSION_MAJOR, FW_VERSION_MINOR]);
                            let _ = uart.write(&resp);
                        }
                        CMD_PLATFORM => {
                            let resp = kiss_encode(CMD_PLATFORM, &[PLATFORM_ESP32]);
                            let _ = uart.write(&resp);
                        }
                        CMD_MCU => {
                            let resp = kiss_encode(CMD_MCU, &[MCU_ESP32]);
                            let _ = uart.write(&resp);
                        }
                        _ => {}
                    }
                }
                return true;
            }
        }
        _ => {}
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{validate_radio_config, RadioConfig};

    #[test]
    fn accepts_default_config() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: crate::config::LORA_BANDWIDTH,
            spreading_factor: crate::config::LORA_SPREADING_FACTOR,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_ok());
    }

    #[test]
    fn rejects_invalid_spreading_factor() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: crate::config::LORA_BANDWIDTH,
            spreading_factor: 13,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_err());
    }

    #[test]
    fn rejects_invalid_bandwidth() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: 123_456,
            spreading_factor: crate::config::LORA_SPREADING_FACTOR,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_err());
    }
}

/// Restore the radio to default standalone configuration from config.rs.
pub fn restore_default_radio_config(radio: &SharedRadio) {
    let mut r = radio.lock().unwrap();
    r.reconfigure(
        crate::config::LORA_FREQUENCY,
        crate::config::LORA_BANDWIDTH,
        crate::config::LORA_SPREADING_FACTOR,
        crate::config::LORA_CODING_RATE,
        crate::config::LORA_TX_POWER,
    );
    log::info!("Radio restored to default config");
}
