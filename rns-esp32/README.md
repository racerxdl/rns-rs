# rns-esp32

Reticulum LoRa transport node firmware for **Heltec WiFi LoRa 32 (V3)** with SX1262 radio.

## Hardware

- **Board**: Heltec WiFi LoRa 32 (V3) - ESP32-S3 based
- **Radio**: SX1262 LoRa module (built-in)
- **Display**: SSD1306 128x64 OLED (built-in)
- **Frequency**: 868 MHz (EU band, configurable)

## Features

- **Dual mode operation**:
  - **Standalone**: Runs a full Reticulum transport node over LoRa
  - **RNode Bridge**: Acts as a KISS interface over USB serial for a PC running `rns-net`
- LoRa packet transport for Reticulum network
- OLED display with multiple info pages (cycled via short-press PRG button)
- Identity persistence via NVS (Non-Volatile Storage)
- IFAC cryptographic helpers are implemented, but runtime IFAC configuration is not wired up yet
- Button gestures:
  - **Short press**: Cycle display page
  - **Double press**: Send ping broadcast
  - **Long press (>800ms)**: Trigger Reticulum announce

## RNode Bridge Mode

When a PC connects via USB serial and sends an RNode DETECT handshake, the device automatically switches from standalone mode to bridge mode. In bridge mode it:

- Responds to the RNode KISS protocol (DETECT, FW_VERSION, PLATFORM, MCU)
- Accepts radio configuration commands (frequency, bandwidth, SF, CR, TX power)
- Bridges KISS data frames between USB serial and the SX1262 LoRa radio
- Reverts to standalone mode after 30 seconds without host serial activity

Use the `rnode_lora` example from `rns-net` to connect from a PC:

```bash
RUST_LOG=info cargo run --example rnode_lora -- /dev/ttyUSB0
```

## Prerequisites

1. Install Rust with ESP target support:
   ```bash
   cargo install espup
   espup install
   . $HOME/export-esp.sh
   ```

2. Install `espflash` for flashing:
   ```bash
   cargo install espflash
   ```

3. Connect your Heltec V3 via USB.

## Building

```bash
cd rns-esp32
cargo build --release
```

## Flashing

```bash
cargo run --release
```

Or manually:
```bash
espflash flash --monitor target/xtensa-esp32s3-espidf/release/rns-esp32
```

## Configuration

Edit `src/config.rs` to modify LoRa parameters:
- Frequency
- Bandwidth
- Spreading factor
- TX power
- Coding rate

The board pinout and partition table are also part of the firmware configuration.

## Display Pages

1. **Stats**: Identity hash (short), TX/RX byte counters, announce count
2. **Radio Info**: Frequency, SF, bandwidth, coding rate, TX power
3. **Identity**: Full 32-byte identity hash

## Architecture

```
main.rs         - Hardware init, thread spawning, mode switching
├── lora.rs     - SX1262 SPI driver (TX/RX), radio reconfiguration
├── rnode.rs    - RNode KISS protocol handler, USB bridge mode
├── display.rs  - SSD1306 OLED rendering
├── button.rs   - GPIO0 button with gesture detection
├── driver.rs   - Event loop, TransportEngine integration
├── ifac.rs     - Interface Access Code crypto
├── rng.rs      - Hardware RNG wrapper
└── config.rs   - Pin assignments, LoRa params
```

## License

Same as parent project.
