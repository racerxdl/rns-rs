# rns-esp32

Reticulum LoRa transport node firmware for **Heltec WiFi LoRa 32 (V3)** with SX1262 radio.

## Hardware

- **Board**: Heltec WiFi LoRa 32 (V3) - ESP32-S3 based
- **Radio**: SX1262 LoRa module (built-in)
- **Display**: SSD1306 128x64 OLED (built-in)
- **Frequency**: 868 MHz (EU band, configurable)

## Features

- LoRa packet transport for Reticulum network
- OLED display with multiple info pages (cycled via long-press PRG button)
- Identity persistence via NVS (Non-Volatile Storage)
- IFAC (Interface Access Code) support for authenticated networks
- Button gestures:
  - **Short press**: Send ping broadcast
  - **Double press**: Trigger Reticulum announce
  - **Long press (>800ms)**: Cycle display page

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

## Display Pages

1. **Stats**: Identity hash (short), TX/RX byte counters, announce count
2. **Radio Info**: Frequency, SF, bandwidth, coding rate, TX power
3. **Identity**: Full 32-byte identity hash

## Architecture

```
main.rs         - Hardware init, thread spawning
├── lora.rs     - SX1262 SPI driver (TX/RX)
├── display.rs  - SSD1306 OLED rendering
├── button.rs   - GPIO0 button with gesture detection
├── driver.rs   - Event loop, TransportEngine integration
├── ifac.rs     - Interface Access Code crypto
├── rng.rs      - Hardware RNG wrapper
└── config.rs   - Pin assignments, LoRa params
```

## License

Same as parent project.
