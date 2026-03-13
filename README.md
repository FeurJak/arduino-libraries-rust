# Arduino Libraries Rust

Rust ports of Arduino libraries for the Arduino Uno Q (STM32U585 MCU + QRB2210 Linux MPU) using Zephyr RTOS.

## Architecture

The Arduino Uno Q is a unique board with two processors:

- **STM32U585 MCU**: Cortex-M33 running Zephyr RTOS (programmed with Rust)
- **QRB2210 MPU**: Qualcomm Adreno running Linux

These communicate via **SPI** (primary) or UART (legacy), using MessagePack-RPC protocol.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Arduino Uno Q Board                              │
├────────────────────────────┬────────────────────────────────────────────┤
│     STM32U585 MCU          │           QRB2210 Linux MPU                │
│     (Zephyr RTOS)          │                                            │
│                            │                                            │
│  ┌──────────────────────┐  │  ┌──────────────────────────────────────┐  │
│  │  Rust Application    │  │  │  Linux Applications                  │  │
│  │  (your code)         │  │  │  (weather-display, etc.)             │  │
│  └──────────┬───────────┘  │  └──────────────────┬───────────────────┘  │
│             │              │                     │                      │
│  ┌──────────▼───────────┐  │  ┌──────────────────▼───────────────────┐  │
│  │  arduino-rpc-bridge  │  │  │  arduino-rpc-client                  │  │
│  │  (MCU-side RPC lib)  │  │  │  (Linux-side RPC client library)     │  │
│  └──────────┬───────────┘  │  └──────────────────┬───────────────────┘  │
│             │ SPI          │                     │ Unix Socket          │
│  ┌──────────▼───────────┐  │  ┌──────────────────▼───────────────────┐  │
│  │  SPI Peripheral      │◄─┼──┤  arduino-spi-router                  │  │
│  │  (Zephyr driver)     │  │  │  (SPI controller + Unix socket)      │  │
│  └──────────────────────┘  │  └──────────────────────────────────────┘  │
│                            │                                            │
│  ┌──────────────────────┐  │                                            │
│  │  arduino-led-matrix  │  │                                            │
│  │  (8x13 LED display)  │  │                                            │
│  └──────────────────────┘  │                                            │
└────────────────────────────┴────────────────────────────────────────────┘
```

## Libraries

### arduino-led-matrix (MCU)

Rust port of the `Arduino_LED_Matrix` C library for controlling the 8x13 charlieplexed LED matrix.

**Features:**

- Binary (on/off) and grayscale (8 levels) display modes
- Frame-based rendering with bitmap support
- Animation sequences with configurable timing
- Safe, idiomatic Rust API

### arduino-rpc-bridge (MCU)

MCU-side MessagePack-RPC library for communication with Linux.

**Features:**

- MessagePack encoder/decoder (no_std)
- SPI transport (primary) and UART transport (legacy)
- RPC server to handle requests from Linux
- RPC client to call methods on Linux

### arduino-spi-router (Linux)

Linux-side SPI router daemon that bridges SPI communication to Unix sockets.

**Features:**

- SPI controller communication with MCU
- Unix socket server for local applications
- MessagePack-RPC message forwarding
- Systemd service for auto-start

### arduino-rpc-client (Linux)

Linux-side RPC client library for calling MCU methods.

**Features:**

- Connect to MCU via arduino-spi-router
- Call MCU methods (LED matrix, GPIO, etc.)
- Async and sync APIs

## Examples

### led-matrix-demo (MCU)

Demonstrates the LED matrix library with various patterns and animations.

### spi-test (MCU)

Tests SPI communication between MCU and Linux.

### rpc-server (MCU)

RPC server that exposes LED matrix control via SPI. **Required for weather-display.**

### weather-display (Linux)

Complete application that fetches weather data from Open-Meteo API and displays temperature and weather icons on the LED matrix via RPC.

## Requirements

- Docker (for building MCU firmware)
- ADB (for flashing): `brew install android-platform-tools`
- Arduino Uno Q board connected via USB-C
- Rust toolchain (for Linux applications)
- cargo-zigbuild (for cross-compiling Linux apps): `cargo install cargo-zigbuild`
- sshpass (for SSH deployment): `brew install hudochenkov/sshpass/sshpass`

## Quick Start

### Building MCU Firmware

```bash
# Build the LED matrix demo
make build APP=led-matrix

# Build the RPC server (required for weather-display)
make build APP=rpc-server

# Flash to the board
make flash
```

### Running the Weather Display

The weather-display example demonstrates the full RPC system by fetching real weather data and displaying it on the LED matrix.

**Prerequisites:**

1. Flash the `rpc-server` firmware to the MCU
2. Ensure `arduino-spi-router` is running on Linux (auto-starts via systemd)

**Step-by-step:**

```bash
# 1. Build and flash the RPC server to MCU
make build APP=rpc-server
make flash

# 2. Build the weather-display Linux app
make build-linux APP=weather-display

# 3. Deploy to the board
make deploy-linux APP=weather-display

# 4. Run it (single update)
make run-linux APP=weather-display

# Or run in demo mode (cycles through icons/temps)
make run-linux APP=weather-display ARGS='--demo --once'

# Or run continuously (updates every 5 minutes)
make run-linux APP=weather-display ARGS='--interval 300'
```

**Weather display options:**

```
--lat <LAT>       Latitude (default: 37.7749, San Francisco)
--lon <LON>       Longitude (default: -122.4194)
--interval <SEC>  Update interval in seconds (default: 300)
--once            Run once and exit
--demo            Demo mode (cycle through patterns)
```

### Running Linux Services

```bash
# The SPI router runs as a systemd service (auto-starts on boot)
sudo systemctl status arduino-spi-router

# Or run manually
/home/arduino/spi-router -v --unix-socket /tmp/arduino-spi-router.sock
```

### Using the RPC Client (Linux)

```rust
use arduino_rpc_client::RpcClientSync;

// Connect to MCU via SPI router
let client = RpcClientSync::connect("/tmp/arduino-spi-router.sock")?;

// Call MCU methods
client.call("ping", vec![])?;  // Returns "pong"
client.call("led_matrix.clear", vec![])?;
client.call("led_matrix.set_pixel", vec![
    rmpv::Value::Integer(0.into()),  // row
    rmpv::Value::Integer(5.into()),  // col
    rmpv::Value::Boolean(true),      // on
])?;
```

## Project Structure

```
arduino-libraries-rust/
├── arduino-led-matrix/          # MCU: LED Matrix library
├── arduino-rpc-bridge/          # MCU: RPC library (no_std)
├── arduino-spi-router/          # Linux: SPI router daemon
├── arduino-rpc-client/          # Linux: RPC client library
├── examples/
│   ├── led-matrix-demo/         # MCU: LED matrix demo
│   ├── spi-test/                # MCU: SPI communication test
│   ├── rpc-server/              # MCU: RPC server example
│   └── weather-display/         # Linux: Weather on LED matrix
├── docker/
│   └── Dockerfile               # Build environment
├── Makefile
├── west.yml                     # Zephyr manifest
└── README.md
```

## Communication Protocol

### SPI Frame Format

```
┌────────────────────────────────────────────────────────────────┐
│                    SPI Frame (512 bytes)                       │
├──────────┬──────────┬──────────────────────────────────────────┤
│  Magic   │  Length  │           Payload (MessagePack)          │
│  2 bytes │  2 bytes │              (508 bytes max)             │
├──────────┼──────────┼──────────────────────────────────────────┤
│  0xAA55  │  len     │  [msgpack data...] [padding...]          │
└──────────┴──────────┴──────────────────────────────────────────┘
```

### MessagePack-RPC Messages

**Request**: `[0, msgid, method, params]`

```
Example: [0, 1, "led_matrix.set_pixel", [0, 5, 1]]
```

**Response**: `[1, msgid, error, result]`

```
Example: [1, 1, null, true]
```

**Notification**: `[2, method, params]`

```
Example: [2, "log", ["Hello from MCU"]]
```

## Available MCU RPC Methods

| Method                      | Parameters       | Description           |
| --------------------------- | ---------------- | --------------------- |
| `ping`                      | `[value]`        | Echo back the value   |
| `version`                   | `[]`             | Get firmware version  |
| `led_matrix.begin`          | `[]`             | Initialize LED matrix |
| `led_matrix.clear`          | `[]`             | Turn off all LEDs     |
| `led_matrix.set_pixel`      | `[row, col, on]` | Set single LED        |
| `led_matrix.load_frame`     | `[data]`         | Load 104-bit frame    |
| `led_matrix.set_brightness` | `[level]`        | Set grayscale level   |

## Development

### Opening a Shell in Docker

```bash
make shell
```

### Accessing the Board

```bash
# Via ADB
adb shell

# Via SSH
ssh arduino@<board-ip>
```

### First-Time Setup

```bash
# Push SWD configuration (if flashing fails)
make setup-swd

# Set SPI permissions (persistent)
sudo bash -c 'echo "SUBSYSTEM==\"spidev\", MODE=\"0666\"" > /etc/udev/rules.d/99-spidev.rules'
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## License

Apache-2.0 OR MIT
