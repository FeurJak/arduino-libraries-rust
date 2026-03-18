# Arduino Libraries Rust

> ## **DEPRECATED**
> 
> This repository has been replaced by **[DragonWing-rs](https://github.com/FeurJak/DragonWing-rs)**.
> 
> Please use the new repository for all future development. This repository is archived and will no longer receive updates.
> 
> **Migration:** All libraries have been renamed with `dragonwing-` prefix and reorganized for better maintainability. See the [DragonWing-rs README](https://github.com/FeurJak/DragonWing-rs#readme) for documentation.

---

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

### arduino-cryptography (MCU)

Comprehensive cryptography library for the MCU, providing post-quantum, classical, anonymous credential, and secure storage cryptographic primitives.

**Features:**

- **ML-KEM 768** (FIPS 203) - Post-quantum key encapsulation
- **ML-DSA 65** (FIPS 204) - Post-quantum digital signatures
- **X-Wing** (draft-connolly-cfrg-xwing-kem) - Hybrid PQ/classical KEM combining ML-KEM-768 + X25519
- **SAGA** - BBS-style MAC for anonymous credentials with unlinkable presentations
- **SAGA + X-Wing** - Credential-protected post-quantum key exchange
- **PSA Secure Storage** - Encrypted persistent storage via Zephyr Secure Storage
  - **PSA ITS** (Internal Trusted Storage) - Store arbitrary encrypted data
  - **PSA Crypto Key Management** - Generate, import, export, and manage cryptographic keys
- **XChaCha20-Poly1305** - Authenticated encryption with 24-byte nonces (via mbedTLS)
- **X25519** - Classical elliptic curve Diffie-Hellman key exchange
- **Ed25519** - Classical elliptic curve digital signatures
- **COSE_Sign1** (RFC 9052) - CBOR Object Signing with ML-DSA
- **Hardware RNG** - True Random Number Generator integration via Zephyr
- Formally verified PQ implementations via [libcrux-iot](https://github.com/cryspen/libcrux-iot)
- no_std compatible

## Examples

### led-matrix-demo (MCU)

Demonstrates the LED matrix library with various patterns and animations.

### spi-test (MCU)

Tests SPI communication between MCU and Linux.

### rpc-server (MCU)

RPC server that exposes LED matrix control via SPI. **Required for weather-display.**

### weather-display (Linux)

Complete application that fetches weather data from Open-Meteo API and displays temperature and weather icons on the LED matrix via RPC.

### mlkem-demo (MCU) + mlkem-client (Linux)

Post-quantum key exchange demonstration using ML-KEM 768 between MCU and Linux.

### pqc-demo (MCU) + pqc-client (Linux)

Complete cryptography demonstration showcasing post-quantum, classical, anonymous credential, and secure storage algorithms:

- **PSA Secure Storage** - Encrypted persistent storage + key management (~2 seconds)
- **ML-KEM 768** - Post-quantum key encapsulation (~2 seconds)
- **ML-DSA 65** - Post-quantum digital signatures (~60+ seconds)
- **X-Wing** - Hybrid PQ KEM combining ML-KEM-768 + X25519 (~2 seconds)
- **SAGA** - Anonymous credentials with unlinkable presentations (~5 seconds)
- **SAGA + X-Wing** - Credential-protected PQ key exchange (~4 seconds)
- **XChaCha20-Poly1305** - Authenticated encryption with 24-byte nonces (~1 second)
- **X25519** - Classical ECDH key exchange (~1 second)
- **Ed25519** - Classical digital signatures (~1 second)
- **COSE_Sign1** - RFC 9052 signing with ML-DSA (~90 seconds)

All demos run entirely on the MCU with LED matrix visual feedback.

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

### Running the PQC Demo

The PQC demo demonstrates cryptography running entirely on the MCU with LED matrix visual feedback, including post-quantum algorithms, anonymous credentials, and secure storage.

**Prerequisites:**

1. Flash the `pqc-demo` firmware to the MCU
2. Deploy the `pqc-client` to the Linux side
3. Ensure `arduino-spi-router` is running on Linux

**Step-by-step:**

```bash
# 1. Build and flash the PQC demo firmware to MCU
make build APP=pqc-demo
make flash

# 2. Build and deploy the pqc-client Linux app
make build-linux APP=pqc-client
make deploy-linux APP=pqc-client

# 3. Run demos using make targets

# List all available demos
make demo-list

# Run PSA Secure Storage demo (fast, ~2 seconds)
make demo DEMO=psa

# Run ML-KEM demo (fast, ~2 seconds)
make demo DEMO=mlkem

# Run X-Wing hybrid PQ KEM demo (fast, ~2 seconds)
make demo DEMO=xwing

# Run SAGA anonymous credentials demo (~5 seconds)
make demo DEMO=saga

# Run SAGA + X-Wing credential key exchange (~4 seconds)
make demo DEMO=saga-xwing

# Run Ed25519 signature demo (fast, ~1 second)
make demo DEMO=ed25519

# Run X25519 ECDH demo (fast, ~1 second)
make demo DEMO=x25519

# Run XChaCha20-Poly1305 AEAD demo (fast, ~1 second)
make demo DEMO=xchacha20

# Run ML-DSA demo (slow, >60 seconds)
make demo DEMO=mldsa

# To see detailed output, open serial console in another terminal
make serial
```

**LED Matrix Indicators:**

| Pattern | Meaning |
|---------|---------|
| Key | Generating keys |
| Lock | Encrypting/decrypting |
| Pen | Signing |
| Shield | Verifying |
| Checkmark | Success |
| X | Failure |

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
├── arduino-cryptography/        # MCU: Post-quantum crypto (ML-KEM + ML-DSA)
├── arduino-spi-router/          # Linux: SPI router daemon
├── arduino-rpc-client/          # Linux: RPC client library
├── examples/
│   ├── led-matrix-demo/         # MCU: LED matrix demo
│   ├── spi-test/                # MCU: SPI communication test
│   ├── rpc-server/              # MCU: RPC server example
│   ├── mlkem-demo/              # MCU: ML-KEM crypto demo
│   ├── pqc-demo/                # MCU: Full PQC demo (ML-KEM + ML-DSA)
│   ├── weather-display/         # Linux: Weather on LED matrix
│   ├── mlkem-client/            # Linux: ML-KEM client
│   └── pqc-client/              # Linux: PQC demo client
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
