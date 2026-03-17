# PQC Demo - Post-Quantum Cryptography for Arduino Uno Q

This example demonstrates post-quantum cryptographic operations running entirely on the Arduino Uno Q's STM32U585 MCU, combining ML-KEM (FIPS 203) for key encapsulation and ML-DSA (FIPS 204) for digital signatures.

## Features

- **ML-KEM 768**: Post-quantum key encapsulation mechanism (NIST Level 3)
- **ML-DSA 65**: Post-quantum digital signatures (NIST Level 3)
- **Self-Contained**: All crypto runs on-device, no binary data transfer needed
- **Visual Feedback**: LED matrix displays operation status in real-time

## Quick Start

```bash
# From the project root:

# 1. Build and flash the PQC demo firmware
make build APP=pqc-demo
make flash APP=pqc-demo

# 2. Build and deploy the Linux client (one-time)
make build-linux APP=pqc-client
make deploy-linux APP=pqc-client

# 3. Run the demo!
make pqc-demo
```

## Available Commands

```bash
# Run ML-KEM 768 demo (recommended - fast, ~2 seconds)
make pqc-demo

# Ping the MCU
make pqc-ping

# Run with custom arguments
make pqc CMD='--mlkem-demo'    # ML-KEM only
make pqc CMD='--mldsa-demo'    # ML-DSA only (slow, >60s)
make pqc CMD='--help'          # Show all options
```

## What the Demo Does

### ML-KEM Demo (`make pqc-demo`)

1. **Key Generation**: Generates ML-KEM 768 key pair (1184 byte public key)
2. **Encapsulation**: Creates ciphertext (1088 bytes) and shared secret (32 bytes)
3. **Decapsulation**: Recovers the shared secret from ciphertext
4. **Verification**: Confirms both shared secrets match

All operations complete in ~2 seconds with LED feedback.

### ML-DSA Demo (slow)

1. **Key Generation**: Generates ML-DSA 65 key pair (1952 byte verification key)
2. **Signing**: Signs a message, producing a 3309 byte signature

Note: ML-DSA operations are computationally intensive and take >60 seconds on the STM32U585.

## LED Matrix Indicators

| Pattern | Meaning |
|---------|---------|
| Key | Generating keys |
| Lock | Encrypting/decrypting |
| Pen | Signing |
| Shield | Verifying |
| Checkmark | Success |
| X | Failure |

## RPC Methods

### Demo Methods (Self-Contained)
- `pqc.run_demo` - Full ML-KEM + ML-DSA demo
- `mlkem.run_demo` - ML-KEM 768 demo only
- `mldsa.run_demo` - ML-DSA 65 demo only

### Core
- `ping` - Returns "pong"
- `version` - Returns firmware version ("pqc-demo 0.2.0")
- `led_matrix.clear` - Clear the LED display

## Algorithm Parameters

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| ML-KEM 768 | Public Key | 1,184 |
| ML-KEM 768 | Private Key | 2,400 |
| ML-KEM 768 | Ciphertext | 1,088 |
| ML-KEM 768 | Shared Secret | 32 |
| ML-DSA 65 | Verification Key | 1,952 |
| ML-DSA 65 | Signing Key | 4,032 |
| ML-DSA 65 | Signature | 3,309 |

## Performance

| Operation | Time (approx) |
|-----------|---------------|
| ML-KEM Key Generation | ~200ms |
| ML-KEM Encapsulation | ~100ms |
| ML-KEM Decapsulation | ~100ms |
| ML-DSA Key Generation | ~30s |
| ML-DSA Signing | ~30s |

## Memory Requirements

- Stack: 48KB (configured in prj.conf)
- Heap: 32KB
- Flash: ~226KB

## Implementation Notes

- Uses [libcrux-iot](https://github.com/cryspen/libcrux-iot) for formally verified PQC implementations
- Simple PRNG used for demo (production should use STM32U585 hardware RNG)
- ML-DSA verification skipped in demo for speed (signing proves the implementation works)

## Troubleshooting

**MCU not responding after ML-DSA demo:**
The ML-DSA operations are slow. If the client times out, the MCU may still be computing. Re-flash to reset:
```bash
make flash APP=pqc-demo
```

**LED matrix not working:**
Ensure you flashed `pqc-demo`, not `rpc-server`. Check with:
```bash
make pqc-ping
# Should show: pqc-demo 0.2.0
```

## License

Apache-2.0 OR MIT
