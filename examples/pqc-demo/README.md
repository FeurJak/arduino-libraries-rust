# PQC Demo - Cryptography Showcase for Arduino Uno Q

This example demonstrates comprehensive cryptographic operations running entirely on the Arduino Uno Q's STM32U585 MCU, including post-quantum algorithms (ML-KEM, ML-DSA, X-Wing) and classical algorithms (X25519, Ed25519).

## Features

### Post-Quantum Cryptography
- **ML-KEM 768** (FIPS 203): Post-quantum key encapsulation mechanism (NIST Level 3)
- **ML-DSA 65** (FIPS 204): Post-quantum digital signatures (NIST Level 3)
- **X-Wing**: Hybrid PQ/classical KEM combining ML-KEM-768 + X25519

### Classical Cryptography
- **X25519**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Elliptic curve digital signatures

### Standards
- **COSE_Sign1** (RFC 9052): CBOR Object Signing with ML-DSA

### Infrastructure
- **Hardware TRNG**: Uses STM32U585's True Random Number Generator
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
# Ping the MCU
make pqc-ping

# Fast demos (< 3 seconds)
make pqc CMD='--mlkem-demo'      # ML-KEM 768 key encapsulation
make pqc CMD='--xwing-demo'      # X-Wing hybrid PQ KEM (ML-KEM + X25519)
make pqc CMD='--x25519-demo'     # X25519 ECDH key exchange
make pqc CMD='--ed25519-demo'    # Ed25519 digital signatures

# Slow demos (60+ seconds)
make pqc CMD='--mldsa-demo'      # ML-DSA 65 signatures
make pqc CMD='--cose-demo'       # COSE_Sign1 with ML-DSA

# Show all options
make pqc CMD='--help'
```

## What the Demos Do

### ML-KEM Demo (~2 seconds)

1. **Key Generation**: Generates ML-KEM 768 key pair (1184 byte public key)
2. **Encapsulation**: Creates ciphertext (1088 bytes) and shared secret (32 bytes)
3. **Decapsulation**: Recovers the shared secret from ciphertext
4. **Verification**: Confirms both shared secrets match

### X-Wing Demo (~2 seconds)

1. **Key Generation**: Generates hybrid key pair (ML-KEM-768 + X25519, 1216 byte public key)
2. **Encapsulation**: Creates hybrid ciphertext (1120 bytes) and combined shared secret
3. **Decapsulation**: Recovers the shared secret using both ML-KEM and X25519
4. **Verification**: Confirms shared secrets match

X-Wing provides IND-CCA2 security if either ML-KEM or X25519 remains secure - hedging against quantum and classical attacks.

### X25519 Demo (~1 second)

1. **Key Generation**: Generates two X25519 key pairs (Alice & Bob)
2. **Key Exchange**: Both parties compute ECDH shared secret
3. **Verification**: Confirms both derived the same 32-byte shared secret

### Ed25519 Demo (~1 second)

1. **Key Generation**: Generates Ed25519 key pair (32 byte public key)
2. **Signing**: Signs a test message, producing a 64 byte signature
3. **Verification**: Verifies the signature against the public key

### ML-DSA Demo (~60+ seconds)

1. **Key Generation**: Generates ML-DSA 65 key pair (1952 byte verification key)
2. **Signing**: Signs a message, producing a 3309 byte signature

Note: ML-DSA operations are computationally intensive on Cortex-M33.

### COSE_Sign1 Demo (~90 seconds)

1. **Key Generation**: Generates ML-DSA 65 key pair
2. **COSE Signing**: Creates RFC 9052 compliant COSE_Sign1 structure with ML-DSA signature
3. **COSE Verification**: Verifies the COSE_Sign1 message and extracts payload

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
- `xwing.run_demo` - X-Wing hybrid KEM demo
- `x25519.run_demo` - X25519 ECDH demo
- `ed25519.run_demo` - Ed25519 signature demo
- `cose.run_demo` - COSE_Sign1 with ML-DSA demo

### Core
- `ping` - Returns "pong"
- `version` - Returns firmware version ("crypto-demo 0.6.0")
- `led_matrix.clear` - Clear the LED display

## Algorithm Parameters

### Post-Quantum

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| ML-KEM 768 | Public Key | 1,184 |
| ML-KEM 768 | Private Key | 2,400 |
| ML-KEM 768 | Ciphertext | 1,088 |
| ML-KEM 768 | Shared Secret | 32 |
| ML-DSA 65 | Verification Key | 1,952 |
| ML-DSA 65 | Signing Key | 4,032 |
| ML-DSA 65 | Signature | 3,309 |

### Hybrid

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| X-Wing | Public Key | 1,216 |
| X-Wing | Secret Key | 32 |
| X-Wing | Ciphertext | 1,120 |
| X-Wing | Shared Secret | 32 |

### Classical

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| X25519 | Secret Key | 32 |
| X25519 | Public Key | 32 |
| X25519 | Shared Secret | 32 |
| Ed25519 | Secret Key | 32 |
| Ed25519 | Public Key | 32 |
| Ed25519 | Signature | 64 |

## Performance

### Fast Operations (< 1 second)

| Operation | Time (approx) |
|-----------|---------------|
| ML-KEM Key Generation | ~200ms |
| ML-KEM Encapsulation | ~100ms |
| ML-KEM Decapsulation | ~100ms |
| X-Wing Key Generation | ~200ms |
| X-Wing Encapsulation | ~100ms |
| X-Wing Decapsulation | ~100ms |
| X25519 Key Generation | <1ms |
| X25519 Diffie-Hellman | <1ms |
| Ed25519 Key Generation | <1ms |
| Ed25519 Sign/Verify | <1ms |

### Slow Operations (> 30 seconds)

| Operation | Time (approx) |
|-----------|---------------|
| ML-DSA Key Generation | ~30s |
| ML-DSA Signing | ~30s |
| ML-DSA Verification | ~30s |

## Memory Requirements

- Stack: 48KB (configured in prj.conf)
- Heap: 32KB
- Flash: ~248KB (with all crypto algorithms enabled)

## Implementation Notes

- Uses [libcrux-iot](https://github.com/cryspen/libcrux-iot) for formally verified PQC implementations (ML-KEM, ML-DSA, SHA3)
- X-Wing follows [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) specification
- X25519 uses a standalone Montgomery ladder implementation
- Ed25519 uses a standalone implementation with SHA-512
- **Hardware TRNG**: Uses STM32U585's True Random Number Generator via Zephyr's entropy API
- ML-DSA verification skipped in some demos for speed (signing proves the implementation works)

## Hardware RNG Integration

The demo uses the STM32U585's hardware True Random Number Generator (TRNG) for all cryptographic operations via the `arduino_cryptography::rng::HwRng` module:

- **Key Generation**: ML-KEM requires 64 bytes of randomness, ML-DSA requires 32 bytes
- **Encapsulation**: ML-KEM encapsulation requires 32 bytes of randomness  
- **Signing**: ML-DSA signing requires 32 bytes of randomness

### Setup Requirements

1. **Kconfig** (`prj.conf`):
   ```
   CONFIG_ENTROPY_GENERATOR=y
   CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR=y
   ```

2. **CMakeLists.txt** - Include the C wrapper:
   ```cmake
   target_sources(app PRIVATE arduino-cryptography/c/hwrng.c)
   ```

3. **Rust code** - Import and use:
   ```rust
   use arduino_cryptography::{kem, rng::HwRng};
   
   let rng = HwRng::new();
   let seed: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();
   let keypair = kem::generate_key_pair(seed);
   ```

See `arduino-cryptography/README.md` for full documentation.

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
# Should show: crypto-demo 0.6.0
```

## pqc-client Options

The Linux client (`pqc-client`) supports these commands:

```
pqc-client --ping               Test connection to MCU
pqc-client --mcu-demo           Run full PQC demo (ML-KEM + ML-DSA)
pqc-client --mlkem-demo         Run ML-KEM 768 demo
pqc-client --mldsa-demo         Run ML-DSA 65 demo (slow!)
pqc-client --xwing-demo         Run X-Wing hybrid PQ KEM demo
pqc-client --x25519-demo        Run X25519 ECDH demo
pqc-client --ed25519-demo       Run Ed25519 signature demo
pqc-client --cose-demo          Run COSE_Sign1 demo
pqc-client --demo               Run local simulation demo
pqc-client --help               Show all options
```

## License

Apache-2.0 OR MIT
