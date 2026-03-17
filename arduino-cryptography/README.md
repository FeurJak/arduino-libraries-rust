# Arduino Cryptography Library

Post-quantum cryptographic primitives for the Arduino Uno Q (STM32U585 MCU).

## Features

- **ML-KEM 768** (FIPS 203) - Post-quantum key encapsulation mechanism
- **ML-DSA 65** (FIPS 204) - Post-quantum digital signatures  
- **Hardware RNG** - True Random Number Generator integration via Zephyr

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
arduino-cryptography = { path = "../../arduino-cryptography" }
```

### ML-KEM Example

```rust
use arduino_cryptography::{kem, rng::HwRng};

let rng = HwRng::new();

// Generate key pair
let keygen_seed: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();
let keypair = kem::generate_key_pair(keygen_seed);

// Encapsulate (sender side)
let encaps_seed: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();
let (ciphertext, shared_secret_sender) = kem::encapsulate(keypair.public_key(), encaps_seed);

// Decapsulate (receiver side)
let shared_secret_receiver = kem::decapsulate(keypair.private_key(), &ciphertext);

// shared_secret_sender == shared_secret_receiver
```

### ML-DSA Example

```rust
use arduino_cryptography::{dsa, rng::HwRng};

let rng = HwRng::new();

// Generate key pair
let keygen_seed: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();
let keypair = dsa::generate_key_pair(keygen_seed);

// Sign a message
let message = b"Hello, quantum-safe world!";
let context = b"my-app-v1";
let sign_seed: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();
let signature = dsa::sign(&keypair.signing_key, message, context, sign_seed)?;

// Verify signature
dsa::verify(&keypair.verification_key, message, context, &signature)?;
```

## Hardware RNG Setup

The `HwRng` module requires some setup in your Zephyr project:

### 1. Kconfig (prj.conf)

```
CONFIG_ENTROPY_GENERATOR=y
CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR=y
```

### 2. Device Tree (optional)

If RNG isn't already enabled in your board's base DTS:

```dts
&rng {
    status = "okay";
};
```

### 3. CMakeLists.txt

Add the C wrapper to your build:

```cmake
# Add the hardware RNG wrapper for Rust FFI
target_sources(app PRIVATE arduino-cryptography/c/hwrng.c)
```

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

## Performance on STM32U585

| Operation | Time (approx) |
|-----------|---------------|
| ML-KEM Key Generation | ~200ms |
| ML-KEM Encapsulation | ~100ms |
| ML-KEM Decapsulation | ~100ms |
| ML-DSA Key Generation | ~30s |
| ML-DSA Signing | ~30s |

Note: ML-DSA operations are computationally intensive on Cortex-M33.

## Dependencies

- [libcrux-iot](https://github.com/cryspen/libcrux-iot) - Formally verified cryptographic implementations
- Zephyr RTOS (for hardware RNG integration)

## License

Apache-2.0 OR MIT
