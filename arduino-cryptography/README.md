# Arduino Cryptography Library

Comprehensive cryptographic primitives for the Arduino Uno Q (STM32U585 MCU), providing both post-quantum and classical algorithms.

## Features

### Post-Quantum Cryptography
- **ML-KEM 768** (FIPS 203) - Post-quantum key encapsulation mechanism
- **ML-DSA 65** (FIPS 204) - Post-quantum digital signatures
- **X-Wing** (draft-connolly-cfrg-xwing-kem) - Hybrid PQ/classical KEM combining ML-KEM-768 + X25519

### Classical Cryptography
- **X25519** - Elliptic curve Diffie-Hellman key exchange (Curve25519)
- **Ed25519** - Elliptic curve digital signatures (Edwards curve)

### Standards Support
- **COSE_Sign1** (RFC 9052) - CBOR Object Signing and Encryption with ML-DSA

### Infrastructure
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

### X-Wing (Hybrid PQ KEM) Example

```rust
use arduino_cryptography::{xwing, rng::HwRng};

let rng = HwRng::new();

// Generate X-Wing key pair (ML-KEM-768 + X25519)
let seed: [u8; xwing::SEED_SIZE] = rng.random_array();
let keypair = xwing::generate_key_pair(&seed);

// Encapsulate (sender side) - produces hybrid shared secret
let encaps_seed: [u8; xwing::ENCAPS_SEED_SIZE] = rng.random_array();
let (ciphertext, shared_secret_sender) = xwing::encapsulate(&keypair.public_key, &encaps_seed);

// Decapsulate (receiver side)
let shared_secret_receiver = xwing::decapsulate(&keypair.secret_key, &keypair.public_key, &ciphertext);

// shared_secret_sender == shared_secret_receiver (32 bytes)
```

### X25519 Example

```rust
use arduino_cryptography::{x25519, rng::HwRng};

let rng = HwRng::new();

// Alice generates key pair
let alice_secret = x25519::SecretKey::random(&rng);
let alice_public = alice_secret.public_key();

// Bob generates key pair
let bob_secret = x25519::SecretKey::random(&rng);
let bob_public = bob_secret.public_key();

// Both compute the same shared secret
let shared_alice = alice_secret.diffie_hellman(&bob_public);
let shared_bob = bob_secret.diffie_hellman(&alice_public);

// shared_alice == shared_bob (32 bytes)
```

### Ed25519 Example

```rust
use arduino_cryptography::{ed25519, rng::HwRng};

let rng = HwRng::new();

// Generate key pair
let secret_key = ed25519::SecretKey::random(&rng);
let public_key = secret_key.public_key();

// Sign a message
let message = b"Hello, world!";
let signature = secret_key.sign(message);

// Verify signature
assert!(public_key.verify(message, &signature));
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

### Post-Quantum Algorithms

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| ML-KEM 768 | Public Key | 1,184 |
| ML-KEM 768 | Private Key | 2,400 |
| ML-KEM 768 | Ciphertext | 1,088 |
| ML-KEM 768 | Shared Secret | 32 |
| ML-DSA 65 | Verification Key | 1,952 |
| ML-DSA 65 | Signing Key | 4,032 |
| ML-DSA 65 | Signature | 3,309 |

### Hybrid Algorithms

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| X-Wing | Seed | 32 |
| X-Wing | Public Key | 1,216 (1184 ML-KEM + 32 X25519) |
| X-Wing | Secret Key | 32 |
| X-Wing | Ciphertext | 1,120 (1088 ML-KEM + 32 X25519) |
| X-Wing | Shared Secret | 32 |

### Classical Algorithms

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| X25519 | Secret Key | 32 |
| X25519 | Public Key | 32 |
| X25519 | Shared Secret | 32 |
| Ed25519 | Secret Key | 32 |
| Ed25519 | Public Key | 32 |
| Ed25519 | Signature | 64 |

## Performance on STM32U585

### Post-Quantum Operations

| Operation | Time (approx) |
|-----------|---------------|
| ML-KEM Key Generation | ~200ms |
| ML-KEM Encapsulation | ~100ms |
| ML-KEM Decapsulation | ~100ms |
| ML-DSA Key Generation | ~30s |
| ML-DSA Signing | ~30s |
| ML-DSA Verification | ~30s |

### Hybrid Operations

| Operation | Time (approx) |
|-----------|---------------|
| X-Wing Key Generation | ~200ms |
| X-Wing Encapsulation | ~100ms |
| X-Wing Decapsulation | ~100ms |

### Classical Operations

| Operation | Time (approx) |
|-----------|---------------|
| X25519 Key Generation | <1ms |
| X25519 Diffie-Hellman | <1ms |
| Ed25519 Key Generation | <1ms |
| Ed25519 Signing | <1ms |
| Ed25519 Verification | <1ms |

Note: ML-DSA operations are computationally intensive on Cortex-M33. X-Wing adds minimal overhead to ML-KEM since X25519 is extremely fast.

## Cargo Features

Enable specific algorithms via Cargo features:

```toml
[dependencies]
arduino-cryptography = { path = "../../arduino-cryptography", features = ["mlkem", "mldsa", "xwing", "x25519", "ed25519", "cose"] }
```

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `mlkem` | ML-KEM 768 key encapsulation | libcrux-iot-mlkem |
| `mldsa` | ML-DSA 65 digital signatures | libcrux-iot-mldsa |
| `xwing` | X-Wing hybrid KEM | mlkem, x25519, libcrux-iot-sha3 |
| `x25519` | X25519 ECDH | C implementation |
| `ed25519` | Ed25519 signatures | C implementation |
| `cose` | COSE_Sign1 (RFC 9052) | mldsa |

## CMakeLists.txt Setup

For features requiring C code (x25519, ed25519), add to your CMakeLists.txt:

```cmake
# Add X25519 implementation
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/x25519.c)

# Add Ed25519 implementation  
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/ed25519.c)

# Add hardware RNG wrapper
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/hwrng.c)
```

## Dependencies

- [libcrux-iot](https://github.com/cryspen/libcrux-iot) - Formally verified PQ implementations (ML-KEM, ML-DSA, SHA3)
- Zephyr RTOS (for hardware RNG integration)

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) - Module-Lattice-Based Key-Encapsulation Mechanism
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) - Module-Lattice-Based Digital Signature Algorithm
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) - X-Wing Hybrid KEM
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) - Elliptic Curves for Security (X25519)
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) - Edwards-Curve Digital Signature Algorithm (Ed25519)
- [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) - CBOR Object Signing and Encryption (COSE)

## License

Apache-2.0 OR MIT
