# Arduino Cryptography Library

Comprehensive cryptographic primitives for the Arduino Uno Q (STM32U585 MCU), providing post-quantum, classical, anonymous credential, and secure storage algorithms.

## Features

### Post-Quantum Cryptography

- **ML-KEM 768** (FIPS 203) - Post-quantum key encapsulation mechanism
- **ML-DSA 65** (FIPS 204) - Post-quantum digital signatures
- **X-Wing** (draft-connolly-cfrg-xwing-kem) - Hybrid PQ/classical KEM combining ML-KEM-768 + X25519

### Anonymous Credentials

- **SAGA** - BBS-style MAC scheme for anonymous credentials with unlinkable presentations
- **SAGA + X-Wing** - Credential-protected post-quantum key exchange combining anonymous authentication with hybrid PQ key encapsulation

### Secure Storage (PSA Certified API)

- **PSA ITS** (Internal Trusted Storage) - Store arbitrary encrypted data persistently
- **PSA Crypto Key Management** - Generate, import, export, and manage cryptographic keys
- Data encrypted at rest using AEAD with device-unique key
- Persistent storage that survives device reboots

### Classical Cryptography

- **X25519** - Elliptic curve Diffie-Hellman key exchange (Curve25519)
- **Ed25519** - Elliptic curve digital signatures (Edwards curve)
- **XChaCha20-Poly1305** - Authenticated encryption with 24-byte nonces (via mbedTLS)

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

### XChaCha20-Poly1305 Example

```rust
use arduino_cryptography::{xchacha20poly1305::{Key, Nonce, encrypt, decrypt}, rng::HwRng};

let rng = HwRng::new();

// Generate a random key (do this once, store securely)
let key_bytes: [u8; 32] = rng.random_array();
let key = Key::from_bytes(&key_bytes);

// Generate a random nonce (must be unique per message)
let nonce_bytes: [u8; 24] = rng.random_array();
let nonce = Nonce::from_bytes(&nonce_bytes);

// Encrypt a message
let plaintext = b"Secret message";
let aad = b"additional authenticated data";
let (ciphertext, tag) = encrypt(&key, &nonce, plaintext, aad).unwrap();

// Decrypt the message
let decrypted = decrypt(&key, &nonce, &ciphertext, &tag, aad).unwrap();
assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

### SAGA Anonymous Credentials Example

```rust
use arduino_cryptography::{saga, rng::HwRng};
use saga::Identity; // For Point::identity()

let mut rng = HwRng::new();

// Issuer: Setup parameters and key pair
let keypair = saga::KeyPair::setup(&mut rng, 3)?; // 3 attributes
let params = keypair.params();
let pk = keypair.pk();

// Create credential attributes (as curve points)
let mut messages = [saga::Point::identity(); saga::MAX_ATTRS];
for i in 0..3 {
    let scalar = saga::Scalar::from((i + 1) as u64);
    messages[i] = saga::smul(&params.g, &scalar);
}

// Issuer: Issue credential (MAC)
let credential = keypair.mac(&mut rng, &messages[..3])?;

// Holder: Verify credential with public key
assert!(credential.verify(params, pk, &messages[..3]));

// Holder: Create unlinkable presentation
let predicate = credential.get_predicate(&mut rng, params, pk, &messages[..3])?;
let presentation = predicate.presentation();
let commitments = predicate.commitments();

// Verifier: Verify presentation (with secret key)
let valid = keypair.verify_presentation(&presentation, commitments)?;
assert!(valid);

// Multiple presentations from the same credential are UNLINKABLE
let predicate2 = credential.get_predicate(&mut rng, params, pk, &messages[..3])?;
// predicate2.presentation() will look completely different from presentation
```

### SAGA + X-Wing Hybrid Key Exchange Example

```rust
use arduino_cryptography::{saga, saga_xwing, rng::HwRng};
use saga::Identity;

let mut rng = HwRng::new();

// === Setup Phase ===
// Issuer creates SAGA parameters and issues credential to device
let saga_keypair = saga::KeyPair::setup(&mut rng, 2)?;
let saga_params = saga_keypair.params();
let saga_pk = saga_keypair.pk();

// Create device credential
let mut messages = [saga::Point::identity(); saga::MAX_ATTRS];
messages[0] = saga::smul(&saga_params.g, &saga::Scalar::from(100u64));
messages[1] = saga::smul(&saga_params.g, &saga::Scalar::from(200u64));
let credential = saga_keypair.mac(&mut rng, &messages[..2])?;

// === Key Exchange Phase ===

// Device: Initiate (creates X-Wing keypair + SAGA presentation)
let (request, device_state) = saga_xwing::CredentialKeyExchange::initiate(
    &mut rng,
    saga_params,
    saga_pk,
    &credential,
    &messages[..2],
)?;

// Server: Verify presentation + encapsulate shared secret
let payload = b"Access granted!";
let (response, server_keys) = saga_xwing::CredentialKeyExchange::respond(
    &mut rng,
    &saga_keypair,
    &request,
    Some(payload),
)?;

// Device: Complete (decapsulate + decrypt payload)
let (device_keys, decrypted) = saga_xwing::CredentialKeyExchange::complete(
    &device_state,
    &response,
)?;

// Both parties now have matching session keys!
assert_eq!(server_keys.shared_secret.as_bytes(), device_keys.shared_secret.as_bytes());
```

### PSA Secure Storage Example

```rust
use arduino_cryptography::psa::{self, its, crypto};
use arduino_cryptography::psa::{StorageUid, StorageFlags, KeyAttributes, KeyType, Algorithm, KeyUsageFlags};

// Initialize PSA Crypto (required once at startup)
crypto::init()?;

// === Internal Trusted Storage (ITS) ===
// Store arbitrary encrypted data that persists across reboots

let uid: StorageUid = 0x0000_1000;  // Application-defined UID
let secret_data = b"my-secret-credential-key";

// Store data (encrypted at rest)
its::set(uid, secret_data, StorageFlags::NONE)?;

// Retrieve data
let mut buffer = [0u8; 64];
let len = its::get(uid, 0, &mut buffer)?;
assert_eq!(&buffer[..len], secret_data);

// Check if entry exists
if its::exists(uid) {
    let info = its::get_info(uid)?;
    println!("Entry size: {} bytes", info.size);
}

// Remove entry
its::remove(uid)?;

// === PSA Crypto Key Management ===
// Generate and manage cryptographic keys

let key_id: psa::KeyId = 0x0001_0001;  // Application-defined key ID

// Generate a persistent AES-256 key
let attrs = KeyAttributes::new()
    .with_type(KeyType::Aes)
    .with_bits(256)
    .with_algorithm(Algorithm::AesGcm)
    .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT | KeyUsageFlags::EXPORT)
    .persistent(key_id);

let generated_id = crypto::generate_key(&attrs)?;

// Export key material (if permitted)
let mut key_buffer = [0u8; 32];
let key_len = crypto::export_key(generated_id, &mut key_buffer)?;

// Get key attributes
let read_attrs = crypto::get_key_attributes(generated_id)?;
println!("Key bits: {}, lifetime: {:?}", read_attrs.bits, read_attrs.lifetime);

// Destroy key when done
crypto::destroy_key(generated_id)?;

// Convenience function for common case
let key_id = crypto::generate_aes256_key(0x0001_0002)?;
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

| Algorithm  | Component        | Size (bytes) |
| ---------- | ---------------- | ------------ |
| ML-KEM 768 | Public Key       | 1,184        |
| ML-KEM 768 | Private Key      | 2,400        |
| ML-KEM 768 | Ciphertext       | 1,088        |
| ML-KEM 768 | Shared Secret    | 32           |
| ML-DSA 65  | Verification Key | 1,952        |
| ML-DSA 65  | Signing Key      | 4,032        |
| ML-DSA 65  | Signature        | 3,309        |

### Hybrid Algorithms

| Algorithm | Component     | Size (bytes)                    |
| --------- | ------------- | ------------------------------- |
| X-Wing    | Seed          | 32                              |
| X-Wing    | Public Key    | 1,216 (1184 ML-KEM + 32 X25519) |
| X-Wing    | Secret Key    | 32                              |
| X-Wing    | Ciphertext    | 1,120 (1088 ML-KEM + 32 X25519) |
| X-Wing    | Shared Secret | 32                              |

### Anonymous Credentials (SAGA)

| Algorithm | Component          | Size (bytes)           |
| --------- | ------------------ | ---------------------- |
| SAGA      | Scalar             | 32                     |
| SAGA      | Point (compressed) | 32                     |
| SAGA      | Parameters         | ~320 (g + generators)  |
| SAGA      | Public Key         | ~288 (X0 + generators) |
| SAGA      | Tag (credential)   | ~160 (A, e, proof)     |
| SAGA      | Presentation       | ~96 (C_A, T, response) |

### Classical Algorithms

| Algorithm          | Component     | Size (bytes) |
| ------------------ | ------------- | ------------ |
| X25519             | Secret Key    | 32           |
| X25519             | Public Key    | 32           |
| X25519             | Shared Secret | 32           |
| Ed25519            | Secret Key    | 32           |
| Ed25519            | Public Key    | 32           |
| Ed25519            | Signature     | 64           |
| XChaCha20-Poly1305 | Key           | 32           |
| XChaCha20-Poly1305 | Nonce         | 24           |
| XChaCha20-Poly1305 | Tag           | 16           |

## Performance on STM32U585

### Post-Quantum Operations

| Operation             | Time (approx) |
| --------------------- | ------------- |
| ML-KEM Key Generation | ~200ms        |
| ML-KEM Encapsulation  | ~100ms        |
| ML-KEM Decapsulation  | ~100ms        |
| ML-DSA Key Generation | ~30s          |
| ML-DSA Signing        | ~30s          |
| ML-DSA Verification   | ~30s          |

### Hybrid Operations

| Operation             | Time (approx) |
| --------------------- | ------------- |
| X-Wing Key Generation | ~200ms        |
| X-Wing Encapsulation  | ~100ms        |
| X-Wing Decapsulation  | ~100ms        |

### Anonymous Credential Operations

| Operation                   | Time (approx) |
| --------------------------- | ------------- |
| SAGA Setup (3 attrs)        | ~500ms        |
| SAGA MAC (issue credential) | ~200ms        |
| SAGA Create Presentation    | ~300ms        |
| SAGA Verify Presentation    | ~200ms        |
| SAGA + X-Wing Full Protocol | ~4s           |

### Classical Operations

| Operation                  | Time (approx) |
| -------------------------- | ------------- |
| X25519 Key Generation      | <1ms          |
| X25519 Diffie-Hellman      | <1ms          |
| Ed25519 Key Generation     | <1ms          |
| Ed25519 Signing            | <1ms          |
| Ed25519 Verification       | <1ms          |
| XChaCha20-Poly1305 Encrypt | <1ms (per KB) |
| XChaCha20-Poly1305 Decrypt | <1ms (per KB) |

Note: ML-DSA operations are computationally intensive on Cortex-M33. X-Wing adds minimal overhead to ML-KEM since X25519 is extremely fast.

## Cargo Features

Enable specific algorithms via Cargo features:

```toml
[dependencies]
arduino-cryptography = { path = "../../arduino-cryptography", features = ["mlkem", "mldsa", "xwing", "x25519", "ed25519", "cose"] }
```

| Feature             | Description                   | Dependencies                      |
| ------------------- | ----------------------------- | --------------------------------- |
| `mlkem`             | ML-KEM 768 key encapsulation  | libcrux-iot-mlkem                 |
| `mldsa`             | ML-DSA 65 digital signatures  | libcrux-iot-mldsa                 |
| `xwing`             | X-Wing hybrid KEM             | mlkem, x25519, libcrux-iot-sha3   |
| `x25519`            | X25519 ECDH                   | C implementation                  |
| `ed25519`           | Ed25519 signatures            | C implementation (mbedTLS SHA512) |
| `xchacha20poly1305` | XChaCha20-Poly1305 AEAD       | mbedTLS, rng                      |
| `saga`              | SAGA anonymous credentials    | curve25519-dalek, sha2, rng       |
| `saga_xwing`        | SAGA + X-Wing hybrid protocol | saga, xwing, xchacha20poly1305    |
| `psa`               | PSA Secure Storage + Crypto   | Zephyr Secure Storage, mbedTLS    |
| `cose`              | COSE_Sign1 (RFC 9052)         | mldsa                             |
| `rng`               | Hardware RNG support          | Zephyr entropy API                |

## CMakeLists.txt Setup

For features requiring C code, add to your CMakeLists.txt:

```cmake
# Add X25519 implementation
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/x25519.c)

# Add Ed25519 implementation
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/ed25519.c)

# Add XChaCha20-Poly1305 implementation (requires mbedTLS)
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/xchacha20poly1305.c)

# Add PSA Secure Storage wrapper (requires Zephyr Secure Storage)
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/psa_wrapper.c)

# Add hardware RNG wrapper
target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/../../arduino-cryptography/c/hwrng.c)
```

## prj.conf Setup

For XChaCha20-Poly1305 and Ed25519, enable mbedTLS in your prj.conf:

```
CONFIG_MBEDTLS=y
CONFIG_MBEDTLS_BUILTIN=y
CONFIG_MBEDTLS_CIPHER_CHACHA20_ENABLED=y
CONFIG_MBEDTLS_POLY1305=y
CONFIG_MBEDTLS_CHACHAPOLY_AEAD_ENABLED=y
CONFIG_MBEDTLS_HASH_ALL_ENABLED=y
CONFIG_MBEDTLS_ENABLE_HEAP=y
CONFIG_MBEDTLS_HEAP_SIZE=8192
```

For PSA Secure Storage, add these additional settings:

```
# PSA Crypto API
CONFIG_MBEDTLS_PSA_CRYPTO_C=y

# Zephyr Secure Storage subsystem
CONFIG_SECURE_STORAGE=y
CONFIG_SECURE_STORAGE_ITS_IMPLEMENTATION_ZEPHYR=y
CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS=y
CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_AEAD=y
CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=512

# Storage backends
CONFIG_SETTINGS=y
CONFIG_SETTINGS_NVS=y
CONFIG_NVS=y
CONFIG_FLASH=y
CONFIG_FLASH_MAP=y
```

And add an ITS partition to your board overlay (`.overlay` file):

```dts
&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        its_partition: partition@e0000 {
            label = "its_storage";
            reg = <0x000e0000 DT_SIZE_K(64)>;
        };
    };
};
```

## Dependencies

- [libcrux-iot](https://github.com/cryspen/libcrux-iot) - Formally verified PQ implementations (ML-KEM, ML-DSA, SHA3)
- Zephyr RTOS (for hardware RNG integration)

## References

- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) - Module-Lattice-Based Key-Encapsulation Mechanism
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) - Module-Lattice-Based Digital Signature Algorithm
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) - X-Wing Hybrid KEM
- [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) - XChaCha20 and XChaCha20-Poly1305
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) - Elliptic Curves for Security (X25519)
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) - Edwards-Curve Digital Signature Algorithm (Ed25519)
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) - ChaCha20 and Poly1305 for IETF Protocols
- [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) - CBOR Object Signing and Encryption (COSE)
- [SAGA Paper](https://eprint.iacr.org/2025/2156.pdf) - Multi-Verifier Keyed-Verification
  Anonymous Credentials

## License

Apache-2.0 OR MIT
