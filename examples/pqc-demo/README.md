# PQC Demo - Post-Quantum Cryptography for Arduino Uno Q

This example demonstrates post-quantum cryptographic operations on the Arduino Uno Q,
combining ML-KEM (FIPS 203) for key encapsulation and ML-DSA (FIPS 204) for digital
signatures.

## Features

- **ML-KEM 768**: Post-quantum key encapsulation mechanism (NIST Level 3)
- **ML-DSA 65**: Post-quantum digital signatures (NIST Level 3)
- **Hybrid Protocol**: Derive signature keys from shared secrets
- **Visual Feedback**: LED matrix displays operation status

## Protocol Flow

```
Linux MPU                              STM32U585 MCU
    |                                       |
    |  1. Request ML-KEM public key         |
    |-------------------------------------->|
    |<--------------------------------------| (1184 bytes)
    |                                       |
    |  2. Encapsulate shared secret         |
    |  (locally, using public key)          |
    |                                       |
    |  3. Send ciphertext to MCU            |
    |-------------------------------------->| (1088 bytes)
    |                                       | Decapsulate -> shared secret
    |                                       | Derive ML-DSA keys
    |                                       | Sign message
    |                                       |
    |  4. Get verification key              |
    |<--------------------------------------| (1952 bytes)
    |                                       |
    |  5. Get signature                     |
    |<--------------------------------------| (3309 bytes)
    |                                       |
    |  6. Verify signature locally          |
    |                                       |
```

## RPC Methods

### Core
- `ping()` - Returns "pong"
- `version()` - Returns firmware version

### ML-KEM
- `mlkem.generate_keypair()` - Generate new ML-KEM 768 key pair
- `mlkem.get_public_key()` - Get public key (1184 bytes)
- `mlkem.decapsulate(ciphertext)` - Decapsulate to get shared secret
- `mlkem.get_shared_secret()` - Get the derived shared secret (32 bytes)

### ML-DSA
- `mldsa.generate_from_secret()` - Generate ML-DSA keys from shared secret
- `mldsa.get_verification_key()` - Get verification key (1952 bytes)
- `mldsa.sign(message)` - Sign a message
- `mldsa.get_signature()` - Get the last signature (3309 bytes)

### Combined
- `pqc.full_demo(ciphertext, message)` - Complete demo sequence

## Size Parameters

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| ML-KEM 768 | Public Key | 1,184 |
| ML-KEM 768 | Private Key | 2,400 |
| ML-KEM 768 | Ciphertext | 1,088 |
| ML-KEM 768 | Shared Secret | 32 |
| ML-DSA 65 | Verification Key | 1,952 |
| ML-DSA 65 | Signing Key | 4,032 |
| ML-DSA 65 | Signature | 3,309 |

## Building

```bash
# From the project root
make build APP=pqc-demo

# Flash to board
make flash APP=pqc-demo
```

## LED Matrix Indicators

| Pattern | Meaning |
|---------|---------|
| Key | Generating keys |
| Lock | Encrypting/decrypting |
| Pen | Signing |
| Checkmark | Success |
| X | Failure |

## Memory Requirements

- Stack: 48KB (for ML-DSA operations)
- Heap: 32KB (for temporary allocations)

## Security Notes

- This demo uses a simple PRNG for key generation. In production, use the STM32U585's hardware RNG.
- The shared secret derivation for ML-DSA is simplified. Production systems should use a proper KDF like HKDF.
- Empty context is used for ML-DSA signing. Production systems may want domain separation.
