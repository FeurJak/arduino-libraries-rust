# Post-Quantum Cryptography on a Microcontroller: Running ML-KEM 768 in Rust on the Arduino Uno Q

## TL;DR

I successfully ported ML-KEM 768 (FIPS 203) to run on an STM32U585 microcontroller using Rust and Zephyr RTOS. The complete key exchange (keygen + encapsulation + decapsulation + verification) runs in under 2 seconds on a 160 MHz Cortex-M33. This proves that quantum-resistant cryptography is practical for embedded systems today.

---

## The Challenge

With quantum computers advancing rapidly, the cryptographic algorithms protecting our devices will eventually become vulnerable. NIST finalized ML-KEM (formerly Kyber) as the standard for post-quantum key encapsulation in August 2024. But can resource-constrained embedded devices actually run these algorithms?

I set out to answer this question using:
- **Arduino Uno Q**: A unique board with an STM32U585 MCU (Cortex-M33 @ 160 MHz, 768 KB RAM)
- **Rust**: For memory safety without garbage collection
- **libcrux-iot**: Cryspen's formally verified PQC implementation
- **Zephyr RTOS**: Real-time operating system with Rust support

## The Implementation

### Architecture

The Arduino Uno Q has a dual-processor architecture:
- **STM32U585 MCU**: Runs Zephyr RTOS with Rust firmware (handles cryptography)
- **QRB2210 MPU**: Runs Linux (orchestrates demos, provides connectivity)

They communicate via SPI using MessagePack-RPC, allowing the Linux side to trigger cryptographic operations on the MCU.

### What I Built

1. **arduino-cryptography**: A `no_std` Rust library wrapping libcrux-iot's ML-KEM 768 implementation
2. **pqc-demo**: MCU firmware that runs complete PQC demos with LED matrix visual feedback
3. **pqc-client**: Linux application to trigger and monitor the demos

### The Demo in Action

```bash
$ make pqc-demo

Running ML-KEM 768 demo on MCU...
Watch the LED matrix for status indicators!

Connected! MCU responded: "pong"
MCU firmware: "pqc-demo 0.2.0"

Running ML-KEM 768 demo on MCU...
ML-KEM demo completed: true
```

The MCU performs:
1. **Key Generation**: Creates a 1184-byte public key and 2400-byte private key
2. **Encapsulation**: Generates a 1088-byte ciphertext and 32-byte shared secret
3. **Decapsulation**: Recovers the shared secret from the ciphertext
4. **Verification**: Confirms both secrets match

All in ~2 seconds, with real-time LED feedback showing each operation.

## Performance Results

| Operation | Time | Memory |
|-----------|------|--------|
| ML-KEM Key Generation | ~200ms | ~25 KB stack |
| ML-KEM Encapsulation | ~100ms | - |
| ML-KEM Decapsulation | ~100ms | - |
| **Total Demo** | **~2 seconds** | 226 KB flash |

### What About ML-DSA?

I also ported ML-DSA 65 (FIPS 204) for digital signatures. While it works, it's significantly slower:
- Key generation: ~30 seconds
- Signing: ~30 seconds

This highlights an important reality: not all PQC algorithms are equally suited for constrained devices. ML-KEM is practical today; ML-DSA needs further optimization (likely assembly-level) for real-time embedded use.

## Why Rust?

Rust was essential for this project:

1. **Memory Safety**: No buffer overflows or use-after-free bugs in cryptographic code
2. **No Runtime**: `no_std` support means no garbage collector competing for CPU cycles
3. **Zero-Cost Abstractions**: High-level APIs without performance penalties
4. **Formal Verification**: libcrux-iot is written in a subset of Rust that's formally verified

Example from my implementation:

```rust
// Safe, ergonomic API for ML-KEM
pub fn generate_key_pair(randomness: [u8; KEYGEN_SEED_SIZE]) -> KeyPair {
    let keypair = mlkem768::generate_key_pair(randomness);
    KeyPair {
        public_key: keypair.pk().clone(),
        private_key: keypair.sk().clone(),
    }
}
```

## Key Takeaways

1. **PQC is practical on MCUs today**: ML-KEM 768 runs efficiently on a Cortex-M33
2. **Algorithm choice matters**: ML-KEM is fast; ML-DSA needs more optimization for embedded
3. **Rust enables safe cryptography**: Memory safety + no_std + formal verification
4. **Start preparing now**: The quantum transition will take years; begin testing today

## What's Next?

- Optimize ML-DSA with assembly routines for Cortex-M33
- Add hardware RNG integration (STM32U585 has a true RNG)
- Implement hybrid classical/PQC schemes
- Benchmark against other PQC implementations

## Resources

- **Code**: The full implementation is available in my arduino-libraries-rust repository
- **libcrux-iot**: https://github.com/cryspen/libcrux-iot
- **NIST PQC Standards**: https://csrc.nist.gov/projects/post-quantum-cryptography

---

*The quantum future is coming. Our embedded devices need to be ready. This project proves they can be.*

---

#PostQuantumCryptography #Rust #EmbeddedSystems #Cybersecurity #IoT #Arduino #MLKEM #FIPS203 #QuantumComputing
