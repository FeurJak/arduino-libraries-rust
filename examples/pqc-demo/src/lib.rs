// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Cryptography Demo for Arduino Uno Q
//
// This example demonstrates cryptographic operations:
//
// Post-Quantum Cryptography:
// - ML-KEM 768 (FIPS 203) for key encapsulation
// - ML-DSA 65 (FIPS 204) for digital signatures [performance issue]
//
// Classical Cryptography:
// - Ed25519 (RFC 8032) for digital signatures
//
// The demo runs entirely on the MCU - no binary data transfer from Linux needed.
// This makes the demo self-contained and easy to trigger via simple RPC calls.
//
// The LED matrix displays status:
// - Key icon: Generating keys
// - Lock icon: Encryption/decryption
// - Pen icon: Signing
// - Checkmark: Success
// - X: Failure
//
// RPC Methods:
// - ping() -> "pong"
// - version() -> firmware version
// - pqc.run_demo() -> complete ML-KEM + ML-DSA demo with verification
// - mlkem.run_demo() -> ML-KEM only demo (keygen, encaps, decaps)
// - mldsa.run_demo() -> ML-DSA only demo (keygen, sign) [slow]
// - ed25519.run_demo() -> Ed25519 demo (keygen, sign, verify)
// - led_matrix.clear() -> clear the LED display

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use arduino_cryptography::{dsa, ed25519, kem, rng::HwRng, x25519, xwing};
use arduino_led_matrix::{Frame, LedMatrix};
use arduino_rpc_bridge::{RpcResult, RpcServer, SpiTransport, Transport};
use zephyr::time::{sleep, Duration};

// Global state
static mut MATRIX: Option<LedMatrix> = None;

/// Get mutable reference to the global matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

// === LED Matrix Patterns ===

/// Show a checkmark pattern (success)
fn show_checkmark() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show an X pattern (failure)
fn show_x() {
    let pattern: [[u8; 13]; 8] = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a key icon (key generation)
fn show_key() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a lock icon (encryption/decryption)
fn show_lock() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a pen/signature icon
fn show_signature() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show shield icon (verification)
fn show_shield() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

// === RPC Handlers ===

/// Handle ping request
fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

/// Handle version request
fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("crypto-demo 0.6.0")
}

/// Run complete ML-KEM demo on-device
/// Demonstrates: key generation, encapsulation, decapsulation
fn handle_mlkem_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  ML-KEM 768 Demo (FIPS 203)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating ML-KEM 768 key pair...");
    warn!("  (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(500));

    let keygen_randomness: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();

    let key_pair = kem::generate_key_pair(keygen_randomness);
    warn!("  Public key:  {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("  Private key: {} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("  Key pair generated!");

    // Step 2: Encapsulate (simulate sender creating shared secret)
    warn!("");
    warn!("Step 2: Encapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let encaps_randomness: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();

    let (ciphertext, shared_secret_sender) =
        kem::encapsulate(key_pair.public_key(), encaps_randomness);
    warn!("  Ciphertext:     {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("  Shared secret:  {} bytes", kem::SHARED_SECRET_SIZE);
    warn!("  Encapsulation complete!");

    // Step 3: Decapsulate (receiver recovers shared secret)
    warn!("");
    warn!("Step 3: Decapsulating to recover shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let shared_secret_receiver = kem::decapsulate(key_pair.private_key(), &ciphertext);
    warn!("  Decapsulation complete!");

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let sender_bytes = shared_secret_sender.as_slice();
    let receiver_bytes = shared_secret_receiver.as_slice();

    let mut secrets_match = true;
    for i in 0..32 {
        if sender_bytes[i] != receiver_bytes[i] {
            secrets_match = false;
            break;
        }
    }

    if secrets_match {
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("  First 8 bytes of shared secret:");
        warn!(
            "    {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            sender_bytes[0],
            sender_bytes[1],
            sender_bytes[2],
            sender_bytes[3],
            sender_bytes[4],
            sender_bytes[5],
            sender_bytes[6],
            sender_bytes[7]
        );
        warn!("");
        warn!("========================================");
        warn!("  ML-KEM 768 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets do not match!");
        show_x();
        RpcResult::Error(-1, "Secrets mismatch")
    }
}

/// Run complete ML-DSA demo on-device
/// Demonstrates: key generation, signing (verification skipped for speed)
///
/// WARNING: ML-DSA operations currently experience significant performance
/// issues on this platform, causing timeouts (>3 minutes). This is a known
/// issue under investigation - the ML-DSA implementation itself is correct,
/// but there appears to be a performance regression in the libcrux-iot library
/// or its integration. ML-KEM operations work correctly (~2 seconds).
fn handle_mldsa_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  ML-DSA 65 Demo (FIPS 204)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");
    warn!("WARNING: ML-DSA operations are currently");
    warn!("experiencing performance issues (>3 min).");
    warn!("This is a known issue - the implementation");
    warn!("is correct but performance is degraded.");
    warn!("See backlog for investigation status.");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating ML-DSA 65 key pair...");
    warn!("  (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(300));

    let keygen_randomness: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();

    let key_pair = dsa::generate_key_pair(keygen_randomness);
    warn!("  Verification key: {} bytes", dsa::VERIFICATION_KEY_SIZE);
    warn!("  Signing key:      {} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("  Key pair generated!");

    // Step 2: Sign a message
    warn!("");
    warn!("Step 2: Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(300));

    let message = b"Hello from Arduino Uno Q!";
    let context: &[u8] = b"";

    let sign_randomness: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();

    match dsa::sign(&key_pair.signing_key, message, context, sign_randomness) {
        Ok(signature) => {
            warn!("  Message:   \"Hello from Arduino Uno Q!\"");
            warn!("  Signature: {} bytes", dsa::SIGNATURE_SIZE);
            warn!("  Signing complete!");
            warn!("");
            warn!("  (Verification skipped for demo speed)");
            warn!("");
            warn!("========================================");
            warn!("  ML-DSA 65 Demo Complete!");
            warn!("========================================");
            show_checkmark();
            RpcResult::Bool(true)
        }
        Err(_) => {
            warn!("  FAILURE: Signing failed!");
            show_x();
            RpcResult::Error(-1, "Sign failed")
        }
    }
}

/// Run complete PQC demo combining ML-KEM and ML-DSA
/// This is the full demonstration showing how PQC can protect communications
fn handle_pqc_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                                                              ║");
    warn!("║           POST-QUANTUM CRYPTOGRAPHY DEMO                     ║");
    warn!("║                                                              ║");
    warn!("║   ML-KEM 768 (FIPS 203) + ML-DSA 65 (FIPS 204)              ║");
    warn!("║   Running on Arduino Uno Q (STM32U585 MCU)                   ║");
    warn!("║   Using Hardware TRNG for cryptographic randomness          ║");
    warn!("║                                                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();
    warn!("Hardware TRNG initialized");
    warn!("");

    // ==========================================
    // Phase 1: Key Exchange with ML-KEM 768
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 1: Post-Quantum Key Exchange (ML-KEM 768)            │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Step 1.1: Generate ML-KEM key pair
    warn!("  [1.1] Generating ML-KEM 768 key pair...");
    warn!("        (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(600));

    let kem_keygen_rand: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();

    let kem_keypair = kem::generate_key_pair(kem_keygen_rand);
    warn!("        Public key:  {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("        Private key: {} bytes", kem::PRIVATE_KEY_SIZE);

    // Step 1.2: Encapsulate shared secret
    warn!("");
    warn!("  [1.2] Encapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let encaps_rand: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();

    let (ciphertext, shared_secret_enc) = kem::encapsulate(kem_keypair.public_key(), encaps_rand);
    warn!("        Ciphertext:    {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("        Shared secret: {} bytes", kem::SHARED_SECRET_SIZE);

    // Step 1.3: Decapsulate
    warn!("");
    warn!("  [1.3] Decapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let shared_secret_dec = kem::decapsulate(kem_keypair.private_key(), &ciphertext);

    // Verify shared secrets match
    let enc_bytes = shared_secret_enc.as_slice();
    let dec_bytes = shared_secret_dec.as_slice();
    let mut kem_success = true;
    for i in 0..32 {
        if enc_bytes[i] != dec_bytes[i] {
            kem_success = false;
            break;
        }
    }

    if !kem_success {
        warn!("        FAILURE: Key exchange failed!");
        show_x();
        return RpcResult::Error(-1, "KEM failed");
    }

    warn!("        Shared secrets match!");
    warn!("");
    warn!("  ✓ ML-KEM 768 key exchange successful");
    warn!("");

    // ==========================================
    // Phase 2: Digital Signatures with ML-DSA 65
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 2: Post-Quantum Digital Signatures (ML-DSA 65)       │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");
    warn!("  WARNING: ML-DSA currently has performance issues (>3 min).");
    warn!("  This demo may timeout. ML-KEM above completed successfully.");
    warn!("");

    // Step 2.1: Generate ML-DSA key pair
    warn!("  [2.1] Generating ML-DSA 65 key pair...");
    warn!("        (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(600));

    let dsa_keygen_rand: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();

    let dsa_keypair = dsa::generate_key_pair(dsa_keygen_rand);
    warn!(
        "        Verification key: {} bytes",
        dsa::VERIFICATION_KEY_SIZE
    );
    warn!("        Signing key:      {} bytes", dsa::SIGNING_KEY_SIZE);

    // Step 2.2: Sign a message
    warn!("");
    warn!("  [2.2] Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(500));

    let message = b"Quantum-safe message from Arduino Uno Q";
    let context: &[u8] = b"pqc-demo-v2";

    let sign_rand: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();

    match dsa::sign(&dsa_keypair.signing_key, message, context, sign_rand) {
        Ok(_signature) => {
            warn!("        Message: \"Quantum-safe message from Arduino Uno Q\"");
            warn!("        Signature: {} bytes", dsa::SIGNATURE_SIZE);
            warn!("");
            warn!("  ✓ ML-DSA 65 signing successful");
        }
        Err(_) => {
            warn!("        FAILURE: Signing failed!");
            show_x();
            return RpcResult::Error(-2, "Sign failed");
        }
    };

    // ==========================================
    // Summary
    // ==========================================
    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                      DEMO COMPLETE                           ║");
    warn!("╠══════════════════════════════════════════════════════════════╣");
    warn!("║  ML-KEM 768:  Key exchange verified                          ║");
    warn!("║  ML-DSA 65:   Signature generated                            ║");
    warn!("║                                                              ║");
    warn!("║  This MCU is now quantum-resistant!                          ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

/// Clear LED matrix
fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        matrix().clear();
    }
    RpcResult::Bool(true)
}

/// Run Ed25519 demo on-device
/// Demonstrates: key generation, signing, verification
fn handle_ed25519_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  Ed25519 Demo (RFC 8032)");
    warn!("  Classical Digital Signatures");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating Ed25519 key pair...");
    warn!("  (Using hardware TRNG for seed)");
    show_key();
    sleep(Duration::millis_at_least(300));

    let seed: [u8; ed25519::SECRET_KEY_SIZE] = rng.random_array();
    let secret_key = ed25519::SecretKey::from_seed(&seed);
    let public_key = secret_key.public_key();

    warn!("  Seed (secret):  {} bytes", ed25519::SECRET_KEY_SIZE);
    warn!("  Public key:     {} bytes", ed25519::PUBLIC_KEY_SIZE);
    warn!("  Key pair generated!");

    // Log first 8 bytes of public key
    let pk_bytes = public_key.to_bytes();
    warn!(
        "  Public key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        pk_bytes[0],
        pk_bytes[1],
        pk_bytes[2],
        pk_bytes[3],
        pk_bytes[4],
        pk_bytes[5],
        pk_bytes[6],
        pk_bytes[7]
    );

    // Step 2: Sign a message
    warn!("");
    warn!("Step 2: Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(300));

    let message = b"Hello from Arduino Uno Q with Ed25519!";
    let signature = secret_key.sign(message);

    warn!("  Message:   \"Hello from Arduino Uno Q with Ed25519!\"");
    warn!("  Signature: {} bytes", ed25519::SIGNATURE_SIZE);
    warn!("  Signing complete!");

    // Log first 8 bytes of signature
    let sig_bytes = signature.to_bytes();
    warn!(
        "  Signature prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        sig_bytes[0],
        sig_bytes[1],
        sig_bytes[2],
        sig_bytes[3],
        sig_bytes[4],
        sig_bytes[5],
        sig_bytes[6],
        sig_bytes[7]
    );

    // Step 3: Verify signature
    warn!("");
    warn!("Step 3: Verifying signature...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    if public_key.verify(message, &signature) {
        warn!("  SUCCESS: Signature verified!");
        warn!("");
        warn!("========================================");
        warn!("  Ed25519 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Signature verification failed!");
        show_x();
        RpcResult::Error(-1, "Verification failed")
    }
}

/// Run X25519 demo on-device
/// Demonstrates: key generation, Diffie-Hellman key agreement
fn handle_x25519_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  X25519 Demo (RFC 7748)");
    warn!("  Elliptic Curve Diffie-Hellman");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let rng = HwRng::new();

    // Step 1: Generate Alice's key pair
    warn!("Step 1: Generating Alice's X25519 key pair...");
    show_key();
    sleep(Duration::millis_at_least(300));

    let alice_seed: [u8; x25519::SECRET_KEY_SIZE] = rng.random_array();
    let alice_sk = x25519::SecretKey::from_bytes(&alice_seed);
    let alice_pk = alice_sk.public_key();

    warn!("  Alice's public key: {} bytes", x25519::PUBLIC_KEY_SIZE);
    let alice_pk_bytes = alice_pk.to_bytes();
    warn!(
        "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        alice_pk_bytes[0],
        alice_pk_bytes[1],
        alice_pk_bytes[2],
        alice_pk_bytes[3],
        alice_pk_bytes[4],
        alice_pk_bytes[5],
        alice_pk_bytes[6],
        alice_pk_bytes[7]
    );

    // Step 2: Generate Bob's key pair
    warn!("");
    warn!("Step 2: Generating Bob's X25519 key pair...");
    sleep(Duration::millis_at_least(200));

    let bob_seed: [u8; x25519::SECRET_KEY_SIZE] = rng.random_array();
    let bob_sk = x25519::SecretKey::from_bytes(&bob_seed);
    let bob_pk = bob_sk.public_key();

    warn!("  Bob's public key: {} bytes", x25519::PUBLIC_KEY_SIZE);
    let bob_pk_bytes = bob_pk.to_bytes();
    warn!(
        "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bob_pk_bytes[0],
        bob_pk_bytes[1],
        bob_pk_bytes[2],
        bob_pk_bytes[3],
        bob_pk_bytes[4],
        bob_pk_bytes[5],
        bob_pk_bytes[6],
        bob_pk_bytes[7]
    );

    // Step 3: Compute shared secrets
    warn!("");
    warn!("Step 3: Computing shared secrets...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    let alice_shared = match alice_sk.diffie_hellman(&bob_pk) {
        Ok(ss) => ss,
        Err(_) => {
            warn!("  FAILURE: Alice's DH failed!");
            show_x();
            return RpcResult::Error(-1, "X25519 DH failed");
        }
    };

    let bob_shared = match bob_sk.diffie_hellman(&alice_pk) {
        Ok(ss) => ss,
        Err(_) => {
            warn!("  FAILURE: Bob's DH failed!");
            show_x();
            return RpcResult::Error(-2, "X25519 DH failed");
        }
    };

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");

    let alice_ss_bytes = alice_shared.as_bytes();
    let bob_ss_bytes = bob_shared.as_bytes();

    if alice_ss_bytes == bob_ss_bytes {
        warn!("  Shared secret: {} bytes", x25519::SHARED_SECRET_SIZE);
        warn!(
            "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            alice_ss_bytes[0],
            alice_ss_bytes[1],
            alice_ss_bytes[2],
            alice_ss_bytes[3],
            alice_ss_bytes[4],
            alice_ss_bytes[5],
            alice_ss_bytes[6],
            alice_ss_bytes[7]
        );
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("========================================");
        warn!("  X25519 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        RpcResult::Error(-3, "Shared secrets mismatch")
    }
}

/// Run X-Wing demo on-device
/// Demonstrates: hybrid PQ KEM (ML-KEM-768 + X25519)
fn handle_xwing_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  X-Wing Demo (Hybrid PQ KEM)");
    warn!("  ML-KEM-768 + X25519 Hybrid");
    warn!("  Post-Quantum Secure Key Encapsulation");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let rng = HwRng::new();

    // Step 1: Generate recipient's key pair
    warn!("Step 1: Generating X-Wing key pair...");
    warn!("  (This combines ML-KEM-768 + X25519)");
    show_key();
    sleep(Duration::millis_at_least(500));

    let seed: [u8; xwing::SECRET_KEY_SIZE] = rng.random_array();
    let secret_key = xwing::SecretKey::from_seed(&seed);
    let public_key = secret_key.public_key();

    warn!("  Secret key seed: {} bytes", xwing::SECRET_KEY_SIZE);
    warn!("  Public key:      {} bytes", xwing::PUBLIC_KEY_SIZE);
    warn!("  Key pair generated!");

    // Log first 8 bytes of public key
    let pk_bytes = public_key.as_bytes();
    warn!(
        "  Public key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        pk_bytes[0],
        pk_bytes[1],
        pk_bytes[2],
        pk_bytes[3],
        pk_bytes[4],
        pk_bytes[5],
        pk_bytes[6],
        pk_bytes[7]
    );

    // Step 2: Encapsulate (sender side)
    warn!("");
    warn!("Step 2: Encapsulating shared secret...");
    warn!("  (Sender creates ciphertext + shared secret)");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let encaps_seed: [u8; xwing::ENCAPS_SEED_SIZE] = rng.random_array();
    let (ciphertext, sender_shared) = xwing::encapsulate(public_key, encaps_seed);

    warn!("  Ciphertext:      {} bytes", xwing::CIPHERTEXT_SIZE);
    warn!("  Shared secret:   {} bytes", xwing::SHARED_SECRET_SIZE);
    warn!("  Encapsulation complete!");

    // Log first 8 bytes of ciphertext
    let ct_bytes = ciphertext.as_bytes();
    warn!(
        "  Ciphertext prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        ct_bytes[0],
        ct_bytes[1],
        ct_bytes[2],
        ct_bytes[3],
        ct_bytes[4],
        ct_bytes[5],
        ct_bytes[6],
        ct_bytes[7]
    );

    // Log first 8 bytes of sender's shared secret
    let sender_ss_bytes = sender_shared.as_bytes();
    warn!(
        "  Sender SS prefix:  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        sender_ss_bytes[0],
        sender_ss_bytes[1],
        sender_ss_bytes[2],
        sender_ss_bytes[3],
        sender_ss_bytes[4],
        sender_ss_bytes[5],
        sender_ss_bytes[6],
        sender_ss_bytes[7]
    );

    // Step 3: Decapsulate (receiver side)
    warn!("");
    warn!("Step 3: Decapsulating shared secret...");
    warn!("  (Receiver recovers shared secret from ciphertext)");
    show_shield();
    sleep(Duration::millis_at_least(500));

    let receiver_shared = xwing::decapsulate(&secret_key, &ciphertext);

    // Log first 8 bytes of receiver's shared secret
    let receiver_ss_bytes = receiver_shared.as_bytes();
    warn!(
        "  Receiver SS prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        receiver_ss_bytes[0],
        receiver_ss_bytes[1],
        receiver_ss_bytes[2],
        receiver_ss_bytes[3],
        receiver_ss_bytes[4],
        receiver_ss_bytes[5],
        receiver_ss_bytes[6],
        receiver_ss_bytes[7]
    );

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");

    if sender_ss_bytes == receiver_ss_bytes {
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("========================================");
        warn!("  X-Wing Demo Complete!");
        warn!("  Hybrid PQ Key Encapsulation Verified!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        RpcResult::Error(-1, "X-Wing shared secrets mismatch")
    }
}

// NOTE: COSE_Sign1 demo temporarily disabled due to ML-DSA performance issues.
// The arduino-zcbor crate with COSE support is ready and working, but ML-DSA
// operations currently timeout (>3 minutes). Once the ML-DSA performance
// regression is resolved, re-enable the COSE demo.
//
// To re-enable:
// 1. Add import: use arduino_zcbor::cose::CoseSign1;
// 2. Uncomment handle_cose_demo function below
// 3. Register handler: server.register("cose.run_demo", handle_cose_demo);

/*
// Static buffer for COSE output to avoid stack overflow
static mut COSE_OUTPUT: [u8; 3500] = [0u8; 3500];

/// Run COSE_Sign1 demo with ML-DSA 65
fn handle_cose_demo(_count: usize) -> RpcResult {
    // ... COSE demo code here (depends on ML-DSA working) ...
    RpcResult::Error(-1, "COSE demo disabled - ML-DSA timeout")
}
*/

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                                                              ║");
    warn!("║           Crypto Demo - Arduino Uno Q                        ║");
    warn!("║           Post-Quantum + Classical Cryptography              ║");
    warn!("║                                                              ║");
    warn!("║           ML-KEM 768 (FIPS 203)                              ║");
    warn!("║           ML-DSA 65  (FIPS 204) [performance issue]          ║");
    warn!("║           Ed25519 (RFC 8032)                                 ║");
    warn!("║           Hardware TRNG (STM32U585)                          ║");
    warn!("║                                                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");
    warn!("Algorithm Parameters:");
    warn!("");
    warn!("  ML-KEM 768 (Post-Quantum Key Encapsulation):");
    warn!("    Public Key:    {:>5} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("    Private Key:   {:>5} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("    Ciphertext:    {:>5} bytes", kem::CIPHERTEXT_SIZE);
    warn!("    Shared Secret: {:>5} bytes", kem::SHARED_SECRET_SIZE);
    warn!("");
    warn!("  ML-DSA 65 (Post-Quantum Signatures):");
    warn!(
        "    Verification Key: {:>5} bytes",
        dsa::VERIFICATION_KEY_SIZE
    );
    warn!("    Signing Key:      {:>5} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("    Signature:        {:>5} bytes", dsa::SIGNATURE_SIZE);
    warn!("");
    warn!("  Ed25519 (Classical Signatures):");
    warn!(
        "    Public Key:       {:>5} bytes",
        ed25519::PUBLIC_KEY_SIZE
    );
    warn!(
        "    Secret Key:       {:>5} bytes",
        ed25519::SECRET_KEY_SIZE
    );
    warn!("    Signature:        {:>5} bytes", ed25519::SIGNATURE_SIZE);
    warn!("");

    // Initialize LED matrix
    warn!("Initializing LED matrix...");
    unsafe {
        MATRIX = Some(LedMatrix::new());
        if !matrix().begin() {
            warn!("Failed to initialize LED matrix!");
            loop {
                sleep(Duration::millis_at_least(1000));
            }
        }
    }
    warn!("LED matrix initialized!");

    // Show key icon briefly at startup
    show_key();
    sleep(Duration::millis_at_least(800));
    unsafe {
        matrix().clear();
    }

    // Initialize SPI transport
    warn!("Initializing SPI transport...");
    let mut spi = SpiTransport::new();
    if !spi.init() {
        warn!("Failed to initialize SPI!");
        show_x();
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    // Create RPC server and register handlers
    warn!("");
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core methods
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // Demo methods (self-contained, no binary data needed)
    server.register("pqc.run_demo", handle_pqc_demo);
    server.register("mlkem.run_demo", handle_mlkem_demo);
    server.register("mldsa.run_demo", handle_mldsa_demo);
    server.register("ed25519.run_demo", handle_ed25519_demo);
    server.register("x25519.run_demo", handle_x25519_demo);
    server.register("xwing.run_demo", handle_xwing_demo);
    // NOTE: cose.run_demo disabled due to ML-DSA performance issues

    // LED matrix control
    server.register("led_matrix.clear", handle_matrix_clear);

    warn!("");
    warn!("Available RPC methods:");
    warn!("  - ping              -> \"pong\"");
    warn!("  - version           -> firmware version");
    warn!("  - pqc.run_demo      -> full ML-KEM + ML-DSA demo");
    warn!("  - mlkem.run_demo    -> ML-KEM 768 demo only");
    warn!("  - mldsa.run_demo    -> ML-DSA 65 demo only (WARNING: slow)");
    warn!("  - ed25519.run_demo  -> Ed25519 demo (fast!)");
    warn!("  - x25519.run_demo   -> X25519 ECDH demo (fast!)");
    warn!("  - xwing.run_demo    -> X-Wing hybrid PQ KEM demo");
    warn!("  - led_matrix.clear  -> clear LED display");
    warn!("");
    warn!("NOTE: ML-DSA operations have a known performance issue");
    warn!("      causing timeouts (>3 min). Ed25519 works normally.");
    warn!("");
    warn!("PQC RPC server ready!");
    warn!("Waiting for requests from Linux...");

    // Prepare initial empty response
    let empty_response: [u8; 0] = [];
    spi.prepare_tx(&empty_response);

    let mut request_count: u32 = 0;

    // Main loop
    loop {
        let rx_len = spi.transceive();

        if rx_len == 0 {
            spi.prepare_tx(&empty_response);
            continue;
        }

        request_count = request_count.wrapping_add(1);

        // Read received data
        let mut rx_buffer = [0u8; 512];
        let mut total_read = 0;
        while total_read < rx_len && total_read < rx_buffer.len() {
            let mut byte_buf = [0u8; 1];
            if spi.read(&mut byte_buf) > 0 {
                rx_buffer[total_read] = byte_buf[0];
                total_read += 1;
            } else {
                break;
            }
        }

        warn!("[{}] RX {} bytes", request_count, total_read);

        // Process RPC message
        if let Some(response) = server.process(&rx_buffer[..total_read]) {
            warn!("[{}] TX {} bytes response", request_count, response.len());
            spi.prepare_tx(response);
        } else {
            warn!("[{}] No response", request_count);
            spi.prepare_tx(&empty_response);
        }
    }
}
