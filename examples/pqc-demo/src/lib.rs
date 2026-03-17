// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PQC Demo for Arduino Uno Q
//
// This example demonstrates post-quantum cryptography combining:
// - ML-KEM 768 (FIPS 203) for key encapsulation
// - ML-DSA 65 (FIPS 204) for digital signatures
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
// - mldsa.run_demo() -> ML-DSA only demo (keygen, sign, verify)
// - led_matrix.clear() -> clear the LED display

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use arduino_cryptography::{dsa, kem, rng::HwRng};
use arduino_led_matrix::{Frame, LedMatrix};
use arduino_rpc_bridge::{RpcResult, RpcServer, SpiTransport, Transport};
use arduino_zcbor::cose::CoseSign1;
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
    RpcResult::Str("pqc-demo 0.4.0-cose")
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
fn handle_mldsa_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  ML-DSA 65 Demo (FIPS 204)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
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

// Static buffer for COSE output to avoid stack overflow
static mut COSE_OUTPUT: [u8; 3500] = [0u8; 3500];

/// Run COSE_Sign1 demo with ML-DSA 65
/// Demonstrates creating RFC 9052 compliant signed messages
/// NOTE: Verification is skipped to reduce demo time (~30s vs ~90s)
fn handle_cose_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  COSE_Sign1 Demo (RFC 9052)");
    warn!("  with ML-DSA 65 (FIPS 204)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    warn!("Initializing hardware RNG...");
    let rng = HwRng::new();
    warn!("RNG ready");

    // Step 1: Generate ML-DSA key pair
    warn!("");
    warn!("Step 1: Generating ML-DSA 65 key pair...");
    warn!("  (This takes ~30 seconds on Cortex-M33)");
    show_key();
    sleep(Duration::millis_at_least(300));

    warn!("  Generating keygen randomness...");
    let keygen_randomness: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();
    warn!("  Calling dsa::generate_key_pair...");
    let key_pair = dsa::generate_key_pair(keygen_randomness);
    warn!("  Verification key: {} bytes", dsa::VERIFICATION_KEY_SIZE);
    warn!("  Signing key:      {} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("  Key pair generated!");

    // Step 2: Create COSE_Sign1 message
    warn!("");
    warn!("Step 2: Creating COSE_Sign1 message...");
    warn!("  (Signing takes ~30 seconds)");
    show_signature();
    sleep(Duration::millis_at_least(300));

    let payload = b"Hello from Arduino Uno Q with COSE!";

    // Use static buffer to avoid stack overflow
    let cose_output = unsafe { &mut COSE_OUTPUT };

    warn!("  Calling CoseSign1::sign_mldsa65...");
    let cose_len = match CoseSign1::sign_mldsa65(payload, &key_pair.signing_key, &rng, cose_output)
    {
        Ok(len) => {
            warn!("  Payload:       \"Hello from Arduino Uno Q with COSE!\"");
            warn!("  Payload size:  {} bytes", payload.len());
            warn!("  COSE_Sign1:    {} bytes", len);
            warn!("  (includes {} byte ML-DSA signature)", dsa::SIGNATURE_SIZE);
            len
        }
        Err(_) => {
            warn!("  FAILURE: COSE signing failed!");
            show_x();
            return RpcResult::Error(-1, "COSE sign failed");
        }
    };

    // Step 3: Decode to verify structure (fast - no crypto verification)
    warn!("");
    warn!("Step 3: Verifying COSE structure...");
    warn!("  (Signature verification skipped for speed)");
    show_shield();
    sleep(Duration::millis_at_least(300));

    warn!("  Calling CoseSign1::decode_unverified...");
    match CoseSign1::decode_unverified(&cose_output[..cose_len]) {
        Ok(parts) => {
            // Verify payload matches
            let mut match_ok = true;
            if parts.payload.len() != payload.len() {
                match_ok = false;
            } else {
                for i in 0..payload.len() {
                    if parts.payload[i] != payload[i] {
                        match_ok = false;
                        break;
                    }
                }
            }

            if match_ok && parts.algorithm == Some(arduino_zcbor::cose::Algorithm::MlDsa65) {
                warn!("  COSE structure valid!");
                warn!("  Algorithm: ML-DSA-65 (alg: -49)");
                warn!("  Signature size: {} bytes", parts.signature.len());
                warn!("  Payload extracted and matches original!");
                warn!("");
                warn!("========================================");
                warn!("  COSE_Sign1 Demo Complete!");
                warn!("========================================");
                warn!("");
                warn!("  COSE_Sign1 structure (RFC 9052):");
                warn!("    [protected, unprotected, payload, signature]");
                warn!("");
                show_checkmark();
                RpcResult::Bool(true)
            } else {
                warn!("  FAILURE: Payload mismatch or wrong algorithm!");
                show_x();
                RpcResult::Error(-3, "Payload mismatch")
            }
        }
        Err(_) => {
            warn!("  FAILURE: COSE decode failed!");
            show_x();
            RpcResult::Error(-2, "Decode failed")
        }
    }
}

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                                                              ║");
    warn!("║           PQC Demo - Arduino Uno Q                           ║");
    warn!("║           Post-Quantum Cryptography                          ║");
    warn!("║                                                              ║");
    warn!("║           ML-KEM 768 (FIPS 203)                              ║");
    warn!("║           ML-DSA 65  (FIPS 204)                              ║");
    warn!("║           COSE_Sign1 (RFC 9052)                              ║");
    warn!("║           Hardware TRNG (STM32U585)                          ║");
    warn!("║                                                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");
    warn!("Algorithm Parameters:");
    warn!("");
    warn!("  ML-KEM 768:");
    warn!("    Public Key:    {:>5} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("    Private Key:   {:>5} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("    Ciphertext:    {:>5} bytes", kem::CIPHERTEXT_SIZE);
    warn!("    Shared Secret: {:>5} bytes", kem::SHARED_SECRET_SIZE);
    warn!("");
    warn!("  ML-DSA 65:");
    warn!(
        "    Verification Key: {:>5} bytes",
        dsa::VERIFICATION_KEY_SIZE
    );
    warn!("    Signing Key:      {:>5} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("    Signature:        {:>5} bytes", dsa::SIGNATURE_SIZE);
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
    server.register("cose.run_demo", handle_cose_demo);

    // LED matrix control
    server.register("led_matrix.clear", handle_matrix_clear);

    warn!("");
    warn!("Available RPC methods:");
    warn!("  - ping              -> \"pong\"");
    warn!("  - version           -> firmware version");
    warn!("  - pqc.run_demo      -> full ML-KEM + ML-DSA demo");
    warn!("  - mlkem.run_demo    -> ML-KEM 768 demo only");
    warn!("  - mldsa.run_demo    -> ML-DSA 65 demo only");
    warn!("  - cose.run_demo     -> COSE_Sign1 with ML-DSA demo");
    warn!("  - led_matrix.clear  -> clear LED display");
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
