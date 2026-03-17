// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PQC Demo for Arduino Uno Q
//
// This example demonstrates post-quantum cryptography combining:
// - ML-KEM 768 (FIPS 203) for key encapsulation
// - ML-DSA 65 (FIPS 204) for digital signatures
//
// Protocol:
// 1. MCU generates ML-KEM key pair and sends public key to Linux
// 2. Linux encapsulates a shared secret using the public key
// 3. Linux sends ciphertext back to MCU
// 4. MCU decapsulates to recover the shared secret
// 5. MCU uses shared secret (via SHA3) to seed ML-DSA key generation
// 6. MCU signs a message with ML-DSA and returns signature + verification key
// 7. Linux verifies the signature
//
// The LED matrix displays status:
// - Key icon: Generating keys
// - Lock icon: Encryption/signing
// - Checkmark: Success
// - X: Failure
//
// RPC Methods:
// - ping() -> "pong"
// - version() -> firmware version
// - mlkem.generate_keypair() -> generates new ML-KEM key pair
// - mlkem.get_public_key() -> returns serialized public key (1184 bytes)
// - mlkem.decapsulate(ciphertext) -> returns shared secret (32 bytes)
// - mldsa.generate_keypair_from_secret() -> generates ML-DSA keys from shared secret
// - mldsa.sign(message) -> signs message, returns signature
// - mldsa.get_verification_key() -> returns verification key (1952 bytes)
// - pqc.full_demo(ciphertext, message) -> complete demo: decapsulate, generate DSA keys, sign

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use arduino_cryptography::{dsa, kem};
use arduino_led_matrix::{Frame, LedMatrix};
use arduino_rpc_bridge::{RpcResult, RpcServer, SpiTransport, Transport, PARAMS};
use zephyr::time::{sleep, Duration};

// Global state
static mut MATRIX: Option<LedMatrix> = None;

// ML-KEM state
static mut KEM_KEY_PAIR: Option<kem::KeyPair> = None;
static mut SHARED_SECRET: Option<[u8; 32]> = None;

// ML-DSA state
static mut DSA_KEY_PAIR: Option<dsa::KeyPair> = None;
static mut LAST_SIGNATURE: Option<dsa::Signature> = None;

// Response buffers
static mut PK_BUFFER: [u8; kem::PUBLIC_KEY_SIZE] = [0u8; kem::PUBLIC_KEY_SIZE];
static mut SS_BUFFER: [u8; 32] = [0u8; 32];
static mut VK_BUFFER: [u8; dsa::VERIFICATION_KEY_SIZE] = [0u8; dsa::VERIFICATION_KEY_SIZE];
static mut SIG_BUFFER: [u8; dsa::SIGNATURE_SIZE] = [0u8; dsa::SIGNATURE_SIZE];

/// Get mutable reference to the global matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

/// Simple pseudo-random number generator
/// In production, use hardware RNG from Zephyr
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut seed = 0u64;
        for (i, &b) in bytes.iter().take(8).enumerate() {
            seed |= (b as u64) << (i * 8);
        }
        Self::new(seed)
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = bytes[i];
            }
        }
    }
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

/// Show a lock icon (encryption/signing)
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

// === RPC Handlers ===

/// Handle ping request
fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

/// Handle version request
fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("pqc-demo 0.1.0")
}

/// Generate a new ML-KEM key pair
fn handle_kem_generate_keypair(_count: usize) -> RpcResult {
    warn!("Generating ML-KEM 768 key pair...");
    show_key();

    // Create randomness for key generation (64 bytes needed)
    let mut rng = SimpleRng::new(0x12345678_9ABCDEF0);
    let mut randomness = [0u8; kem::KEYGEN_SEED_SIZE];
    rng.fill_bytes(&mut randomness);

    // Generate key pair
    let key_pair = kem::generate_key_pair(randomness);

    unsafe {
        KEM_KEY_PAIR = Some(key_pair);
        SHARED_SECRET = None;
        DSA_KEY_PAIR = None;
        LAST_SIGNATURE = None;
    }

    warn!("ML-KEM key pair generated!");
    RpcResult::Bool(true)
}

/// Get the ML-KEM public key
fn handle_kem_get_public_key(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref kp) = KEM_KEY_PAIR {
            let pk_bytes = kp.public_key().as_slice();
            PK_BUFFER.copy_from_slice(pk_bytes);
            warn!("Returning ML-KEM public key ({} bytes)", pk_bytes.len());
            RpcResult::Int(kem::PUBLIC_KEY_SIZE as i64)
        } else {
            warn!("No ML-KEM key pair generated!");
            RpcResult::Error(-1, "No key pair")
        }
    }
}

/// Decapsulate a ciphertext to get the shared secret
fn handle_kem_decapsulate(count: usize) -> RpcResult {
    warn!("Decapsulating ciphertext...");
    show_lock();

    if count < 1 {
        return RpcResult::Error(-1, "Need ciphertext");
    }

    unsafe {
        if let Some(ref kp) = KEM_KEY_PAIR {
            let ct_bytes = &PARAMS.bytes[..kem::CIPHERTEXT_SIZE];
            let mut ct_array = [0u8; kem::CIPHERTEXT_SIZE];
            ct_array.copy_from_slice(ct_bytes);

            let ciphertext = kem::ciphertext_from_bytes(&ct_array);
            let shared_secret = kem::decapsulate(kp.private_key(), &ciphertext);

            SS_BUFFER.copy_from_slice(shared_secret.as_slice());
            SHARED_SECRET = Some(SS_BUFFER);

            warn!("Decapsulation successful!");
            RpcResult::Int(32)
        } else {
            warn!("No ML-KEM key pair generated!");
            show_x();
            RpcResult::Error(-1, "No key pair")
        }
    }
}

/// Get the shared secret
fn handle_kem_get_shared_secret(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref ss) = SHARED_SECRET {
            SS_BUFFER.copy_from_slice(ss);
            warn!("Returning shared secret (32 bytes)");
            RpcResult::Int(32)
        } else {
            RpcResult::Error(-1, "No shared secret")
        }
    }
}

/// Generate ML-DSA key pair from the shared secret
fn handle_dsa_generate_from_secret(_count: usize) -> RpcResult {
    warn!("Generating ML-DSA 65 key pair from shared secret...");
    show_key();

    unsafe {
        if let Some(ref ss) = SHARED_SECRET {
            // Use shared secret to seed RNG for ML-DSA key generation
            let mut rng = SimpleRng::from_bytes(ss);
            let mut randomness = [0u8; dsa::KEYGEN_RANDOMNESS_SIZE];
            rng.fill_bytes(&mut randomness);

            // Generate ML-DSA key pair
            let key_pair = dsa::generate_key_pair(randomness);
            DSA_KEY_PAIR = Some(key_pair);
            LAST_SIGNATURE = None;

            warn!("ML-DSA 65 key pair generated!");
            RpcResult::Bool(true)
        } else {
            warn!("No shared secret available!");
            show_x();
            RpcResult::Error(-1, "No shared secret")
        }
    }
}

/// Get the ML-DSA verification key
fn handle_dsa_get_verification_key(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref kp) = DSA_KEY_PAIR {
            VK_BUFFER.copy_from_slice(kp.verification_key.as_slice());
            warn!(
                "Returning ML-DSA verification key ({} bytes)",
                dsa::VERIFICATION_KEY_SIZE
            );
            RpcResult::Int(dsa::VERIFICATION_KEY_SIZE as i64)
        } else {
            warn!("No ML-DSA key pair generated!");
            RpcResult::Error(-1, "No DSA key pair")
        }
    }
}

/// Sign a message with ML-DSA
fn handle_dsa_sign(count: usize) -> RpcResult {
    warn!("Signing message with ML-DSA 65...");
    show_signature();

    if count < 1 {
        return RpcResult::Error(-1, "Need message");
    }

    unsafe {
        if let Some(ref kp) = DSA_KEY_PAIR {
            // Get message from params
            let msg_len = PARAMS.ints[0] as usize;
            let message = &PARAMS.bytes[..msg_len.min(256)];

            // Generate signing randomness
            let mut rng = SimpleRng::new(0xDEADBEEF_CAFEBABE);
            let mut randomness = [0u8; dsa::SIGNING_RANDOMNESS_SIZE];
            rng.fill_bytes(&mut randomness);

            // Sign with empty context (domain separation)
            let context: &[u8] = b"";

            match dsa::sign(&kp.signing_key, message, context, randomness) {
                Ok(signature) => {
                    SIG_BUFFER.copy_from_slice(signature.as_slice());
                    LAST_SIGNATURE = Some(signature);
                    warn!("Signature generated ({} bytes)", dsa::SIGNATURE_SIZE);
                    show_checkmark();
                    RpcResult::Int(dsa::SIGNATURE_SIZE as i64)
                }
                Err(_e) => {
                    warn!("Signing failed!");
                    show_x();
                    RpcResult::Error(-2, "Signing failed")
                }
            }
        } else {
            warn!("No ML-DSA key pair generated!");
            show_x();
            RpcResult::Error(-1, "No DSA key pair")
        }
    }
}

/// Get the last signature
fn handle_dsa_get_signature(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref sig) = LAST_SIGNATURE {
            SIG_BUFFER.copy_from_slice(sig.as_slice());
            warn!("Returning signature ({} bytes)", dsa::SIGNATURE_SIZE);
            RpcResult::Int(dsa::SIGNATURE_SIZE as i64)
        } else {
            RpcResult::Error(-1, "No signature")
        }
    }
}

/// Full PQC demo: decapsulate ciphertext, generate DSA keys, sign message
/// Params: ciphertext (1088 bytes), then message length (int), then message
fn handle_pqc_full_demo(count: usize) -> RpcResult {
    warn!("=== Starting full PQC demo ===");

    if count < 2 {
        return RpcResult::Error(-1, "Need ciphertext and message");
    }

    unsafe {
        // Step 1: Check ML-KEM key pair exists
        if KEM_KEY_PAIR.is_none() {
            warn!("No ML-KEM key pair - generating...");
            show_key();
            let mut rng = SimpleRng::new(0x12345678_9ABCDEF0);
            let mut randomness = [0u8; kem::KEYGEN_SEED_SIZE];
            rng.fill_bytes(&mut randomness);
            KEM_KEY_PAIR = Some(kem::generate_key_pair(randomness));
        }

        // Step 2: Decapsulate
        warn!("Step 1: Decapsulating ciphertext...");
        show_lock();

        let kp = KEM_KEY_PAIR.as_ref().unwrap();
        let ct_bytes = &PARAMS.bytes[..kem::CIPHERTEXT_SIZE];
        let mut ct_array = [0u8; kem::CIPHERTEXT_SIZE];
        ct_array.copy_from_slice(ct_bytes);

        let ciphertext = kem::ciphertext_from_bytes(&ct_array);
        let shared_secret = kem::decapsulate(kp.private_key(), &ciphertext);
        SS_BUFFER.copy_from_slice(shared_secret.as_slice());
        SHARED_SECRET = Some(SS_BUFFER);
        warn!("  Shared secret derived!");

        // Step 3: Generate ML-DSA key pair from shared secret
        warn!("Step 2: Generating ML-DSA keys from shared secret...");
        show_key();

        let mut rng = SimpleRng::from_bytes(&SS_BUFFER);
        let mut dsa_randomness = [0u8; dsa::KEYGEN_RANDOMNESS_SIZE];
        rng.fill_bytes(&mut dsa_randomness);

        let dsa_keypair = dsa::generate_key_pair(dsa_randomness);
        VK_BUFFER.copy_from_slice(dsa_keypair.verification_key.as_slice());
        DSA_KEY_PAIR = Some(dsa_keypair);
        warn!("  ML-DSA key pair generated!");

        // Step 4: Sign the message
        warn!("Step 3: Signing message...");
        show_signature();

        let msg_len = PARAMS.ints[0] as usize;
        let message = &PARAMS.bytes[kem::CIPHERTEXT_SIZE..kem::CIPHERTEXT_SIZE + msg_len.min(256)];

        let mut sign_rng = SimpleRng::new(0xDEADBEEF_CAFEBABE);
        let mut sign_randomness = [0u8; dsa::SIGNING_RANDOMNESS_SIZE];
        sign_rng.fill_bytes(&mut sign_randomness);

        let context: &[u8] = b"";
        let dsa_kp = DSA_KEY_PAIR.as_ref().unwrap();

        match dsa::sign(&dsa_kp.signing_key, message, context, sign_randomness) {
            Ok(signature) => {
                SIG_BUFFER.copy_from_slice(signature.as_slice());
                LAST_SIGNATURE = Some(signature);
                warn!("  Message signed!");
                warn!("=== PQC demo complete ===");
                show_checkmark();
                RpcResult::Bool(true)
            }
            Err(_e) => {
                warn!("  Signing failed!");
                show_x();
                RpcResult::Error(-2, "Signing failed")
            }
        }
    }
}

/// Clear LED matrix
fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        matrix().clear();
    }
    RpcResult::Bool(true)
}

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  PQC Demo - Arduino Uno Q");
    warn!("  Post-Quantum Cryptography");
    warn!("  ML-KEM 768 + ML-DSA 65");
    warn!("===========================================");
    warn!("");
    warn!("ML-KEM 768 Parameters:");
    warn!("  Public Key:    {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("  Private Key:   {} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("  Ciphertext:    {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("  Shared Secret: {} bytes", kem::SHARED_SECRET_SIZE);
    warn!("");
    warn!("ML-DSA 65 Parameters:");
    warn!("  Verification Key: {} bytes", dsa::VERIFICATION_KEY_SIZE);
    warn!("  Signing Key:      {} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("  Signature:        {} bytes", dsa::SIGNATURE_SIZE);
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

    // Show key icon briefly
    show_key();
    sleep(Duration::millis_at_least(500));
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
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core methods
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // ML-KEM methods
    server.register("mlkem.generate_keypair", handle_kem_generate_keypair);
    server.register("mlkem.get_public_key", handle_kem_get_public_key);
    server.register("mlkem.decapsulate", handle_kem_decapsulate);
    server.register("mlkem.get_shared_secret", handle_kem_get_shared_secret);

    // ML-DSA methods
    server.register(
        "mldsa.generate_from_secret",
        handle_dsa_generate_from_secret,
    );
    server.register(
        "mldsa.get_verification_key",
        handle_dsa_get_verification_key,
    );
    server.register("mldsa.sign", handle_dsa_sign);
    server.register("mldsa.get_signature", handle_dsa_get_signature);

    // Combined PQC demo
    server.register("pqc.full_demo", handle_pqc_full_demo);

    // LED matrix control
    server.register("led_matrix.clear", handle_matrix_clear);

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
