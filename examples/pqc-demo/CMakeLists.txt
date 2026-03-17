# SPDX-License-Identifier: Apache-2.0 OR MIT
# PQC Demo Application for Arduino Uno Q (ML-KEM + ML-DSA)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqc_demo)

# Add the SPI peripheral C driver
target_sources(app PRIVATE src/c/spi_peripheral.c)

# Add the LED matrix C driver
target_sources(app PRIVATE src/c/matrix.c)

# Add the hardware RNG wrapper for Rust FFI
# This file is provided by arduino-cryptography library
target_sources(app PRIVATE arduino-cryptography/c/hwrng.c)

# Add Ed25519 implementation (classical cryptography)
# This file is provided by arduino-cryptography library
target_sources(app PRIVATE arduino-cryptography/c/ed25519.c)

# Build the Rust application
rust_cargo_application()
