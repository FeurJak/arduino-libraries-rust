# SPDX-License-Identifier: Apache-2.0 OR MIT
# RPC Server Application for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(rpc_server)

# Add the SPI peripheral C driver
target_sources(app PRIVATE src/c/spi_peripheral.c)

# Add the LED matrix C driver
target_sources(app PRIVATE src/c/matrix.c)

# Build the Rust application
rust_cargo_application()
