# SPDX-License-Identifier: Apache-2.0 OR MIT
# LED Matrix Demo Application for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(led_matrix_demo)

# Add the LED matrix C driver
target_sources(app PRIVATE src/c/matrix.c)

# Build the Rust application
rust_cargo_application()
