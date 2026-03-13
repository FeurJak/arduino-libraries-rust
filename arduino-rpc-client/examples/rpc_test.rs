// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Test Client
//
// A simple command-line tool to test RPC communication with the Arduino Uno Q MCU.

use arduino_rpc_client::{LedMatrixClient, RpcClientSync};
use std::env;

fn main() {
    env_logger::init();

    let socket_path =
        env::var("RPC_SOCKET").unwrap_or_else(|_| "/tmp/arduino-spi-router.sock".to_string());

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  ping                    - Test connection");
        eprintln!("  version                 - Get firmware version");
        eprintln!("  clear                   - Clear LED matrix");
        eprintln!("  fill                    - Fill LED matrix");
        eprintln!("  pixel <row> <col> <0|1> - Set single pixel");
        eprintln!("  brightness <level>      - Set brightness (0-7)");
        return;
    }

    println!("Connecting to {}...", socket_path);
    let client = match RpcClientSync::connect(&socket_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return;
        }
    };

    match args[1].as_str() {
        "ping" => {
            println!("Sending ping...");
            match client.call("ping", vec![]) {
                Ok(result) => println!("Response: {:?}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "version" => {
            println!("Getting version...");
            match client.call("version", vec![]) {
                Ok(result) => println!("Version: {:?}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "clear" => {
            println!("Clearing LED matrix...");
            match client.led_matrix_clear() {
                Ok(()) => println!("OK"),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "fill" => {
            println!("Filling LED matrix...");
            match client.call("led_matrix.fill", vec![]) {
                Ok(result) => println!("Result: {:?}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "pixel" => {
            if args.len() < 5 {
                eprintln!("Usage: {} pixel <row> <col> <0|1>", args[0]);
                return;
            }
            let row: u8 = args[2].parse().unwrap_or(0);
            let col: u8 = args[3].parse().unwrap_or(0);
            let on: bool = args[4] != "0";

            println!("Setting pixel ({}, {}) = {}", row, col, on);
            match client.led_matrix_set_pixel(row, col, on) {
                Ok(()) => println!("OK"),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "brightness" => {
            if args.len() < 3 {
                eprintln!("Usage: {} brightness <level>", args[0]);
                return;
            }
            let level: u8 = args[2].parse().unwrap_or(4);

            println!("Setting brightness to {}...", level);
            match client.call(
                "led_matrix.set_grayscale",
                vec![rmpv::Value::Integer(level.into())],
            ) {
                Ok(result) => println!("Result: {:?}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        other => {
            eprintln!("Unknown command: {}", other);
        }
    }
}
