# Arduino Libraries Rust

Rust ports of Arduino libraries for the Arduino Uno Q (STM32U585) using Zephyr RTOS.

## Libraries

### arduino-led-matrix

A Rust port of the `Arduino_LED_Matrix` C library for controlling the 8x13 (104 LEDs) charlieplexed LED matrix on the Arduino Uno Q board.

**Features:**
- Binary (on/off) and grayscale (8 levels) display modes
- Frame-based rendering with bitmap support
- Animation sequences with configurable timing
- Pre-defined patterns and animations
- Safe, idiomatic Rust API

**Example:**
```rust
use arduino_led_matrix::{LedMatrix, Frame, GrayscaleFrame};

let mut matrix = LedMatrix::new();
matrix.begin();

// Display a binary frame
let frame = Frame::all_on();
matrix.load_frame(&frame);

// Display grayscale
matrix.set_grayscale_bits(3);
let mut gray = GrayscaleFrame::all_off();
for row in 0..8 {
    for col in 0..13 {
        gray.set(row, col, row as u8);  // Gradient
    }
}
matrix.draw(&gray);
```

## Requirements

- Docker (for building)
- ADB (for flashing): `brew install android-platform-tools`
- Arduino Uno Q board connected via USB-C

## Quick Start

```bash
# Build the LED matrix demo
make build

# Flash to the board
make flash

# Or build and flash in one step
make all
```

## Project Structure

```
arduino-libraries-rust/
├── arduino-led-matrix/          # LED Matrix library
│   ├── src/
│   │   ├── lib.rs              # Main library interface
│   │   ├── ffi.rs              # FFI bindings to C driver
│   │   ├── frame.rs            # Frame types (binary & grayscale)
│   │   └── animation.rs        # Animation support
│   └── Cargo.toml
├── examples/
│   └── led-matrix-demo/         # Demo application
│       ├── src/
│       │   ├── lib.rs          # Demo code
│       │   └── c/matrix.c      # C LED matrix driver
│       ├── boards/
│       │   └── arduino_uno_q.overlay
│       ├── CMakeLists.txt
│       ├── Cargo.toml
│       └── prj.conf
├── docker/
│   └── Dockerfile              # Build environment
├── Makefile
├── west.yml                    # Zephyr manifest
└── README.md
```

## Development

### Opening a Shell in the Docker Container

```bash
make shell
```

### Accessing the Board

```bash
# Open ADB shell
make shell-board

# Or directly
adb shell
```

### First-Time Setup

If flashing fails, you may need to push the SWD configuration to the board:

```bash
make setup-swd
```

## API Documentation

### LedMatrix

The main interface for controlling the LED matrix.

| Method | Description |
|--------|-------------|
| `new()` | Create a new matrix controller |
| `begin()` | Initialize the matrix driver |
| `end()` | Stop the matrix driver |
| `clear()` | Turn off all LEDs |
| `load_frame(&Frame)` | Display a binary frame |
| `draw(&GrayscaleFrame)` | Display a grayscale frame |
| `set_grayscale_bits(u8)` | Set grayscale bit depth (3 or 8) |
| `load_sequence(&Animation)` | Load an animation |
| `next()` | Advance to next animation frame |
| `play_sequence(loop)` | Play animation (blocking) |

### Frame

Binary (on/off) frame type with 104 LED states packed into 4 u32 words.

| Method | Description |
|--------|-------------|
| `new([u32; 4])` | Create from raw data |
| `all_on()` | All LEDs on |
| `all_off()` | All LEDs off |
| `from_bitmap(&[[u8; 13]; 8])` | Create from 8x13 bitmap |
| `get(row, col)` | Get LED state |
| `set(row, col, on)` | Set LED state |

### GrayscaleFrame

Grayscale frame with 8 brightness levels per LED.

| Method | Description |
|--------|-------------|
| `new([u8; 104])` | Create from raw data |
| `all_on()` | All LEDs at max brightness |
| `all_off()` | All LEDs off |
| `from_bitmap(&[[u8; 13]; 8])` | Create from bitmap |
| `get(row, col)` | Get brightness (0-7) |
| `set(row, col, brightness)` | Set brightness |
| `fill(brightness)` | Set all to same brightness |

### Animation

Define animations using the `animation!` macro:

```rust
use arduino_led_matrix::animation;

animation!(MY_ANIM, [
    [0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788, 100],  // 100ms
    [0x00000000, 0x00000000, 0x00000000, 0x00000000, 100],  // 100ms
]);
```

Pre-defined patterns available in `arduino_led_matrix::animation::patterns`:
- `BLINK` - Simple on/off blink
- `SCROLL_LINE` - Scrolling vertical line
- `HEART` - Heart shape
- `SMILEY` - Smiley face

## License

Apache-2.0 OR MIT
