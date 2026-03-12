# Makefile for Arduino Libraries Rust
#
# This Makefile provides a Docker-based workflow for building and flashing
# Rust applications using the arduino-led-matrix library.
#
# Quick Start:
#   make build    - Build the LED matrix demo in Docker
#   make flash    - Flash the demo to the board
#   make all      - Build and flash
#
# Requirements:
#   - Docker (for building)
#   - ADB (for flashing only)

# Configuration
# Use the arduino-uno-q-rust image if it exists, otherwise build our own
IMAGE_NAME := arduino-uno-q-rust
DOCKER_DIR := docker
APP_DIR := examples/led-matrix-demo
BUILD_DIR := build
OUTPUT_DIR := output

# Board configuration
BOARD := arduino_uno_q

# OpenOCD paths on the Arduino Uno Q board
OPENOCD_BIN := /opt/openocd/bin/openocd
OPENOCD_SCRIPTS := /opt/openocd/share/openocd/scripts
OPENOCD_CFG_DIR := /opt/openocd
SWD_CFG := /home/arduino/QRB2210_swd.cfg
STM32_CFG := /opt/openocd/stm32u5x.cfg
REMOTE_ELF := /home/arduino/zephyr.elf

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

.PHONY: all build flash clean shell docker-build help check-docker check-adb

# Default target
all: build flash

# Help target
help:
	@echo "$(CYAN)Arduino Libraries Rust$(NC)"
	@echo ""
	@echo "$(GREEN)Quick Start:$(NC)"
	@echo "  make build       - Build the LED matrix demo in Docker"
	@echo "  make flash       - Flash the demo to the board"
	@echo "  make all         - Build and flash (default)"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make shell       - Open a shell in the Docker container"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make distclean   - Remove build artifacts and Docker image"
	@echo ""
	@echo "$(GREEN)Setup:$(NC)"
	@echo "  make docker-build - Rebuild the Docker image"
	@echo "  make setup-swd    - Copy SWD config to board (first-time)"
	@echo ""
	@echo "$(GREEN)Board Access:$(NC)"
	@echo "  make shell-board  - Open ADB shell to board"
	@echo ""
	@echo "$(YELLOW)Requirements:$(NC)"
	@echo "  - Docker (for building)"
	@echo "  - ADB (for flashing): brew install android-platform-tools"

# Check if Docker is available
check-docker:
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Error: Docker is not installed$(NC)"; exit 1; }

# Check if ADB is available
check-adb:
	@command -v adb >/dev/null 2>&1 || { echo "$(RED)Error: ADB is not installed. Install via: brew install android-platform-tools$(NC)"; exit 1; }
	@adb devices | grep -q "device$$" || { echo "$(RED)Error: No ADB device found. Connect the Arduino Uno Q via USB.$(NC)"; exit 1; }

# Build the Docker image
docker-build: check-docker
	@echo "$(CYAN)Building Docker image...$(NC)"
	docker build -t $(IMAGE_NAME) -f $(DOCKER_DIR)/Dockerfile $(DOCKER_DIR)
	@echo "$(GREEN)Docker image built successfully$(NC)"

# Ensure Docker image exists
.docker-image-built: $(DOCKER_DIR)/Dockerfile
	@$(MAKE) docker-build
	@touch .docker-image-built

# Build the application
build: check-docker .docker-image-built
	@echo "$(CYAN)Building LED matrix demo in Docker...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	docker run --rm \
		-v "$$(pwd)/arduino-led-matrix:/app-lib:ro" \
		-v "$$(pwd)/$(APP_DIR):/app:ro" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash -c '\
			set -e && \
			echo "Copying app source..." && \
			cp -r /app /tmp/app && \
			mkdir -p /tmp/app/arduino-led-matrix && \
			cp -r /app-lib/* /tmp/app/arduino-led-matrix/ && \
			sed -i "s|path = \"../../arduino-led-matrix\"|path = \"arduino-led-matrix\"|" /tmp/app/Cargo.toml && \
			echo "Configuring build..." && \
			west build -p auto -b $(BOARD) /tmp/app -d /tmp/build && \
			echo "Copying artifacts..." && \
			cp /tmp/build/zephyr/zephyr.elf /output/ && \
			cp /tmp/build/zephyr/zephyr.bin /output/ 2>/dev/null || true && \
			cp /tmp/build/zephyr/zephyr.hex /output/ 2>/dev/null || true && \
			echo "Build artifacts:" && \
			ls -la /output/ \
		'
	@echo "$(GREEN)Build complete! Artifacts in $(OUTPUT_DIR)/$(NC)"

# Flash the application
flash: check-adb
	@echo "$(CYAN)Flashing LED matrix demo to Arduino Uno Q...$(NC)"
	@test -f $(OUTPUT_DIR)/zephyr.elf || { echo "$(RED)Error: No firmware found. Run 'make build' first.$(NC)"; exit 1; }
	@echo "Pushing firmware to board..."
	adb push $(OUTPUT_DIR)/zephyr.elf $(REMOTE_ELF)
	@echo "Flashing via OpenOCD..."
	adb shell "$(OPENOCD_BIN) \
		-s $(OPENOCD_SCRIPTS) \
		-s $(OPENOCD_CFG_DIR) \
		-f $(SWD_CFG) \
		-f $(STM32_CFG) \
		-c 'program $(REMOTE_ELF) verify reset exit'"
	@echo "$(GREEN)Flash complete!$(NC)"

# Copy SWD configuration to the board (first-time setup)
setup-swd: check-adb
	@echo "$(CYAN)Setting up SWD configuration on board...$(NC)"
	adb push QRB2210_swd.cfg /home/arduino/
	@echo "$(GREEN)SWD configuration uploaded$(NC)"

# Open a shell in the Docker container for debugging
shell: check-docker .docker-image-built
	@echo "$(CYAN)Opening shell in Docker container...$(NC)"
	docker run --rm -it \
		-v "$$(pwd):/workspace" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash

# Quick access to board shell
shell-board: check-adb
	@echo "$(CYAN)Opening ADB shell to Arduino Uno Q...$(NC)"
	adb shell

# Clean build artifacts
clean:
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	rm -rf $(OUTPUT_DIR)
	rm -rf $(BUILD_DIR)
	rm -f .docker-image-built
	@echo "$(GREEN)Clean complete$(NC)"

# Clean everything including Docker image
distclean: clean
	@echo "$(CYAN)Removing Docker image...$(NC)"
	-docker rmi $(IMAGE_NAME) 2>/dev/null || true
	@echo "$(GREEN)Distclean complete$(NC)"
