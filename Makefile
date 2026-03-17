# Makefile for Arduino Libraries Rust
#
# This Makefile provides a Docker-based workflow for building and flashing
# Rust applications for Arduino Uno Q.
#
# Quick Start:
#   make build              - Build the default demo (led-matrix)
#   make build APP=rpc      - Build the RPC demo
#   make flash              - Flash to the board
#   make all                - Build and flash
#
# Linux Apps (run on QRB2210 MPU):
#   make build-linux APP=weather-display  - Build Linux app
#   make deploy-linux APP=weather-display - Deploy to board
#   make run-linux APP=weather-display    - Run on board
#
# Available Apps:
#   led-matrix (default)    - LED matrix demo
#   rpc                     - RPC bridge demo
#
# Requirements:
#   - Docker (for building MCU firmware)
#   - cargo-zigbuild (for building Linux apps)
#   - ADB or SSH (for flashing/deploying)

# Configuration
IMAGE_NAME := arduino-uno-q-rust
DOCKER_DIR := docker
BUILD_DIR := build
OUTPUT_DIR := output

# Default app to build (can override with APP=rpc)
APP ?= led-matrix

# Board connection settings (can override with environment variables)
BOARD_IP ?= 192.168.1.199
BOARD_USER ?= arduino
BOARD_PASS ?= password

# Linux app configuration
LINUX_TARGET := aarch64-unknown-linux-gnu

# Map app names to directories and libraries
ifeq ($(APP),led-matrix)
    APP_DIR := examples/led-matrix-demo
    LIB_NAME := arduino-led-matrix
    LIB_PATH_PATTERN := ../../arduino-led-matrix
    MULTI_LIB :=
else ifeq ($(APP),rpc)
    APP_DIR := examples/rpc-demo
    LIB_NAME := arduino-rpc-bridge
    LIB_PATH_PATTERN := ../../arduino-rpc-bridge
    MULTI_LIB :=
else ifeq ($(APP),spi-test)
    APP_DIR := examples/spi-test
    LIB_NAME :=
    LIB_PATH_PATTERN :=
    MULTI_LIB :=
else ifeq ($(APP),rpc-server)
    APP_DIR := examples/rpc-server
    LIB_NAME := arduino-led-matrix arduino-rpc-bridge
    LIB_PATH_PATTERN := ../../arduino-led-matrix ../../arduino-rpc-bridge
    MULTI_LIB := yes
else ifeq ($(APP),mlkem-demo)
    APP_DIR := examples/mlkem-demo
    LIB_NAME := arduino-led-matrix arduino-rpc-bridge arduino-cryptography
    LIB_PATH_PATTERN := ../../arduino-led-matrix ../../arduino-rpc-bridge ../../arduino-cryptography
    MULTI_LIB := yes
else ifeq ($(APP),pqc-demo)
    APP_DIR := examples/pqc-demo
    LIB_NAME := arduino-led-matrix arduino-rpc-bridge arduino-cryptography
    LIB_PATH_PATTERN := ../../arduino-led-matrix ../../arduino-rpc-bridge ../../arduino-cryptography
    MULTI_LIB := yes
else ifeq ($(APP),weather-display)
    # Linux app - no MCU build needed
    LINUX_APP := yes
else ifeq ($(APP),spi-router)
    # Linux app - no MCU build needed
    LINUX_APP := yes
else ifeq ($(APP),mlkem-client)
    # Linux app - no MCU build needed
    LINUX_APP := yes
else ifeq ($(APP),pqc-client)
    # Linux app - no MCU build needed
    LINUX_APP := yes
else
    $(error Unknown APP '$(APP)'. MCU apps: led-matrix, rpc, spi-test, rpc-server, mlkem-demo, pqc-demo. Linux apps: weather-display, spi-router, mlkem-client, pqc-client)
endif

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

.PHONY: all build flash clean shell docker-build help check-docker check-adb \
        build-linux deploy-linux run-linux check-zigbuild check-ssh

# Default target
all: build flash

# Help target
help:
	@echo "$(CYAN)Arduino Libraries Rust$(NC)"
	@echo ""
	@echo "$(GREEN)Quick Start (MCU Firmware):$(NC)"
	@echo "  make build              - Build the default demo (led-matrix)"
	@echo "  make build APP=rpc      - Build the RPC demo"
	@echo "  make flash              - Flash to the board"
	@echo "  make all                - Build and flash (default)"
	@echo ""
	@echo "$(GREEN)MCU Apps (run on STM32U585):$(NC)"
	@echo "  led-matrix (default)    - LED matrix demo"
	@echo "  rpc                     - RPC bridge demo (UART)"
	@echo "  spi-test                - SPI communication test"
	@echo "  rpc-server              - RPC server with LED matrix (SPI)"
	@echo ""
	@echo "$(GREEN)Linux Apps (run on QRB2210 MPU):$(NC)"
	@echo "  make build-linux APP=weather-display  - Build Linux app"
	@echo "  make deploy-linux APP=weather-display - Deploy to board"
	@echo "  make run-linux APP=weather-display    - Run on board (once)"
	@echo "  make run-linux APP=weather-display ARGS='--demo' - Run with args"
	@echo ""
	@echo "$(GREEN)SPI Router Setup:$(NC)"
	@echo "  make setup-spi-router   - Build, deploy, and install spi-router service"
	@echo "  make install-spi-router - Install systemd service (after deploy)"
	@echo ""
	@echo "$(GREEN)Available Linux Apps:$(NC)"
	@echo "  weather-display         - Weather display on LED matrix"
	@echo "  spi-router              - SPI router daemon"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make shell              - Open a shell in the Docker container"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make distclean          - Remove build artifacts and Docker image"
	@echo ""
	@echo "$(GREEN)Setup:$(NC)"
	@echo "  make docker-build       - Rebuild the Docker image"
	@echo "  make setup-swd          - Copy SWD config to board (first-time)"
	@echo ""
	@echo "$(GREEN)Board Access:$(NC)"
	@echo "  make shell-board        - Open ADB shell to board"
	@echo "  make ssh-board          - SSH to board"
	@echo ""
	@echo "$(YELLOW)Requirements:$(NC)"
	@echo "  - Docker (for building MCU firmware)"
	@echo "  - cargo-zigbuild (for Linux apps): cargo install cargo-zigbuild"
	@echo "  - ADB (for flashing): brew install android-platform-tools"
	@echo "  - sshpass (for SSH deploy): brew install hudochenkov/sshpass/sshpass"

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
	@echo "$(CYAN)Building $(APP) in Docker...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
ifeq ($(LIB_NAME),)
	docker run --rm \
		-v "$$(pwd)/$(APP_DIR):/app:ro" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash -c '\
			set -e && \
			echo "Copying app source..." && \
			cp -r /app /tmp/app && \
			echo "Configuring build..." && \
			west build -p auto -b $(BOARD) /tmp/app -d /tmp/build && \
			echo "Copying artifacts..." && \
			cp /tmp/build/zephyr/zephyr.elf /output/ && \
			cp /tmp/build/zephyr/zephyr.bin /output/ 2>/dev/null || true && \
			cp /tmp/build/zephyr/zephyr.hex /output/ 2>/dev/null || true && \
			echo "Build artifacts:" && \
			ls -la /output/ \
		'
else ifeq ($(MULTI_LIB),yes)
	docker run --rm \
		-v "$$(pwd)/arduino-led-matrix:/lib-led-matrix:ro" \
		-v "$$(pwd)/arduino-rpc-bridge:/lib-rpc-bridge:ro" \
		-v "$$(pwd)/arduino-cryptography:/lib-cryptography:ro" \
		-v "$$(pwd)/$(APP_DIR):/app:ro" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash -c '\
			set -e && \
			echo "Copying app source..." && \
			cp -r /app /tmp/app && \
			echo "Copying libraries..." && \
			mkdir -p /tmp/app/arduino-led-matrix && \
			mkdir -p /tmp/app/arduino-rpc-bridge && \
			mkdir -p /tmp/app/arduino-cryptography && \
			cp -r /lib-led-matrix/* /tmp/app/arduino-led-matrix/ && \
			cp -r /lib-rpc-bridge/* /tmp/app/arduino-rpc-bridge/ && \
			if [ -d /lib-cryptography ]; then cp -r /lib-cryptography/* /tmp/app/arduino-cryptography/ 2>/dev/null || true; fi && \
			sed -i "s|path = \"../../arduino-led-matrix\"|path = \"arduino-led-matrix\"|" /tmp/app/Cargo.toml && \
			sed -i "s|path = \"../../arduino-rpc-bridge\"|path = \"arduino-rpc-bridge\"|" /tmp/app/Cargo.toml && \
			sed -i "s|path = \"../../arduino-cryptography\"|path = \"arduino-cryptography\"|" /tmp/app/Cargo.toml 2>/dev/null || true && \
			echo "Configuring build..." && \
			west build -p auto -b $(BOARD) /tmp/app -d /tmp/build && \
			echo "Copying artifacts..." && \
			cp /tmp/build/zephyr/zephyr.elf /output/ && \
			cp /tmp/build/zephyr/zephyr.bin /output/ 2>/dev/null || true && \
			cp /tmp/build/zephyr/zephyr.hex /output/ 2>/dev/null || true && \
			echo "Build artifacts:" && \
			ls -la /output/ \
		'
else
	docker run --rm \
		-v "$$(pwd)/$(LIB_NAME):/app-lib:ro" \
		-v "$$(pwd)/$(APP_DIR):/app:ro" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash -c '\
			set -e && \
			echo "Copying app source..." && \
			cp -r /app /tmp/app && \
			mkdir -p /tmp/app/$(LIB_NAME) && \
			cp -r /app-lib/* /tmp/app/$(LIB_NAME)/ && \
			sed -i "s|path = \"$(LIB_PATH_PATTERN)\"|path = \"$(LIB_NAME)\"|" /tmp/app/Cargo.toml && \
			echo "Configuring build..." && \
			west build -p auto -b $(BOARD) /tmp/app -d /tmp/build && \
			echo "Copying artifacts..." && \
			cp /tmp/build/zephyr/zephyr.elf /output/ && \
			cp /tmp/build/zephyr/zephyr.bin /output/ 2>/dev/null || true && \
			cp /tmp/build/zephyr/zephyr.hex /output/ 2>/dev/null || true && \
			echo "Build artifacts:" && \
			ls -la /output/ \
		'
endif
	@echo "$(GREEN)Build complete! Artifacts in $(OUTPUT_DIR)/$(NC)"

# Flash the application
flash: check-adb
	@echo "$(CYAN)Flashing $(APP) demo to Arduino Uno Q...$(NC)"
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

# =============================================================================
# Linux App Targets (for QRB2210 MPU)
# =============================================================================

# Check if cargo-zigbuild is available
check-zigbuild:
	@command -v cargo-zigbuild >/dev/null 2>&1 || { echo "$(RED)Error: cargo-zigbuild is not installed. Install via: cargo install cargo-zigbuild$(NC)"; exit 1; }

# Check if sshpass is available for SSH operations
check-ssh:
	@command -v sshpass >/dev/null 2>&1 || { echo "$(RED)Error: sshpass is not installed. Install via: brew install hudochenkov/sshpass/sshpass$(NC)"; exit 1; }

# Build a Linux application for aarch64
build-linux: check-zigbuild
	@echo "$(CYAN)Building Linux app: $(APP)...$(NC)"
ifeq ($(APP),weather-display)
	cd examples/weather-display && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: examples/weather-display/target/$(LINUX_TARGET)/release/weather-display$(NC)"
else ifeq ($(APP),spi-router)
	cd arduino-spi-router && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: arduino-spi-router/target/$(LINUX_TARGET)/release/spi-router$(NC)"
else ifeq ($(APP),mlkem-client)
	cd examples/mlkem-client && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: examples/mlkem-client/target/$(LINUX_TARGET)/release/mlkem-client$(NC)"
else ifeq ($(APP),pqc-client)
	cd examples/pqc-client && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: examples/pqc-client/target/$(LINUX_TARGET)/release/pqc-client$(NC)"
else
	$(error Unknown Linux APP '$(APP)'. Use APP=weather-display, APP=spi-router, APP=mlkem-client, or APP=pqc-client)
endif

# Deploy a Linux application to the board
deploy-linux: check-ssh
	@echo "$(CYAN)Deploying $(APP) to board...$(NC)"
ifeq ($(APP),weather-display)
	@test -f examples/weather-display/target/$(LINUX_TARGET)/release/weather-display || { echo "$(RED)Error: Binary not found. Run 'make build-linux APP=weather-display' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp examples/weather-display/target/$(LINUX_TARGET)/release/weather-display $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/weather-display$(NC)"
else ifeq ($(APP),spi-router)
	@test -f arduino-spi-router/target/$(LINUX_TARGET)/release/spi-router || { echo "$(RED)Error: Binary not found. Run 'make build-linux APP=spi-router' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp arduino-spi-router/target/$(LINUX_TARGET)/release/spi-router $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/spi-router$(NC)"
else ifeq ($(APP),mlkem-client)
	@test -f examples/mlkem-client/target/$(LINUX_TARGET)/release/mlkem-client || { echo "$(RED)Error: Binary not found. Run 'make build-linux APP=mlkem-client' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp examples/mlkem-client/target/$(LINUX_TARGET)/release/mlkem-client $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/mlkem-client$(NC)"
else ifeq ($(APP),pqc-client)
	@test -f examples/pqc-client/target/$(LINUX_TARGET)/release/pqc-client || { echo "$(RED)Error: Binary not found. Run 'make build-linux APP=pqc-client' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp examples/pqc-client/target/$(LINUX_TARGET)/release/pqc-client $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/pqc-client$(NC)"
else
	$(error Unknown Linux APP '$(APP)'. Use APP=weather-display, APP=spi-router, APP=mlkem-client, or APP=pqc-client)
endif

# Run a Linux application on the board
ARGS ?= --once
run-linux: check-ssh
	@echo "$(CYAN)Running $(APP) on board...$(NC)"
ifeq ($(APP),weather-display)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "RUST_LOG=info /home/$(BOARD_USER)/weather-display $(ARGS)"
else ifeq ($(APP),mlkem-client)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "RUST_LOG=info /home/$(BOARD_USER)/mlkem-client $(ARGS)"
else ifeq ($(APP),pqc-client)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "RUST_LOG=info /home/$(BOARD_USER)/pqc-client $(ARGS)"
else
	$(error Unknown Linux APP '$(APP)' for run-linux. Use APP=weather-display, APP=mlkem-client, or APP=pqc-client)
endif

# Build and deploy Linux app in one step
all-linux: build-linux deploy-linux
	@echo "$(GREEN)Linux app $(APP) built and deployed$(NC)"

# Install spi-router as a systemd service (requires deploy-linux APP=spi-router first)
install-spi-router: check-ssh
	@echo "$(CYAN)Installing spi-router systemd service...$(NC)"
	@test -f arduino-spi-router/arduino-spi-router.service || { echo "$(RED)Error: Service file not found$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp arduino-spi-router/arduino-spi-router.service $(BOARD_USER)@$(BOARD_IP):/tmp/
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S cp /tmp/arduino-spi-router.service /etc/systemd/system/ && \
		echo '$(BOARD_PASS)' | sudo -S systemctl daemon-reload && \
		echo '$(BOARD_PASS)' | sudo -S systemctl enable arduino-spi-router && \
		echo '$(BOARD_PASS)' | sudo -S systemctl restart arduino-spi-router && \
		sleep 2 && \
		systemctl status arduino-spi-router --no-pager"
	@echo "$(GREEN)spi-router service installed and started$(NC)"

# Setup spi-router completely (build, deploy, install service)
setup-spi-router: check-zigbuild check-ssh
	@echo "$(CYAN)Setting up spi-router...$(NC)"
	$(MAKE) build-linux APP=spi-router
	$(MAKE) deploy-linux APP=spi-router
	$(MAKE) install-spi-router
	@echo "$(GREEN)spi-router setup complete! It will auto-start on boot.$(NC)"

# SSH to board
ssh-board: check-ssh
	@echo "$(CYAN)SSH to Arduino Uno Q...$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP)
