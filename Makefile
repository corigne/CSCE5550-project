# Makefile for Attack/Defense Project
# Builds attack binary, monitor, and signature generator

.PHONY: all clean attack monitor siggen help install-deps signatures

# Default target
all: attack monitor monitor-fanotify siggen

# Build the attack binary
attack:
	@echo "Building attack binary..."
	@cd p1_attack && go build -o attack main.go
	@echo "✓ Attack binary built: p1_attack/attack"

# Build the monitor
monitor:
	@echo "Building monitor..."
	@cd p2_monitor_detect_mitigate/monitor && go build -o monitor monitor.go
	@echo "✓ Monitor built: p2_monitor_detect_mitigate/monitor/monitor"

monitor-fanotify:
	@echo "Building fanotify based monitor..."
	@cd p2_monitor_detect_mitigate/monitor_fanotify && go build -o monitor_fanotify monitor_fanotify.go
	@echo "✓ Built monitor_fanotify"

# Build the signature generator
siggen:
	@echo "Building signature generator..."
	@cd p2_monitor_detect_mitigate/signature_generator && go build -o sig_gen signature_generator.go
	@echo "✓ Signature generator built: p2_monitor_detect_mitigate/signature_generator/sig_gen"

# Install Go dependencies for all modules
install-deps:
	@echo "Installing dependencies for p1_attack..."
	@cd p1_attack && go mod download
	@echo "Installing dependencies for monitor..."
	@cd p2_monitor_detect_mitigate/monitor && go mod download
	@echo "Installing dependencies for fanotify monitor..."
	@cd p2_monitor_detect_mitigate/monitor_fanotify && go mod download
	@echo "Installing dependencies for signature_generator..."
	@cd p2_monitor_detect_mitigate/signature_generator && go mod download
	@echo "✓ All dependencies installed"

# Generate signature for attack binary
signatures: attack siggen
	@echo "Generating signature for attack binary..."
	@cd p2_monitor_detect_mitigate/signature_generator && ./sig_gen ../../p1_attack/attack > ../malicious_sigs.txt
	@echo "✓ Signature saved to: p2_monitor_detect_mitigate/malicious_sigs.txt"
	@cat p2_monitor_detect_mitigate/malicious_sigs.txt

# Clean all built binaries
clean:
	@echo "Cleaning build artifacts..."
	@rm -f p1_attack/attack
	@rm -f p2_monitor_detect_mitigate/monitor/monitor
	@rm -f p2_monitor_detect_mitigate/signature_generator/sig_gen
	@rm -f p2_monitor_detect_mitigate/malicious_sigs.txt
	@echo "✓ Clean complete"

# Run the attack (creates encrypt_me if needed)
run-attack:
	@echo "Running attack binary..."
	@cd p1_attack && ./attack

# Run the monitor with signature detection
run-monitor: signatures
	@echo "[AS SUDO] Running monitor with signature detection..."
	@cd p2_monitor_detect_mitigate/monitor && sudo ./monitor -dir=../../p1_attack/encrypt_me -sigs=../malicious_sigs.txt

# Run the monitor using fanotify with signature detection
run-monitor-fanotify: signatures
	@echo "[AS SUDO] Running monitor with signature detection..."
	@cd p2_monitor_detect_mitigate/monitor_fanotify && sudo ./monitor_fanotify -dir=../../p1_attack/encrypt_me -sigs=../malicious_sigs.txt

# Run the monitor without signature detection (directory monitoring only)
run-monitor-basic:
	@if [ "$(id -u)" -ne 0 ]; then \
		echo "Error: This target must be run as root"; \
		echo "Please run: sudo make run-monitor-basic"; \
		exit 1; \
		fi
	@echo "Running monitor (basic directory monitoring)..."
	@cd p2_monitor_detect_mitigate/monitor && ./monitor -dir=../../p1_attack/encrypt_me

# Setup: ensure encrypt_me directory exists
setup:
	@echo "Setting up environment..."
	@mkdir -p p1_attack/encrypt_me
	@echo "✓ Setup complete"

# Build everything and generate signatures
build-all: install-deps all signatures
	@echo ""
	@echo "═══════════════════════════════════════════"
	@echo "Build Summary:"
	@echo "═══════════════════════════════════════════"
	@ls -lh p1_attack/attack 2>/dev/null && echo "✓ Attack binary ready" || echo "✗ Attack binary missing"
	@ls -lh p2_monitor_detect_mitigate/monitor/monitor 2>/dev/null && echo "✓ Monitor ready" || echo "✗ Monitor missing"
	@ls -lh p2_monitor_detect_mitigate/signature_generator/sig_gen 2>/dev/null && echo "✓ Signature generator ready" || echo "✗ Signature generator missing"
	@ls -lh p2_monitor_detect_mitigate/malicious_sigs.txt 2>/dev/null && echo "✓ Signatures file ready" || echo "✗ Signatures file missing"
	@echo "═══════════════════════════════════════════"
	@echo ""
	@echo "Quick Start:"
	@echo "  Terminal 1: sudo make run-monitor"
	@echo "  Terminal 2: make run-attack"
	@echo ""

# Test the full workflow
test: build-all setup
	@echo ""
	@echo "═══════════════════════════════════════════"
	@echo "Test Setup Complete!"
	@echo "═══════════════════════════════════════════"
	@echo ""
	@echo "To test the defense system:"
	@echo "  1. In Terminal 1, run: sudo make run-monitor"
	@echo "  2. In Terminal 2, run: make run-attack"
	@echo ""
	@echo "The monitor should detect and kill the attack process."
	@echo ""

# Help target
help:
	@echo "Attack/Defense Project Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make all              - Build all binaries (default)"
	@echo "  make attack           - Build attack binary only"
	@echo "  make monitor          - Build monitor only"
	@echo "  make siggen           - Build signature generator only"
	@echo "  make install-deps     - Install Go dependencies for all modules"
	@echo "  make signatures       - Generate signature file for attack binary"
	@echo "  make build-all        - Build everything and generate signatures"
	@echo "  make setup            - Create necessary directories"
	@echo "  make test             - Build everything and setup for testing"
	@echo ""
	@echo "Running targets:"
	@echo "  make run-attack       - Execute the attack binary"
	@echo "  sudo make run-monitor - Run monitor with signature detection (MUST use sudo)"
	@echo "  sudo make run-monitor-basic - Run monitor without signatures (MUST use sudo)"
	@echo ""
	@echo "Maintenance targets:"
	@echo "  make clean            - Remove all built binaries"
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Quick workflow:"
	@echo "  make test             - Setup everything"
	@echo "  sudo make run-monitor - Start defender (Terminal 1)"
	@echo "  make run-attack       - Start attack (Terminal 2)"
	@echo ""
