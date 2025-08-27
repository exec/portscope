.PHONY: build release install uninstall clean test

# Build debug version
build:
	cargo build

# Build optimized release version
release:
	cargo build --release

# Install to system
install: release
	./install.sh

# Uninstall from system
uninstall:
	./uninstall.sh

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Run with example arguments
run-example: build
	cargo run -- --target 127.0.0.1 --ports common

# Create distributable package
dist: release
	mkdir -p dist
	cp target/release/portscan dist/
	cp README.md dist/
	cp install.sh dist/
	cp uninstall.sh dist/
	tar -czf portscan-rs-$(shell cargo pkgid | cut -d# -f2).tar.gz -C dist .
	rm -rf dist

# Format code
fmt:
	cargo fmt

# Run linter
lint:
	cargo clippy -- -D warnings