# PortScope Development Guide

## Project Overview

PortScope is an advanced network port scanner with intelligent service detection capabilities. This tool provides professional protocol fingerprinting and adaptive scanning techniques.

## Architecture

### Core Components

- **Scanner Engine**: Multi-threaded scanning with adaptive timing
- **Protocol Detectors**: Modular service detection system
- **Intelligence Engine**: Advanced service classification and identification
- **Output Formatters**: Multiple output formats (human, JSON, XML, CSV)

### Protocol Detection Capabilities

Currently supported protocols with confidence ratings:
- HTTP Services (90% confidence)
- HTTPS/TLS Services (95% confidence) 
- DNS Services (80% confidence)
- SSH Services (85% confidence)
- FTP Services (80% confidence)
- Database Services (PostgreSQL, MongoDB, Redis)
- Various other network protocols

## Development Commands

### Building
```bash
cargo build --release
```

### Testing
```bash
# Basic functionality test
./target/release/portscope 127.0.0.1 -p 80,443

# Network range scanning
./target/release/portscope 192.168.1.0/24

# Service detection with verbose output
./target/release/portscope target -A -v
```

## Code Quality Standards

- Follow Rust best practices and idioms
- Maintain comprehensive error handling
- Include documentation for public APIs
- Use modular architecture for maintainability
- Ensure memory safety and performance optimization