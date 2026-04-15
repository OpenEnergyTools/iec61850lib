
# IEC 61850 Library

A high-performance Rust library for encoding and decoding IEC 61850 GOOSE and Sampled Values (SMV) messages. !The library is under development!


## About The Project

This library provides efficient Rust implementations for IEC 61850-8-1 (GOOSE) and IEC 61850-9-2 LE (Sampled Values) protocols. It features:

- **sampled value encoding**
- **sampled value decoding**
- **GOOSE encoding**
- **GOOSE decoding**

It also gives you most common client functionality:
- **Server discovery**
- **Polling of data values**
- **Reporting**
- **Control capabilities**

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
iec_61850_lib = { git = "https://github.com/OpenEnergyTools/iec61850lib.git" }
```

Or clone and build locally:

```sh
git clone https://github.com/OpenEnergyTools/iec61850lib.git
cd iec61850lib
cargo build --release
```

## Documentation

| Topic | Description |
|-------|-------------|
| [GOOSE](docs/goose.md) | Encoding and decoding IEC 61850-8-1 GOOSE frames |
| [Sampled Values (SMV)](docs/smv.md) | Encoding and decoding IEC 61850-9-2 LE SMV frames |
| [Client](docs/client.md) | Async client: data access, reports, and control services |
| [Benchmarking](docs/benchmarking.md) | Performance analysis and benchmark methodology |

## Running Benchmarks
You can check performance with your hardware:

```sh
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench smv_decode
cargo bench --bench goose_codec
```

## Running Tests

The library includes comprehensive unit tests (68+ tests):

```sh
# Run all tests
cargo test

# Run specific test
cargo test test_roundtrip_extreme_values

# Run with verbose output
cargo test -- --nocapture
```

## Copyright

Copyright © 2025-2026 Jakob Vogelsang. All rights reserved.
