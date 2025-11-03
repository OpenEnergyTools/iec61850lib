# Benchmarking Guide

This document explains how to run and view the different benchmark tests in the project.

## Available Benchmark Suites

### GOOSE Benchmarks
**File**: `benches/goose_codec.rs`

Individual benchmarks:
- `goose_frame_detection` - Detecting GOOSE frames from Ethernet packets
- `ethernet_header_decode` - Decoding Ethernet header (with VLAN support)
- `goose_pdu_decode` - Decoding GOOSE PDU using RASN
- `full_goose_decode` - Complete GOOSE decode (header + PDU)
- `ethernet_header_encode` - Encoding Ethernet header
- `goose_pdu_encode` - Encoding GOOSE PDU using RASN
- `encode_decode_roundtrip` - Full encode → decode cycle
- `goose_with_different_data_sizes` - Tests with 1, 5, 10, 20, 50 data elements
- `goose_packet_rates` - Tests at different rates (50 Hz, 100 Hz, 1000 Hz)

## Running Benchmarks

### Run All Benchmarks
```bash
cargo bench
```

Output location: `target/criterion/report/index.html`

### Run GOOSE Benchmarks
```bash
cargo bench --bench goose_codec
```

### Run a Single Benchmark
```bash
# Run just the GOOSE PDU decode benchmark
cargo bench --bench goose_codec -- goose_pdu_decode

# Run all rate tests
cargo bench -- rates
```

### List Available Benchmarks
```bash
# Show what benchmarks would run without running them
cargo bench -- --list
```

## Viewing Results

### 1. Terminal Output
Criterion prints statistical analysis directly to the terminal:
```
decode_92_le_data       time:   [563.21 ns 567.89 ns 573.45 ns]
                        change: [-2.1234% +0.8123% +3.7891%] (p = 0.45)
```

### 2. HTML Reports
Open the HTML report in your browser:
```bash
open target/criterion/report/index.html
```

The report includes:
- Performance graphs
- Statistical distributions
- Comparison with previous runs
- Detailed measurements

### 3. Individual Benchmark Reports
Each benchmark has its own detailed report:
```bash
open target/criterion/goose_pdu_decode/report/index.html
```

## Quick Performance Tests

For quick performance checks during development, use the unit tests:

```bash
# GOOSE decode performance
cargo test test_goose_decode_performance -- --nocapture --test-threads=1

# GOOSE encode performance
cargo test test_goose_encode_performance -- --nocapture --test-threads=1

# GOOSE roundtrip performance
cargo test test_goose_roundtrip_performance -- --nocapture --test-threads=1
```

These run faster than criterion benchmarks and show simple results:
```
=== GOOSE Decode Performance ===
Iterations: 10000
Total time: 235.123456ms
Average per decode: 23.512 μs
Theoretical max rate: 42513 Hz (42.5 kHz)
```

## Comparing Performance

### Compare Against Baseline
```bash
# Save current performance as baseline
cargo bench -- --save-baseline before_changes

# Make your code changes...

# Compare against baseline
cargo bench -- --baseline before_changes
```

### Filtering Tests
```bash
# Run only GOOSE benchmarks with "decode" in the name
cargo bench --bench goose_codec -- decode

# Run only rate tests
cargo bench -- rates

# Run benchmarks matching a pattern
cargo bench -- "data_size"
```

## Performance Targets

### GOOSE (IEC 61850-8-1)
- **Full decode**: < 1000 μs (1 ms)
- **Target rates**: 50-1000 Hz (20-1 ms between packets)
- **Current performance**: ~24 μs (42 kHz capable)

## Tips

1. **Release build**: Benchmarks automatically use release mode with optimizations
2. **Consistent environment**: Close other applications for consistent results
3. **Warm-up**: Criterion runs warm-up iterations automatically
4. **Statistics**: Results include confidence intervals and outlier detection
5. **Save baselines**: Use `--save-baseline` before making performance changes

## Example Workflow

```bash
# 1. Check current performance
cargo bench

# 2. View HTML report
open target/criterion/report/index.html

# 3. Save baseline before making changes
cargo bench -- --save-baseline before_optimization

# 4. Make your optimizations...

# 5. Compare performance
cargo bench -- --baseline before_optimization

# 6. Check specific benchmark in detail
open target/criterion/goose_pdu_decode/report/index.html
```
