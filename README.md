
# IEC 61850 Library

A high-performance Rust library for encoding and decoding IEC 61850 GOOSE and Sampled Values (SMV) messages. !The library is under development!


## About The Project

This library provides efficient Rust implementations for IEC 61850-8-1 (GOOSE) and IEC 61850-9-2 LE (Sampled Values) protocols. It features:

- **sampled value encoding**
- **sampled value decoding**
- **GOOSE encoding**
- **GOOSE decoding**

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

## Usage

The library exposes four main functions for working with IEC 61850 protocols:

### 1. GOOSE Encoding

Encode a GOOSE PDU with Ethernet header into a complete frame:

```rust
use iec_61850_lib::encode_goose::encode_goose;
use iec_61850_lib::types::{
    EthernetHeader,
    IECGoosePdu,
    IECData,
    TimeQuality,
    Timestamp,
};

let header = EthernetHeader {
    dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00],
    src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    tpid: Some([0x81, 0x00]),              // VLAN tag (optional)
    tci: Some([0x80, 0x00]),
    ether_type: [0x88, 0xb8],              // GOOSE EtherType
    appid: [0x00, 0x01],
    length: [0x00, 0x00],                  // Will be set automatically
};

let timestamp = Timestamp {
    seconds: 1698502245,
    fraction: 2097152,
    quality: TimeQuality {
        leap_second_known: false,
        clock_failure: false,
        clock_not_synchronized: false,
        time_accuracy: 10,
    },
};

// Create GOOSE PDU
let pdu = IECGoosePdu {
    go_cb_ref: "IED1$GO$GoCB01".to_string(),
    time_allowed_to_live: 2000,
    dat_set: "IED1$Dataset1".to_string(),
    go_id: "IED1_GOOSE1".to_string(),
    t: timestamp,
    st_num: 1,
    sq_num: 0,
    simulation: false,
    conf_rev: 1,
    nds_com: false,
    num_dat_set_entries: 2,
    all_data: vec![
        IECData::Boolean(true),
        IECData::Int(12345),
    ],
};

// Encode to complete Ethernet frame
match encode_goose(&header, &pdu) {
    Ok(frame) => {
        println!("Encoded GOOSE frame: {} bytes", frame.len());
        // Send frame to network...
    }
    Err(e) => eprintln!("Encoding failed: {:?}", e),
}
```

### 2. GOOSE Decoding

Decode a GOOSE message from a raw Ethernet frame:

```rust
use iec_61850_lib::decode_goose::decode_goose_pdu;
use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::types::EthernetHeader;

// Raw packet buffer from network
let packet: &[u8] = &[/* ... raw bytes ... */];

// First decode the Ethernet header
let mut header = EthernetHeader::default();
let pos = decode_ethernet_header(&mut header, packet);

// Then decode the GOOSE PDU
match decode_goose_pdu(packet, pos) {
    Ok(pdu) => {
        println!("GOOSE ID: {}", pdu.go_id);
        println!("State Number: {}", pdu.st_num);
        println!("Sequence Number: {}", pdu.sq_num);
        println!("Data entries: {}", pdu.all_data.len());

        // Process data
        for data in &pdu.all_data {
            println!("  {:?}", data);
        }
    }
    Err(e) => eprintln!("Decoding failed: {:?}", e),
}
```

### 3. SMV Encoding

Encode Sampled Values PDU with zero-copy performance:

```rust
use iec_61850_lib::encode_smv::encode_smv;
use iec_61850_lib::types::{EthernetHeader, SavPdu, SavAsdu, Sample};

// Create Ethernet header for SMV
let header = EthernetHeader {
    dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
    src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    tpid: None,
    tci: None,
    ether_type: [0x88, 0xba],  // SMV EtherType
    appid: [0x40, 0x00],
    length: [0x00, 0x00],
};

// Create sample data (8-bit integer samples with quality)
let samples = vec![
    Sample::new(1000, 0),    // value, quality
    Sample::new(2000, 0),
    Sample::new(3000, 0),
];

// Create ASDU
let asdu = SavAsdu {
    msv_id: "AA1E1Q01BCLD1/LLN0.dataSetName".to_string(),
    dat_set: None,
    smp_cnt: 0,
    conf_rev: 1,
    refr_tm: None,
    smp_synch: 0,
    smp_rate: Some(4800),
    all_data: samples,
    smp_mod: None,
    gm_identity: None,
};

// Create SMV PDU
let pdu = SavPdu {
    sim: false,
    no_asdu: 1,
    sav_asdu: vec![asdu],
    security: None,
};

// Encode with zero-copy performance
match encode_smv(&header, &pdu) {
    Ok(frame) => {
        println!("Encoded SMV frame: {} bytes", frame.len());
        // Send frame to network...
    }
    Err(e) => eprintln!("Encoding failed: {:?}", e),
}
```

### 4. SMV Decoding

Decode Sampled Values messages from raw packets:

```rust
use iec_61850_lib::decode_smv::decode_smv;
use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::types::EthernetHeader;

// Raw packet buffer from network
let packet: &[u8] = &[/* ... raw bytes ... */];

// Decode Ethernet header
let mut header = EthernetHeader::default();
let pos = decode_ethernet_header(&mut header, packet);

// Decode SMV PDU
match decode_smv(packet, pos) {
    Ok(pdu) => {
        println!("Number of ASDUs: {}", pdu.no_asdu);

        for asdu in &pdu.sav_asdu {
            println!("SV ID: {}", asdu.msv_id);
            println!("Sample Count: {}", asdu.smp_cnt);
            println!("Number of samples: {}", asdu.all_data.len());

            // Process samples
            for (i, sample) in asdu.all_data.iter().enumerate() {
                println!("  Sample {}: value={}, quality={}",
                         i, sample.value, sample.quality.is_good());
            }
        }
    }
    Err(e) => eprintln!("Decoding failed: {:?}", e),
}
```

## Performance

The library is optimized for high-performance industrial applications:

### GOOSE Performance

GOOSE encoding and decoding use `rasn`, a well-defined Rust implementation of ASN.1:

- **GOOSE Encoding**: ~2-5µs per message (depending on data complexity)
- **GOOSE Decoding**: ~1-3µs per message
- **Round-trip (encode + decode)**: ~5-8µs

### Sampled Values (SMV) Performance

SMV encoding uses zero-copy techniques with exact buffer preallocation, achieving **3-4x performance improvement** over naive implementations:

#### SMV Encoding
- **Small packets (1 ASDU × 8 samples)**: ~418ns
- **Realistic packets (8 ASDUs × 12 samples)**: ~4.35µs
- **Large packets (8 ASDUs × 32 samples)**: ~10.98µs

#### SMV Decoding
- **Small packets (1 ASDU × 8 samples)**: ~235ns
- **Realistic packets (8 ASDUs × 12 samples)**: ~2.37µs
- **Large packets (8 ASDUs × 32 samples)**: ~4.20µs

#### SMV Round-trip (encode + decode)
- **Small packets**: ~757ns
- **Realistic packets**: ~7.22µs
- **Large packets**: ~15.80µs

See [benchmarking documentation](docs/benchmarking.md) for detailed performance analysis.

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

Copyright © 2025 Jakob Vogelsang. All rights reserved.
