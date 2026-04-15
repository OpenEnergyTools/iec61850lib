# Sampled Values (SMV) API

The `encode_smv` and `decode_smv` modules implement IEC 61850-9-2 LE Sampled Values
encoding and decoding over raw Ethernet frames. The encoder uses zero-copy techniques
with exact buffer preallocation for high-throughput use cases.

## Table of Contents

- [Encoding](#encoding)
- [Decoding](#decoding)
- [Types](#types)

---

## Encoding

`encode_smv` takes an `EthernetHeader` and a `SavPdu` and returns a complete
Ethernet frame as `Vec<u8>`.

```rust
use iec_61850_lib::encode_smv::encode_smv;
use iec_61850_lib::types::{EthernetHeader, SavPdu, SavAsdu, Sample};

let header = EthernetHeader {
    dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
    src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    tpid: None,
    tci: None,
    ether_type: [0x88, 0xba],  // SMV EtherType
    appid: [0x40, 0x00],
    length: [0x00, 0x00],
};

let asdu = SavAsdu {
    msv_id: "AA1E1Q01BCLD1/LLN0.dataSetName".to_string(),
    dat_set: None,
    smp_cnt: 0,
    conf_rev: 1,
    refr_tm: None,
    smp_synch: 0,
    smp_rate: Some(4800),
    all_data: vec![
        Sample::new(1000, 0),
        Sample::new(2000, 0),
        Sample::new(3000, 0),
    ],
    smp_mod: None,
    gm_identity: None,
};

let pdu = SavPdu {
    sim: false,
    no_asdu: 1,
    sav_asdu: vec![asdu],
    security: None,
};

match encode_smv(&header, &pdu) {
    Ok(frame) => println!("Encoded SMV frame: {} bytes", frame.len()),
    Err(e) => eprintln!("Encoding failed: {:?}", e),
}
```

---

## Decoding

`decode_smv` parses a `SavPdu` from a raw Ethernet frame. Use
`decode_ethernet_header` first to obtain the byte offset where the PDU begins.

```rust
use iec_61850_lib::decode_smv::decode_smv;
use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::types::EthernetHeader;

let packet: &[u8] = &[/* raw bytes from network */];

let mut header = EthernetHeader::default();
let pos = decode_ethernet_header(&mut header, packet);

match decode_smv(packet, pos) {
    Ok(pdu) => {
        println!("Number of ASDUs: {}", pdu.no_asdu);
        for asdu in &pdu.sav_asdu {
            println!("SV ID: {}", asdu.msv_id);
            println!("Sample count: {}", asdu.smp_cnt);
            for (i, sample) in asdu.all_data.iter().enumerate() {
                println!("  Sample {}: value={}, good={}", i, sample.value, sample.quality.is_good());
            }
        }
    }
    Err(e) => eprintln!("Decoding failed: {:?}", e),
}
```

---

## Types

### `SavPdu`

| Field | Type | Description |
|-------|------|-------------|
| `sim` | `bool` | Simulation mode flag |
| `no_asdu` | `u8` | Number of ASDUs in this PDU |
| `sav_asdu` | `Vec<SavAsdu>` | List of ASDUs |
| `security` | `Option<Vec<u8>>` | Optional security extension |

### `SavAsdu`

| Field | Type | Description |
|-------|------|-------------|
| `msv_id` | `String` | Multicast SV identifier |
| `dat_set` | `Option<String>` | Dataset reference |
| `smp_cnt` | `u16` | Sample counter |
| `conf_rev` | `u32` | Configuration revision |
| `refr_tm` | `Option<Timestamp>` | Refresh time |
| `smp_synch` | `u8` | Synchronisation source (`0` = none, `1` = local, `2` = global) |
| `smp_rate` | `Option<u16>` | Nominal sample rate (samples/second) |
| `all_data` | `Vec<Sample>` | Encoded sample values |
| `smp_mod` | `Option<u16>` | Sample mode |
| `gm_identity` | `Option<Vec<u8>>` | IEEE 1588 grandmaster identity |

### `Sample`

Each `Sample` carries a 32-bit integer value and a 32-bit quality word.

```rust
let s = Sample::new(1000, 0);   // value = 1000, quality = Good
```

`sample.quality.is_good()` returns `true` when no quality bits are set.

### Performance

SMV encoding uses zero-copy preallocation, achieving **3–4× improvement** over naive implementations:

| Scenario | Encoding | Decoding | Round-trip |
|----------|----------|----------|------------|
| 1 ASDU × 8 samples | ~418 ns | ~235 ns | ~757 ns |
| 8 ASDUs × 12 samples | ~4.35 µs | ~2.37 µs | ~7.22 µs |
| 8 ASDUs × 32 samples | ~10.98 µs | ~4.20 µs | ~15.80 µs |

See [benchmarking documentation](benchmarking.md) for methodology and hardware details.
