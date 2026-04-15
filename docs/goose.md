# GOOSE API

The `encode_goose` and `decode_goose` modules implement IEC 61850-8-1 GOOSE encoding
and decoding over raw Ethernet frames.

## Table of Contents

- [Encoding](#encoding)
- [Decoding](#decoding)
- [Types](#types)

---

## Encoding

`encode_goose` takes an `EthernetHeader` and an `IECGoosePdu` and returns a complete
Ethernet frame as `Vec<u8>`. The `length` field in the header is set automatically.

```rust
use iec_61850_lib::encode_goose::encode_goose;
use iec_61850_lib::types::{
    EthernetHeader, IECGoosePdu, IECData, TimeQuality, Timestamp,
};

let header = EthernetHeader {
    dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00],
    src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    tpid: Some([0x81, 0x00]),   // VLAN tag (optional)
    tci: Some([0x80, 0x00]),
    ether_type: [0x88, 0xb8],   // GOOSE EtherType
    appid: [0x00, 0x01],
    length: [0x00, 0x00],       // Set automatically
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

match encode_goose(&header, &pdu) {
    Ok(frame) => println!("Encoded GOOSE frame: {} bytes", frame.len()),
    Err(e) => eprintln!("Encoding failed: {:?}", e),
}
```

---

## Decoding

`decode_goose_pdu` parses the GOOSE PDU from a raw Ethernet frame. Use
`decode_ethernet_header` first to obtain the byte offset where the PDU begins.

```rust
use iec_61850_lib::decode_goose::decode_goose_pdu;
use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::types::EthernetHeader;

let packet: &[u8] = &[/* raw bytes from network */];

let mut header = EthernetHeader::default();
let pos = decode_ethernet_header(&mut header, packet);

match decode_goose_pdu(packet, pos) {
    Ok(pdu) => {
        println!("GOOSE ID: {}", pdu.go_id);
        println!("State number: {}", pdu.st_num);
        println!("Sequence number: {}", pdu.sq_num);
        for data in &pdu.all_data {
            println!("  {:?}", data);
        }
    }
    Err(e) => eprintln!("Decoding failed: {:?}", e),
}
```

---

## Types

### `IECGoosePdu`

| Field | Type | Description |
|-------|------|-------------|
| `go_cb_ref` | `String` | GOOSE control block reference |
| `time_allowed_to_live` | `u32` | Maximum time (ms) a receiver should consider this message valid |
| `dat_set` | `String` | Dataset reference |
| `go_id` | `String` | GOOSE identifier |
| `t` | `Timestamp` | Event timestamp |
| `st_num` | `u32` | State number — incremented on data change |
| `sq_num` | `u32` | Sequence number — incremented on every retransmission |
| `simulation` | `bool` | Simulation mode flag |
| `conf_rev` | `u32` | Configuration revision |
| `nds_com` | `bool` | Needs commissioning flag |
| `num_dat_set_entries` | `u32` | Number of entries in `all_data` |
| `all_data` | `Vec<IECData>` | Dataset values |

### `EthernetHeader`

| Field | Type | Description |
|-------|------|-------------|
| `dst_addr` | `[u8; 6]` | Destination MAC address |
| `src_addr` | `[u8; 6]` | Source MAC address |
| `tpid` | `Option<[u8; 2]>` | VLAN tag protocol identifier (`0x81 0x00`), or `None` |
| `tci` | `Option<[u8; 2]>` | VLAN tag control information, or `None` |
| `ether_type` | `[u8; 2]` | EtherType (`0x88 0xB8` for GOOSE) |
| `appid` | `[u8; 2]` | Application identifier |
| `length` | `[u8; 2]` | PDU length (set automatically by the encoder) |

### Performance

GOOSE encoding and decoding use `rasn`, a Rust ASN.1 implementation:

- **Encoding**: ~2–5 µs per message (depending on data complexity)
- **Decoding**: ~1–3 µs per message
- **Round-trip**: ~5–8 µs

See [benchmarking documentation](benchmarking.md) for methodology and hardware details.
