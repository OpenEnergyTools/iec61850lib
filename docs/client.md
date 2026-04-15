# Client API

The `client` module provides an async, protocol-agnostic IEC 61850 client.
It wraps the transport layer (currently MMS/TCP) behind a `Client` struct that exposes
the IEC 61850 services as plain Rust async methods.

## Table of Contents

- [Connecting](#connecting)
- [Data Access](#data-access)
- [Report Control Blocks](#report-control-blocks)
- [Control Services](#control-services)
- [Error Handling](#error-handling)
- [Reference Types](#reference-types)

---

## Connecting

Use `ClientBuilder` to configure and establish a connection.

```rust
use iec_61850_lib::client::{ClientBuilder, Protocol};
use std::time::Duration;

let client = ClientBuilder::new()
    .protocol(Protocol::Mms)
    .timeout(Duration::from_secs(5))
    .connect("192.168.1.10", 102)
    .await?;
```

### `ClientBuilder` methods

| Method | Description |
|--------|-------------|
| `ClientBuilder::new()` | Create a builder with defaults (MMS, 10 s timeout, no TLS). |
| `.protocol(Protocol)` | Select the transport protocol. Only `Protocol::Mms` is available. |
| `.timeout(Duration)` | Set the connection timeout. Default is 10 seconds. |
| `.connect(host, port)` | Async — establishes the connection and returns a `Client`. |

**TLS** can be enabled by providing a `TLSConfig` (from the `mms` crate) before calling
`.connect()`.

---

## Data Access

### `get_server_directory`

Returns the names of all logical devices published by the server.

```rust
let lds: Vec<String> = client.get_server_directory().await?;
// e.g. ["IED1LD", "IED1CTRL"]
```

### `get_logical_device_directory`

Returns the logical node names within a logical device.

```rust
let lns: Vec<String> = client
    .get_logical_device_directory("IED1LD".to_string())
    .await?;
// e.g. ["IED1LD/LLN0", "IED1LD/XCBR1"]
```

### `get_data_values`

Reads one or more data attributes in a single request.
Each item in the input `Vec` is a [`DataReference`](#datareference) that
pairs a dot-path reference with a function constraint.

```rust
use iec_61850_lib::client::DataReference;

let refs = vec![
    DataReference { reference: "IED1LD/XCBR1.Pos".to_string(), fc: "ST".to_string() },
    DataReference { reference: "IED1LD/MMXU1.A.phsA".to_string(), fc: "MX".to_string() },
];

let values: Vec<IECData> = client.get_data_values(refs).await?;
```

The returned `Vec` is positionally aligned with the input slice.

### `get_data_definition`

Retrieves the structural schema (type tree) for a data attribute.
Useful for understanding the shape of a value before reading it.

```rust
use iec_61850_lib::client::DataReference;

let def = client
    .get_data_definition(DataReference {
        reference: "IED1LD/XCBR1.Pos".to_string(),
        fc: "ST".to_string(),
    })
    .await?;

println!("{}: {:?}", def.name, def.data_type);
```

---

## Report Control Blocks

IEC 61850 uses Report Control Blocks (RCBs) to push data changes to clients.
There are two kinds:

- **BRCB** (Buffered) — buffers entries while the client is disconnected.
- **URCB** (Unbuffered) — discards entries when the client is not actively subscribed.

### Reading RCB attributes

```rust
// Buffered RCB
let brcb = client.get_brcb_values("IED1LD/LLN0.BRCB01".to_string()).await?;
println!("RptEna: {}, BufTm: {} ms", brcb.rpt_ena, brcb.buf_tm);

// Unbuffered RCB
let urcb = client.get_urcb_values("IED1LD/LLN0.URCB01".to_string()).await?;
println!("Reserved: {}", urcb.resv);
```

### Writing RCB attributes

Only pass the fields you want to change; all others are `None`.

```rust
use iec_61850_lib::types::{SetBrcbValuesSettings, TriggerOptions};

let settings = SetBrcbValuesSettings {
    rpt_ena: Some(true),
    buf_tm: Some(0),
    gi: Some(true),
    ..Default::default()
};

let results = client
    .set_brcb_values("IED1LD/LLN0.BRCB01".to_string(), settings)
    .await?;

// Each element corresponds to one attribute write
for r in results {
    if let Err(e) = r {
        eprintln!("Attribute write failed: {e}");
    }
}
```

`SetUrcbValuesSettings` works identically for unbuffered RCBs:

```rust
use iec_61850_lib::types::SetUrcbValuesSettings;

let settings = SetUrcbValuesSettings {
    resv: Some(true),
    rpt_ena: Some(true),
    ..Default::default()
};

client.set_urcb_values("IED1LD/LLN0.URCB01".to_string(), settings).await?;
```

### Receiving reports

`subscribe_reports` returns a `tokio::sync::mpsc::Receiver<Report>`.
The subscription stays active until the receiver is dropped.

```rust
use iec_61850_lib::types::ReportType;

let mut rx = client.subscribe_reports(
    "IED1LD/LLN0.BRCB01".to_string(),
    "IED1LD/LLN0.BRCB01".to_string(), // RptID
    ReportType::Buffered,
);

while let Some(report) = rx.recv().await {
    println!("Report seq={:?}", report.metadata.seq_num);
    for point in &report.data {
        println!("  {:?} = {:?}", point.data_reference, point.value);
    }
}
```

**Subscribe before enabling** — call `subscribe_reports` before writing
`rpt_ena = true` to the RCB so that no reports are missed.

---

## Control Services

### `select`

Selects a controllable object without providing a value (classic SBO).

```rust
client.select("IED1LD/CSWI1.Pos".to_string()).await?;
```

### `select_with_value`

Selects a controllable object and provides the intended value upfront, allowing
the device to validate it before the operate step.

```rust
use iec_61850_lib::types::{ControlObject, CtlVal, Originator, Check, Timestamp};

let ctrl = ControlObject {
    ctrl_obj_ref: "IED1LD/CSWI1.Pos".to_string(),
    ctl_val: CtlVal::Bool(true),
    oper_tm: None,
    origin: Originator::default(),
    ctl_num: 1,
    t: Timestamp { seconds: 0, fraction: 0, quality: Default::default() },
    test: false,
    check: Check::default(),
};

let response = client.select_with_value(ctrl).await?;
if response.add_cause.is_some() {
    eprintln!("Select rejected: {:?}", response.add_cause);
}
```

### `operate`

Executes the control action. For SBO, call `select` (or `select_with_value`) first.

```rust
use iec_61850_lib::types::{ControlObject, CtlVal, Originator, Check, Timestamp};

let ctrl = ControlObject {
    ctrl_obj_ref: "IED1LD/CSWI1.Pos".to_string(),
    ctl_val: CtlVal::Bool(true),
    oper_tm: None,
    origin: Originator::default(),
    ctl_num: 1,
    t: Timestamp { seconds: 0, fraction: 0, quality: Default::default() },
    test: false,
    check: Check::default(),
};

let response = client.operate(ctrl).await?;
match response.add_cause {
    None => println!("Operate accepted"),
    Some(cause) => eprintln!("Operate rejected: {:?}", cause),
}
```

### `cancel`

Cancels a pending select or operate.

```rust
use iec_61850_lib::types::{CancelObject, CtlVal, Originator, Timestamp};

let cancel = CancelObject {
    ctrl_obj_ref: "IED1LD/CSWI1.Pos".to_string(),
    ctl_val: CtlVal::Bool(true),
    oper_tm: None,
    origin: Originator::default(),
    ctl_num: 1,
    t: Timestamp { seconds: 0, fraction: 0, quality: Default::default() },
    test: false,
};

let response = client.cancel(cancel).await?;
```

### `subscribe_command_termination`

IEC 61850 devices send a **CommandTermination** report asynchronously after
executing (or rejecting) a control action.

Call this **before** `operate` to guarantee you receive it even for very fast devices.

```rust
let ctrl_obj_ref = "IED1LD/CSWI1.Pos".to_string();

let mut ct_rx = client.subscribe_command_termination(ctrl_obj_ref.clone());

client.operate(/* ... */).await?;

match ct_rx.recv().await {
    Some(Ok(response)) => println!("Command terminated: {:?}", response.add_cause),
    Some(Err(e)) => eprintln!("Command termination error: {e}"),
    None => eprintln!("Channel closed before CommandTermination arrived"),
}
```

---

## Error Handling

All fallible methods return `Result<_, client::Error>`. BUT error mapping is not done acc. to IEC 61850. This is still be be done and the API here will definitely change.

```rust
use iec_61850_lib::client::Error;

match client.get_server_directory().await {
    Ok(lds) => println!("{:?}", lds),
    Err(Error::ConnectionFailed(msg)) => eprintln!("Lost connection: {msg}"),
    Err(Error::DataAccessError(code)) => eprintln!("Server refused access (code {code})"),
    Err(Error::ParseError(msg)) => eprintln!("Could not decode server response: {msg}"),
}
```

| Variant | When it occurs |
|---------|----------------|
| `ConnectionFailed(String)` | TCP/TLS handshake failed or the connection was lost. |
| `DataAccessError(u8)` | The server returned an MMS `object-access-denied` error. |
| `ParseError(String)` | The library could not decode the server's response. |

---

## Reference Types

### `DataReference`

Identifies a single data attribute on the server.

| Field | Type | Description |
|-------|------|-------------|
| `reference` | `String` | Dot-separated IEC 61850 path, e.g. `"IED1LD/XCBR1.Pos"` |
| `fc` | `String` | Function constraint, e.g. `"ST"` (status), `"MX"` (measured value), `"CO"` (control), `"CF"` (configuration) |

Common function constraints:

| FC | Meaning |
|----|---------|
| `ST` | Status |
| `MX` | Measured value |
| `CO` | Control |
| `CF` | Configuration |
| `DC` | Description |
| `SP` | Set point |
| `SV` | Substitution |
| `SE` | Setting group editable |
| `SG` | Setting group |
| `EX` | Extended |
