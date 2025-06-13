
## About The Project

This project is implementing a RUST based function library that allows you to communicate through services as defined in the IEC 61850. 


## Getting Started



### Installation

1. Clone the repo
   ```sh
      git clone https://github.com/orbitdoc/iec_61850_lib.git
   ```

2. Build Rust packages
   ```sh
      cd iec_61850_lib/
      cargo build
   ```

## Running Unit Tests

This library includes comprehensive unit tests to ensure correctness and robustness of the IEC 61850 decoding and encoding functions.

To run all tests, use:

```sh
cargo test
```

You can run a specific test by name:

```sh
cargo test test_decode_integer
```

Test output will indicate which branches and error conditions are covered.  
If you add new features or bug fixes, please include corresponding unit tests to maintain code quality.

---

## Quick start

This repository also includes two WebSocket-based tools that utilize the functions in this library. They are not **tested** and **shall not be used in production**. They are a means of testing the library and allow a quick start with the library

- <u>**GOOSE Simulator:**</u>

  A WebSocket server that is utilizing GOOSE encoding functions. Connected to a client this could be the basis for a GOOSE simulator or a process interface unit (PUI). [Read more in the GOOSE Simulator documentation.](docs/goose_simulator.md)

- <u>**GOOSE Sniffer:**</u>

  A WebSocket server that listens for and decodes GOOSE messages on the network, providing real-time monitoring and sniffing of GOOSE messages. This could also be the basis for a process interface unit (PUI). [Read more in the GOOSE Sniffer documentation.](docs/goose_sniffer.md)

