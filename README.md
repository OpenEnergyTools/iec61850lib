
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

## Testing

This library has some example use for a quick start. 
- web socket server implementation running a GOOSE sniffer
   run `./target/debug/ws_goose_rx <ethernet node e.g. eth0>`