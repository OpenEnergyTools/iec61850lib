# GOOSE Sniffer

The GOOSE Sniffer (`ws_goose_rx.rs`) is a WebSocket server that listens for IEC 61850 GOOSE messages on a specified network interface and streams the decoded messages to connected WebSocket clients in real time.

## How It Works

- **Network Listening:**  
  The sniffer uses the `pnet` crate to capture Ethernet frames on the specified network interface. It continuously listens for incoming packets.

- **GOOSE Decoding:**  
  For each received Ethernet frame, the sniffer checks if it is a GOOSE message. If so, it decodes both the Ethernet header and the GOOSE PDU using the library's decoding functions.

- **WebSocket Broadcasting:**  
  Decoded GOOSE messages are serialized as JSON and sent to all connected WebSocket clients using the `warp` web framework. Each client receives a JSON object containing both the Ethernet header and the decoded GOOSE PDU fields.

- **Concurrency:**  
  The implementation uses asynchronous channels (`tokio::mpsc` and `tokio::broadcast`) to efficiently forward decoded messages from the packet listener to all WebSocket clients.

## How to Start the Sniffer

Run the following command from the project root:

```sh
cargo run --bin ws_goose_rx <interface_name> [port]

```

## Sending Message
 
The information is decoded into a JSON looking like so:

```json
{
  "header": {
    "srcAddr": [ 1,12,205,1,0,0 ],
    "dstAddr": [ 123,112,205,1,0,245 ],
    "tpid": ...,
    "tci": ...,
    "etherType": ...,
    "appID": ...,
    "length": ...
  },
  "pdu": {
    "goCbRef": "...",
    "timeAllowedToLive": ...,
    "goID": "...",
    "t": [...],                 //encoded as a 8 byte array
    "datSet": "...",
    "stNum": ...,
    "sqNum": ...,
    "simulation": ...,
    "confRev": ...,
    "ndsCom": ...,
    "numDatSetEntries": ...,
    "allData": [ 
        {
            "Structure": [
                {
                    "Structure": [
                        {
                            "Float32": 0
                        }
                    ]
                },
                {
                    "Structure": [
                        {
                            "Float32": 0
                        }
                    ]
                }
            ]
        },
        {
            "Structure": [
                {
                    "Float32": 0
                }
            ]
        },
        {
            "Float32": 0
        }
     ]
  }
}
```