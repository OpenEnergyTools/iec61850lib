# GOOSE Simulator

The GOOSE Simulator (/bin/ws_goose_tx.rs) is a WebSocket server that allows clients to simulate IEC 61850 GOOSE messages over the network. This tool is useful for testing, development, and integration of IEC 61850-based systems without requiring real IED hardware.

## How to Start the Server

To start the GOOSE Simulator server, run the following command from the project root:

```sh
cargo run --bin ws_goose_tx <interface_name> [port]
```

- `<interface_name>`: The name of the network interface to send GOOSE messages on (e.g., `en0` on macOS).
- `[port]`: (Optional) The port for the WebSocket server (default is `3030`).

**Example:**
```sh
cargo run --bin ws_goose_tx en0 3030
```

This will start the WebSocket server on `ws://localhost:3030/ws` and begin listening for client connections.

## How to Communicate to the Simulator

A WebSocket client (such as a browser, custom application, or tools like `wscat`) can connect to the simulator's WebSocket endpoint. Once connected, the client can send JSON messages to configure and trigger GOOSE messages.


## Message types
You can send three type of message to the server. 

### Init 

To start the the sending of GOOSE you have to initialize the GOOSE once. This will start the GOOSE repetition stategy and resend the GOOSE with the `max_repetition` [ms]. 


```json
{
    "cmd": "init",
    "config": {
        "dst_addr": [
            1,
            12,
            205,
            1,
            0,
            0
        ],
        "tpid": [129, 0],
        "tci": [0, 0],
        "appid": [
            0,
            0
        ],
        "go_cb_ref": "IED1LD1/LLN0$GO$gse1",
        "dat_set": "IED1LD1/LLN0$TestMHAI",
        "go_id": "SomeAppId",
        "simulation": true,
        "conf_rev": 1,
        "nds_com": true,
        "num_dat_set_entries": 3,
        "all_data": [
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
        ],
        "max_repetition": 2000,
        "min_repetition": 20,
    }
}
 ```

 ## Stop

 To stop the GOOSE send this message 

 ```json
{
    "cmd": "stop",
    "go_cb_ref": "IED1LD1/LLN0$GO$gse1"
}
 ```


 ## Update

 To update a GOOSE you need to send and update message holding the updates data. This will immediately trigger and new GOOSE packet and the will go to the repetition strategy again.


```json
{
    "cmd": "update",
    "go_cb_ref": "IED1LD1/LLN0$GO$gse1",
    "data": [
        {
            "Structure": [
                {
                    "Structure": [
                        {
                            "Float32": 23123.123213
                        }
                    ]
                },
                {
                    "Structure": [
                        {
                            "Float32": 45.6
                        }
                    ]
                }
            ]
        },
        {
            "Structure": [
                {
                    "Float32": 145.332
                }
            ]
        },
        {
            "Float32": 34
        }
    ],
}
 ```



