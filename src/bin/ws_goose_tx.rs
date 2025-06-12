use futures_util::StreamExt;
use iec_61850_lib::encode_goose::encode_goose;
use iec_61850_lib::types::{GooseConfig, GooseRuntime};
use pnet::datalink::{self, interfaces, Channel};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use warp::Filter;

struct GooseState {
    config: GooseConfig,
    runtime: GooseRuntime,
    current_interval: u32,
    running: bool,
    handle: Option<JoinHandle<()>>,
    notify: Arc<Notify>,
}

type GooseMap = Arc<Mutex<HashMap<String, Arc<Mutex<GooseState>>>>>;

/// Returns the current time as an 8-byte array in IEC 61850 GOOSE UTC time format.
/// The first 4 bytes are seconds since UNIX_EPOCH (big-endian),
/// the next 3 bytes are fractional seconds (in nanoseconds, big-endian, most significant bytes),
/// and the last byte is the quality indicator (0x18 for "time is synchronized").
pub fn time_ms() -> [u8; 8] {
    let mut time = [0u8; 8];
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

    // 4 bytes: seconds since epoch (big-endian)
    let seconds = since_epoch.as_secs() as u32;
    let sec_bytes = seconds.to_be_bytes();

    // 3 bytes: fractional seconds (nanoseconds, most significant bytes)
    // Convert microseconds to nanoseconds, then take the top 3 bytes
    let nanos = (since_epoch.subsec_micros() as u32) * 1000;
    let nano_bytes = nanos.to_be_bytes();

    time[0..4].copy_from_slice(&sec_bytes);
    time[4..7].copy_from_slice(&nano_bytes[0..3]);
    // 1 byte: time quality (0x18 = time is synchronized, no leap second, etc.)
    time[7] = 0x18;

    time
}

#[tokio::main]
async fn main() {
    // Shared state for all GOOSE frames
    let goose_map: GooseMap = Arc::new(Mutex::new(HashMap::new()));

    // Parse command line arguments
    let mut args = env::args().skip(1);
    let interface_name = args.next().expect("Please provide interface name");
    let port = args.next().unwrap_or_else(|| "3030".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().expect("Invalid port");

    // Find the specified network interface
    let interface = interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Unknown interface name");

    let src_addr = interface
        .mac
        .expect("Interface has no MAC address")
        .octets();

    // Open datalink channel for sending Ethernet frames
    let (tx_eth, _rx_eth) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, _rx)) => (tx, _rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let tx_eth = Arc::new(Mutex::new(tx_eth));

    // WebSocket route
    let goose_map_ws = goose_map.clone();
    let tx_eth_ws = tx_eth.clone();
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and_then(move |ws: warp::ws::Ws| {
            let goose_map = goose_map_ws.clone();
            let tx_eth = tx_eth_ws.clone();
            async move {
                Ok::<_, std::convert::Infallible>(ws.on_upgrade(move |websocket| async move {
                    let (_ws_tx, mut ws_rx) = websocket.split();

                    while let Some(Ok(msg)) = ws_rx.next().await {
                        if let Ok(text) = msg.to_str() {
                            if let Ok(json_msg) = serde_json::from_str::<serde_json::Value>(text) {
                                // Use go_cb_ref as the unique key for each GOOSE instance
                                println!("Received message: {:?}", json_msg);
                                
                                match json_msg.get("cmd").and_then(|c| c.as_str()) {
                                    Some("init") => {
                                        let go_cb_ref = if let Some(config) = json_msg.get("config") {
                                            config.get("go_cb_ref")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string())
                                        } else {
                                            None
                                        };
                                        let Some(go_cb_ref) = go_cb_ref else { continue; };

                                        let mut map = goose_map.lock().await;
                                        let goose_state = map.entry(go_cb_ref.clone()).or_insert_with(|| {
                                            Arc::new(Mutex::new(GooseState {
                                                config: GooseConfig::default(),
                                                runtime: GooseRuntime {
                                                    st_num: 1,
                                                    sq_num: 1,
                                                    timestamp: time_ms(),
                                                    src_addr,
                                                },
                                                current_interval: 10000,
                                                running: false,
                                                handle: None,
                                                notify: Arc::new(Notify::new()),
                                            }))
                                        }).clone();

                                        println!("Initializing GOOSE Control Block: {}", go_cb_ref);

                                        // Serialize config object in the JSON message
                                        let mut state = goose_state.lock().await;
                                        if let Some(config_json) = json_msg.get("config") {
                                            println!("Config value: {:?}", config_json);
                                            if let Ok(config) = serde_json::from_value::<GooseConfig>(config_json.clone()) {
                                                println!("Serialized config: {:?}", config);
                                                state.config = config;
                                            } else {
                                                println!("Failed to deserialize configuration: {:?}", config_json);
                                            }
                                        }

                                        // Stop previous task if running
                                        if let Some(handle) = state.handle.take() {
                                            handle.abort();
                                        }
                                        state.running = true;
                                        state.current_interval = state.config.max_repetition;

                                        // Start periodic GOOSE sender task with repetition strategy
                                        let goose_state2 = goose_state.clone();
                                        println!("GOOSE sender state.running: {}", state.running);
                                        let tx_eth2 = tx_eth.clone();
                                        let notify = state.notify.clone();
                                        let handle = tokio::spawn(async move {

                                            println!("Starting GOOSE sender task for {}", go_cb_ref);
                                            let interval = {
                                                let state = goose_state2.lock().await;
                                                state.current_interval
                                            };
                                            loop {
                                                // Send GOOSE frame immediately
                                                {
                                                    let mut state = goose_state2.lock().await;
                                                    println!("Encoding GOOSE frame for {}", go_cb_ref);

                                                    // Allocate buffer
                                                    let mut buffer = vec![0u8; 1518]; // Maximum Ethernet frame size

                                                    // Encode GOOSE
                                                    match encode_goose(&state.config, &state.runtime, &mut buffer) {
                                                        Ok(end_pos) => {
                                                            println!("Written buffer {}",end_pos); 
                                                            let mut tx = tx_eth2.lock().await;
                                                            let _ = tx.send_to(&&buffer[..end_pos], None);
                                                        },
                                                        Err(_e) => panic!("Failed to encode GOOSE PDU"),
                                                    }

                                                    // Increment sq_num on each re-transmission
                                                    state.runtime.sq_num = state.runtime.sq_num.wrapping_add(1);
                                                }


                                                // Wait for max_time or notification before next send
                                                println!("GOOSE sender loop tick for {}", go_cb_ref);
                                                tokio::select! {
                                                    _ = tokio::time::sleep(Duration::from_millis(interval as u64)) => {},
                                                    _ = notify.notified() => {},
                                                }

                                                let state = goose_state2.lock().await;
                                                if !state.running {
                                                    break;
                                                }
                                            }
                                        });
                                        state.handle = Some(handle);
                                    }
                                    Some("stop") => {
                                        println!("Intention to stop GOOSE");

                                        let go_cb_ref = json_msg
                                            .get("go_cb_ref")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string());
                                        let Some(go_cb_ref) = go_cb_ref else { continue; };

                                        let map = goose_map.lock().await;
                                        if let Some(goose_state) = map.get(&go_cb_ref) {
                                            println!("Found a GOOSE to stop: {:?}", go_cb_ref);
                                            let mut state = goose_state.lock().await;
                                            state.running = false;
                                            if let Some(handle) = state.handle.take() {
                                                handle.abort();
                                            }
                                        }
                                    }
                                    Some("update") => {
                                        println!("Intention to update GOOSE");

                                        let go_cb_ref = json_msg
                                            .get("go_cb_ref")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string());
                                        let Some(go_cb_ref) = go_cb_ref else { continue; };

                                        let map = goose_map.lock().await;
                                        if let Some(goose_state) = map.get(&go_cb_ref) {
                                            let mut state = goose_state.lock().await;
                                            // Update all_data or other fields as needed
                                            if let Some(data) = json_msg.get("data") {
                                                if let Ok(new_all_data) = serde_json::from_value(data.clone()) {
                                                    state.config.all_data = new_all_data;
                                                }
                                            }
                                            // Increment st_num on update
                                            state.runtime.st_num = state.runtime.st_num.wrapping_add(1);
                                            state.runtime.sq_num = 1;

                                            // Update the timestamp
                                            state.runtime.timestamp = time_ms();

                                            // Reset interval and notify sender task to send immediately
                                            state.current_interval = state.config.min_repetition;
                                            state.notify.notify_one();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }))
            }
        });

    println!("WebSocket server running on ws://{}/ws", addr);
    warp::serve(ws_route).run(addr).await;
}
