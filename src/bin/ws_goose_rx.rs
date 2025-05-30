extern crate iec_61850_lib;

use futures_util::{SinkExt, StreamExt};
use pnet::datalink::{self, interfaces, Channel, NetworkInterface};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::decode_goose::{decode_goose_pdu, is_goose_frame};

fn display_network_interfaces() {
    let interfaces = interfaces();
    for interface in interfaces.iter() {
        println!("interface  {}", interface.index);
        println!("\t name {}", interface.name);
        println!("\t ips {:?}", interface.ips);
        println!("\t description {}", interface.description);
    }
}

fn time_string() -> String {
    // Get the current system time
    let now = SystemTime::now();

    // Convert it to a duration since the UNIX epoch
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

    // Extract the number of seconds and nanoseconds
    let total_seconds = since_the_epoch.as_secs();
    let nanoseconds = since_the_epoch.subsec_nanos();

    // Calculate the number of days, hours, minutes, and seconds
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    let hours = minutes / 60;
    let minutes = minutes % 60;
    let days = hours / 24;
    let hours = hours % 24;

    // Format the time as a string
    let time_string = format!(
        "{} days, {} hours, {} minutes, {} seconds, {} nanoseconds",
        days, hours, minutes, seconds, nanoseconds
    );
    return time_string;
}

pub fn get_time_ms() -> [u8; 8] {
    let mut time_array = [0u8; 8];
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let seconds = since_the_epoch.as_secs() as u32;
    let sec_array = seconds.to_be_bytes();
    let subsec_nano = (since_the_epoch.subsec_micros() as f32 * 4294.967296) as u32;
    let nano_array = subsec_nano.to_be_bytes();
    time_array[0..4].copy_from_slice(&sec_array);
    time_array[4..7].copy_from_slice(&nano_array[..3]);
    // Set the last byte to 0x18, which might represent a specific flag or identifier.
    time_array[7] = 0x18;
    time_array
}

#[tokio::main]
async fn main() {
    // Create a channel to receive new messages
    let (tx, mut rx) = mpsc::channel(50);
    let (broadcast_tx, broadcast_rx) = broadcast::channel(100);

    // Clone the broadcast_tx before moving it into the task
    let broadcast_tx_clone = broadcast_tx.clone();

    // check whether the the interface name exist
    let interface_name = match env::args().nth(1) {
        Some(name) => name,
        None => {
            println!(
                "please add an interface name as argument. the available interface in the system:"
            );
            display_network_interfaces();
            panic!();
        }
    };

    // find the interface and throw if not so
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = interfaces();
    // Find the network interface with the provided name
    let interface = match interfaces.into_iter().filter(interface_names_match).next() {
        Some(val) => val,
        _ => {
            println!("unknown interface name. the available interface in the system:");
            display_network_interfaces();
            panic!();
        }
    };

    // Spawn a task to forward messages from the channel to the broadcast channel
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let message: String = message; // Explicitly annotate the type
            println!("Forwarding message to broadcast channel: {}", message); // Debug print
            if let Err(e) = broadcast_tx_clone.send(message.clone()) {
                eprintln!("Failed to send message to broadcast channel: {}", e);
            } else {
                println!("Sent message to broadcast channel: {}", message); // Debug print
            }
        }
    });

    // Bind the server to the specified address
    let addr: SocketAddr = "0.0.0.0:3030".parse().unwrap();
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("WebSocket server running on ws://{}", addr);

    // Keep a reference to the broadcast receiver to prevent the channel from closing
    let _broadcast_rx_keeper = broadcast_rx;

    // Spawn a task to handle WebSocket connections
    let server_handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let broadcast_tx = broadcast_tx.clone();
            tokio::spawn(async move {
                match accept_async(stream).await {
                    Ok(ws_stream) => {
                        let (mut write, mut read) = ws_stream.split();

                        // Subscribe to the broadcast channel
                        let mut rx = broadcast_tx.subscribe();

                        loop {
                            tokio::select! {
                                // Handle incoming messages from the client
                                msg = read.next() => {
                                    if let Some(msg) = msg {
                                        match msg {
                                            Ok(msg) => {
                                                if msg.is_close() {
                                                    println!("Client disconnected"); // Debug print
                                                    break;
                                                } else {
                                                    println!("Received message from client: {:?}", msg); // Debug print
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Error receiving message from client: {}", e);
                                                break;
                                            }
                                        }
                                    } else {
                                        println!("Client disconnected"); // Debug print
                                        break;
                                    }
                                }

                                // Send messages from the broadcast channel to the client
                                msg = rx.recv() => {
                                    if let Ok(msg) = msg {
                                        println!("Sending message to client: {}", msg); // Debug print
                                        if let Err(e) = write.send(Message::Text(msg)).await {
                                            eprintln!("Failed to send message to client: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to accept WebSocket connection: {}", e);
                    }
                }
            });
        }
    });

    // Receive and foreward GOOSE messages through web socket
    println!("Spawning message simulation task"); // Debug print
    let simulation_handle = tokio::spawn(async move {
        let (_, mut datalink_rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        println!("start listening goose messages");

        loop {
            match datalink_rx.next() {
                Ok(packet) => {
                    //display_buffer(packet, packet.len());
                    let (rx_header, next_pos) = decode_ethernet_header(&packet);

                    if is_goose_frame(&rx_header) {
                        let (rx_pdu, _next_pos) = decode_goose_pdu(&packet, next_pos);
                        let time = get_time_ms();
                        let message = format!(
                            "GOOSE message {} received at {}",
                            rx_pdu.go_cb_ref,
                            time_string()
                        );

                        let content: String = json!({
                            "time": time,
                            "header": {
                                "srcAddr": rx_header.src_addr,
                                "dstAddr": rx_header.dst_addr,
                                "tpid": rx_header.tpid,
                                "tci": rx_header.tci,
                                "etherType": rx_header.ether_type,
                                "appID": rx_header.appid,
                                "length": rx_header.length
                            },
                            "pdu": {
                                "goCbRef": rx_pdu.go_cb_ref.clone(),
                                "timeAllowedToLive": rx_pdu.time_allowed_to_live,
                                "goID": rx_pdu.go_id.clone(),
                                "t": rx_pdu.t,
                                "datSet": rx_pdu.data_set.clone(),
                                "stNum": rx_pdu.st_num,
                                "sqNum": rx_pdu.sq_num,
                                "simulation": rx_pdu.simulation,
                                "confRev": rx_pdu.conf_rev,
                                "ndsCom": rx_pdu.nds_com,
                                "numDatSetEntries": rx_pdu.num_data_set_entries,
                                "allData": rx_pdu.all_data,
                            }
                        })
                        .to_string();

                        println!("{}", message);
                        // println!("decode header {:?}",rx_header);
                        // println!("decode pdu {:?}",rx_pdu);

                        // send content of the ethernet packet to channel
                        if let Err(e) = tx.send(content).await {
                            eprintln!("Failed to send message to mpsc channel: {}", e);
                        }

                        // Yield to allow the forwarding task to run
                        tokio::task::yield_now().await;
                    }
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    // Wait for both tasks to complete
    let _ = tokio::join!(server_handle, simulation_handle);
}
