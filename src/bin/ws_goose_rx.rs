use futures_util::{SinkExt, StreamExt};
use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::decode_goose::{decode_goose_pdu, is_goose_frame};
use iec_61850_lib::types::{EthernetHeader, IECGoosePdu};
use pnet::datalink::{self, interfaces, Channel};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use tokio::sync::{broadcast, mpsc};
use warp::Filter;

#[tokio::main]
async fn main() {
    // Parse args
    let mut args = env::args().skip(1);
    let interface_name = args.next().expect("Please provide interface name");
    let port = args.next().unwrap_or_else(|| "3030".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().expect("Invalid port");

    // Find interface
    let interface = interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Unknown interface name");

    // Channels for message passing
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let (broadcast_tx, _) = broadcast::channel::<String>(1);

    // Forward messages from mpsc to broadcast
    let broadcast_tx_clone = broadcast_tx.clone();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            println!("Forwarding message to broadcast.");
            let _ = broadcast_tx_clone.send(message);
        }
    });

    // GOOSE listener task
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let (_, mut datalink_rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => ((), rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        println!("start listening goose messages");

        let mut header = EthernetHeader::default();
        let mut pdu = IECGoosePdu::default();

        loop {
            match datalink_rx.next() {
                Ok(packet) => {
                    let next_pos = decode_ethernet_header(&mut header, &packet);
                    if is_goose_frame(&packet) {
                        let _next_pos = decode_goose_pdu(&mut pdu, &packet, next_pos);
                        // NOTE: You could use https://docs.rs/serde_json/latest/serde_json/fn.to_string.html or https://docs.rs/serde_json/latest/serde_json/fn.to_value.html here instead of writing out all fields
                        let message = json!({
                            "header": {
                                "srcAddr": header.src_addr,
                                "dstAddr": header.dst_addr,
                                "tpid": header.tpid,
                                "tci": header.tci,
                                "etherType": header.ether_type,
                                "appID": header.appid,
                                "length": header.length
                            },
                            "pdu": {
                                "goCbRef": pdu.go_cb_ref,
                                "timeAllowedToLive": pdu.time_allowed_to_live,
                                "goID": pdu.go_id,
                                "t": pdu.t,
                                "datSet": pdu.dat_set,
                                "stNum": pdu.st_num,
                                "sqNum": pdu.sq_num,
                                "simulation": pdu.simulation,
                                "confRev": pdu.conf_rev,
                                "ndsCom": pdu.nds_com,
                                "numDatSetEntries": pdu.num_dat_set_entries,
                                "allData": pdu.all_data,
                            }
                        })
                        .to_string();

                        println!("Send message to WebSocket to mpsc");

                        let _ = tx_clone.send(message).await;
                    }
                }
                Err(e) => {
                    eprintln!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    // WebSocket route using warp
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and_then(move |ws: warp::ws::Ws| {
            let broadcast_tx = broadcast_tx.clone();
            async move {
                Ok::<_, std::convert::Infallible>(ws.on_upgrade(move |websocket| async move {
                    let (mut ws_tx, mut ws_rx) = websocket.split();
                    let mut rx = broadcast_tx.subscribe();

                    // Forward broadcast messages to WebSocket
                    loop {
                        tokio::select! {
                            Some(Ok(msg)) = ws_rx.next() => {
                                if msg.is_close() {
                                    break;
                                }
                            }
                            Ok(msg) = rx.recv() => {
                                println!("Received message from broadcast!");
                                if ws_tx.send(warp::ws::Message::text(msg)).await.is_err() {
                                    break;
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
