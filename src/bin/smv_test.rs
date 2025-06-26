use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::decode_smv::decode_goose_smv;
use iec_61850_lib::types::{EthernetHeader, SavPdu};
use pnet::datalink::{self, interfaces, Channel};
use std::env;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

/// Determines if the provided Ethernet frame buffer contains a Sampled Values (SMV) frame
/// by checking the EtherType field, accounting for possible VLAN tagging.
///
/// Returns `true` if the EtherType matches the SMV type (0x88ba), regardless of VLAN presence.
/// If a VLAN tag (0x81, 0x00) is detected, the EtherType is checked at bytes 16-17; otherwise, at bytes 12-13.
pub fn is_smv_frame(buffer: &[u8]) -> bool {
    if buffer.len() < 14 {
        return false;
    }
    // If VLAN tag (0x81, 0x00) is present, EtherType is at offset 16; otherwise, at 12.
    let ether_type_offset = if buffer[12..14] == [0x81, 0x00] {
        16
    } else {
        12
    };
    if buffer.len() < ether_type_offset + 2 {
        return false;
    }
    let ether_type = &buffer[ether_type_offset..ether_type_offset + 2];
    ether_type == [0x88, 0xba]
}

fn main() {
    // Parse args
    let mut args = env::args().skip(1);
    let interface_name = args.next().expect("Please provide interface name");

    // Find interface
    let interface = interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Unknown interface name");

    // Set up a shutdown flag
    let running = Arc::new(AtomicBool::new(true));
    let running_listener = running.clone();

    // Spawn the listener thread
    let handle = thread::spawn(move || {
        let (_, mut datalink_rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => ((), rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        println!("Start listening for SMV messages (Ctrl+C to stop)");

        let mut header = EthernetHeader::default();
        let mut sav_pdu = SavPdu::default();

        while running_listener.load(Ordering::SeqCst) {
            match datalink_rx.next() {
                Ok(packet) => {
                    let next_pos = decode_ethernet_header(&mut header, &packet);
                    if is_smv_frame(packet) {
                        println!("New SMV frame detected");

                        let _next_pos = decode_goose_smv(&mut sav_pdu, &packet, next_pos);

                        // Return instantaneous RMS value assuming system
                        for i in 0..sav_pdu.sav_asdu.len() {
                            let data = &sav_pdu.sav_asdu[i].all_data;

                            // Calculate RMS of the first 3 currents if available
                            let ia = data[0].0;
                            let ib = data[1].0;
                            let ic = data[2].0;
                            println!(
                                "RMS of current {}",
                                ((ia * ia + ib * ib + ic * ic) / 3.0).sqrt()
                            );

                            // Calculate RMS of the first 3 currents if available
                            let va = data[4].0;
                            let vb = data[5].0;
                            let vc = data[6].0;
                            println!(
                                "RMS of voltage {}",
                                ((va * va + vb * vb + vc * vc) / 3.0).sqrt()
                            );
                        }

                        println!("SMV PDU: {:?}", sav_pdu);
                    }
                }
                Err(e) => {
                    eprintln!("An error occurred while reading: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        println!("Listener thread exiting.");
    });

    // Handle Ctrl+C for graceful shutdown
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            println!("Shutting down.");
            running.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    // Wait for the listener thread to finish
    handle.join().unwrap();
}
