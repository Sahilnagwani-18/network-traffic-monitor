use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::packet::{parse_ethernet_frame, PacketEvent};
use crate::proc_lookup::ProcTable;

pub fn list_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| !i.ips.is_empty() || i.is_up())
        .map(|i| i.name)
        .collect()
}

fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| i.name == name)
}

/// Spawns a blocking OS thread that captures packets on `iface_name` and
/// publishes parsed `PacketEvent`s to the broadcast channel for WebSocket
/// clients to consume.
pub fn spawn_capture(iface_name: String, tx: broadcast::Sender<PacketEvent>) {
    std::thread::spawn(move || {
        let interface = match find_interface(&iface_name) {
            Some(i) => i,
            None => {
                eprintln!(
                    "Interface '{iface_name}' not found. Available: {:?}",
                    list_interfaces()
                );
                return;
            }
        };

        let local_ips: Vec<IpAddr> = interface.ips.iter().map(|n| n.ip()).collect();
        let proc_table = Arc::new(ProcTable::new());

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                eprintln!("Unsupported channel type on {iface_name}");
                return;
            }
            Err(e) => {
                eprintln!(
                    "Failed to open capture on {iface_name}: {e}. \
                     Try running with sudo or grant CAP_NET_RAW (setcap cap_net_raw,cap_net_admin=eip <binary>)."
                );
                return;
            }
        };

        println!("Capturing on '{iface_name}' (local IPs: {local_ips:?})");

        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(event) = parse_ethernet_frame(frame, &local_ips, &proc_table) {
                        // Ignore send errors (happens when no subscribers connected yet)
                        let _ = tx.send(event);
                    }
                }
                Err(e) => {
                    eprintln!("Capture read error: {e}");
                }
            }
        }
    });
}
