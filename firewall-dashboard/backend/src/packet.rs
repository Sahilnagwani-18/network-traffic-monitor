use chrono::Utc;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Serialize;
use std::net::IpAddr;

use crate::proc_lookup::ProcTable;

/// A single captured/summarized packet, flattened across L2-L7 for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct PacketEvent {
    pub ts: String,
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,     // L3/L4 protocol: TCP/UDP/ICMP/ARP/...
    pub l7_guess: String,     // best-effort application protocol: HTTP/HTTPS/DNS/SSH/...
    pub length: usize,
    pub direction: String,    // inbound / outbound / local
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub user: Option<String>,
    pub flags: Option<String>, // TCP flags, if applicable
    pub sni: Option<String>,   // TLS SNI hostname, if we can parse it
    pub dns_query: Option<String>,
}

fn well_known_l7(proto: &str, port: u16) -> Option<&'static str> {
    match (proto, port) {
        ("TCP", 80) | ("TCP", 8080) => Some("HTTP"),
        ("TCP", 443) | ("TCP", 8443) => Some("HTTPS/TLS"),
        ("TCP", 22) => Some("SSH"),
        ("TCP", 21) => Some("FTP"),
        ("TCP", 25) | ("TCP", 587) => Some("SMTP"),
        ("TCP", 3306) => Some("MySQL"),
        ("TCP", 5432) => Some("PostgreSQL"),
        ("TCP", 6379) => Some("Redis"),
        ("UDP", 53) | ("TCP", 53) => Some("DNS"),
        ("UDP", 67) | ("UDP", 68) => Some("DHCP"),
        ("UDP", 123) => Some("NTP"),
        ("UDP", 443) => Some("QUIC/HTTP3"),
        _ => None,
    }
}

/// Very small best-effort TLS ClientHello SNI parser.
fn parse_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 6 || payload[0] != 0x16 {
        return None; // not a TLS handshake record
    }
    // Skip TLS record header (5) + handshake header (4) + client version (2) + random (32)
    let mut pos = 5 + 4 + 2 + 32;
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = *payload.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > payload.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= payload.len() {
        return None;
    }
    let comp_len = *payload.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos + 2 > payload.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(payload.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            // server_name extension
            let mut sp = pos + 2 + 1; // skip list len (2) + name type (1)
            if sp + 2 > payload.len() {
                return None;
            }
            let name_len = u16::from_be_bytes([payload[sp], payload[sp + 1]]) as usize;
            sp += 2;
            if sp + name_len <= payload.len() {
                return String::from_utf8(payload[sp..sp + name_len].to_vec()).ok();
            }
        }
        pos += ext_len;
    }
    None
}

fn tcp_flags_str(tcp: &TcpPacket) -> String {
    let f = tcp.get_flags();
    let mut s = Vec::new();
    if f & 0x01 != 0 { s.push("FIN"); }
    if f & 0x02 != 0 { s.push("SYN"); }
    if f & 0x04 != 0 { s.push("RST"); }
    if f & 0x08 != 0 { s.push("PSH"); }
    if f & 0x10 != 0 { s.push("ACK"); }
    if f & 0x20 != 0 { s.push("URG"); }
    s.join(",")
}

pub fn parse_ethernet_frame(
    data: &[u8],
    local_ips: &[IpAddr],
    proc_table: &ProcTable,
) -> Option<PacketEvent> {
    let eth = EthernetPacket::new(data)?;
    let src_mac = eth.get_source().to_string();
    let dst_mac = eth.get_destination().to_string();

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            build_event_v4(&ip, src_mac, dst_mac, local_ips, proc_table)
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            build_event_v6(&ip, src_mac, dst_mac, local_ips, proc_table)
        }
        EtherTypes::Arp => Some(PacketEvent {
            ts: Utc::now().to_rfc3339(),
            src_mac,
            dst_mac,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: "ARP".into(),
            l7_guess: "ARP".into(),
            length: data.len(),
            direction: "local".into(),
            process: None,
            pid: None,
            user: None,
            flags: None,
            sni: None,
            dns_query: None,
        }),
        _ => None,
    }
}

fn direction_for(src: IpAddr, local_ips: &[IpAddr]) -> &'static str {
    if local_ips.contains(&src) { "outbound" } else { "inbound" }
}

fn build_event_v4(
    ip: &Ipv4Packet,
    src_mac: String,
    dst_mac: String,
    local_ips: &[IpAddr],
    proc_table: &ProcTable,
) -> Option<PacketEvent> {
    let src_ip = IpAddr::V4(ip.get_source());
    let dst_ip = IpAddr::V4(ip.get_destination());
    let direction = direction_for(src_ip, local_ips).to_string();

    let (protocol, src_port, dst_port, l7_guess, flags, sni, dns_query) = match ip.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ip.payload())?;
            let sport = tcp.get_source();
            let dport = tcp.get_destination();
            let l7 = well_known_l7("TCP", dport)
                .or_else(|| well_known_l7("TCP", sport))
                .unwrap_or("TCP")
                .to_string();
            let sni = if dport == 443 || sport == 443 {
                parse_sni(tcp.payload())
            } else {
                None
            };
            ("TCP".to_string(), Some(sport), Some(dport), l7, Some(tcp_flags_str(&tcp)), sni, None)
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ip.payload())?;
            let sport = udp.get_source();
            let dport = udp.get_destination();
            let l7 = well_known_l7("UDP", dport)
                .or_else(|| well_known_l7("UDP", sport))
                .unwrap_or("UDP")
                .to_string();
            let dns_query = if dport == 53 || sport == 53 {
                parse_dns_query(udp.payload())
            } else {
                None
            };
            ("UDP".to_string(), Some(sport), Some(dport), l7, None, None, dns_query)
        }
        IpNextHeaderProtocols::Icmp => {
            ("ICMP".to_string(), None, None, "ICMP".to_string(), None, None, None)
        }
        other => (format!("{:?}", other), None, None, "OTHER".to_string(), None, None, None),
    };

    let (process, pid, user) = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
        proc_table.lookup(protocol.as_str(), src_ip, sp, dst_ip, dp)
    } else {
        (None, None, None)
    };

    Some(PacketEvent {
        ts: Utc::now().to_rfc3339(),
        src_mac,
        dst_mac,
        src_ip: Some(src_ip.to_string()),
        dst_ip: Some(dst_ip.to_string()),
        src_port,
        dst_port,
        protocol,
        l7_guess,
        length: ip.get_total_length() as usize,
        direction,
        process,
        pid,
        user,
        flags,
        sni,
        dns_query,
    })
}

fn build_event_v6(
    ip: &Ipv6Packet,
    src_mac: String,
    dst_mac: String,
    local_ips: &[IpAddr],
    proc_table: &ProcTable,
) -> Option<PacketEvent> {
    let src_ip = IpAddr::V6(ip.get_source());
    let dst_ip = IpAddr::V6(ip.get_destination());
    let direction = direction_for(src_ip, local_ips).to_string();

    let (protocol, src_port, dst_port, l7_guess) = match ip.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ip.payload())?;
            let sport = tcp.get_source();
            let dport = tcp.get_destination();
            let l7 = well_known_l7("TCP", dport).unwrap_or("TCP").to_string();
            ("TCP".to_string(), Some(sport), Some(dport), l7)
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ip.payload())?;
            let sport = udp.get_source();
            let dport = udp.get_destination();
            let l7 = well_known_l7("UDP", dport).unwrap_or("UDP").to_string();
            ("UDP".to_string(), Some(sport), Some(dport), l7)
        }
        other => (format!("{:?}", other), None, None, "OTHER".to_string()),
    };

    let (process, pid, user) = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
        proc_table.lookup(protocol.as_str(), src_ip, sp, dst_ip, dp)
    } else {
        (None, None, None)
    };

    Some(PacketEvent {
        ts: Utc::now().to_rfc3339(),
        src_mac,
        dst_mac,
        src_ip: Some(src_ip.to_string()),
        dst_ip: Some(dst_ip.to_string()),
        src_port,
        dst_port,
        protocol,
        l7_guess,
        length: ip.payload().len(),
        direction,
        process,
        pid,
        user,
        flags: None,
        sni: None,
        dns_query: None,
    })
}

/// Extremely small DNS question-section parser, just for the query name.
fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }
    let mut pos = 12; // skip header
    let mut labels = Vec::new();
    loop {
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > payload.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&payload[pos..pos + len]).to_string());
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
