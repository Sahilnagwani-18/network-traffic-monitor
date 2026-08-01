use dashmap::DashMap;
use std::fs;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Maps a socket "local_addr:local_port" key -> (inode) built from
/// /proc/net/{tcp,tcp6,udp,udp6}, and a second map inode -> (pid, comm, uid),
/// built by scanning /proc/[pid]/fd. Rebuilt periodically since this is O(N)
/// over all processes and would be too slow per-packet.
pub struct ProcTable {
    inode_by_socket: DashMap<(String, u16), u64>, // (protocol+local_ip, local_port) -> inode
    proc_by_inode: DashMap<u64, (u32, String, String)>, // inode -> (pid, comm, username)
    last_refresh: std::sync::Mutex<Instant>,
    refresh_interval: Duration,
}

impl ProcTable {
    pub fn new() -> Self {
        let t = Self {
            inode_by_socket: DashMap::new(),
            proc_by_inode: DashMap::new(),
            last_refresh: std::sync::Mutex::new(Instant::now() - Duration::from_secs(60)),
            refresh_interval: Duration::from_secs(2),
        };
        t.refresh();
        t
    }

    pub fn maybe_refresh(&self) {
        let mut last = self.last_refresh.lock().unwrap();
        if last.elapsed() >= self.refresh_interval {
            self.refresh();
            *last = Instant::now();
        }
    }

    fn refresh(&self) {
        self.inode_by_socket.clear();
        for (proto, path) in [
            ("tcp", "/proc/net/tcp"),
            ("tcp", "/proc/net/tcp6"),
            ("udp", "/proc/net/udp"),
            ("udp", "/proc/net/udp6"),
        ] {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 10 {
                        continue;
                    }
                    if let Some((local_addr, local_port)) = parse_hex_addr(fields[1]) {
                        if let Ok(inode) = fields[9].parse::<u64>() {
                            if inode != 0 {
                                self.inode_by_socket
                                    .insert((format!("{proto}:{local_addr}"), local_port), inode);
                            }
                        }
                    }
                }
            }
        }

        self.proc_by_inode.clear();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid: u32 = match entry.file_name().to_string_lossy().parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let fd_dir = format!("/proc/{pid}/fd");
                let Ok(fds) = fs::read_dir(&fd_dir) else { continue };
                let mut inodes = Vec::new();
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        if let Some(s) = link.to_str() {
                            if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    inodes.push(inode);
                                }
                            }
                        }
                    }
                }
                if inodes.is_empty() {
                    continue;
                }
                let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_else(|_| "unknown".into())
                    .trim()
                    .to_string();
                let username = uid_to_username(read_uid(pid));
                for inode in inodes {
                    self.proc_by_inode.insert(inode, (pid, comm.clone(), username.clone()));
                }
            }
        }
    }

    /// Look up the local socket for a packet. Since capture sees both directions,
    /// we try matching either the src or dst as "local".
    pub fn lookup(
        &self,
        proto: &str,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> (Option<String>, Option<u32>, Option<String>) {
        self.maybe_refresh();
        let proto_lc = proto.to_lowercase();

        for (ip, port) in [(src_ip, src_port), (dst_ip, dst_port)] {
            let key_specific = (format!("{proto_lc}:{}", normalize_ip(ip)), port);
            if let Some(inode) = self.inode_by_socket.get(&key_specific) {
                if let Some(p) = self.proc_by_inode.get(&inode) {
                    let (pid, comm, user) = p.value().clone();
                    return (Some(comm), Some(pid), Some(user));
                }
            }
            // Many sockets listen on 0.0.0.0 / :: rather than the specific IP.
            let wildcard = if ip.is_ipv4() { "0.0.0.0" } else { "::" };
            let key_wild = (format!("{proto_lc}:{wildcard}"), port);
            if let Some(inode) = self.inode_by_socket.get(&key_wild) {
                if let Some(p) = self.proc_by_inode.get(&inode) {
                    let (pid, comm, user) = p.value().clone();
                    return (Some(comm), Some(pid), Some(user));
                }
            }
        }
        (None, None, None)
    }
}

fn normalize_ip(ip: IpAddr) -> String {
    ip.to_string()
}

/// /proc/net/tcp encodes addr:port in hex, little-endian per octet for IPv4.
fn parse_hex_addr(field: &str) -> Option<(String, u16)> {
    let mut parts = field.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if addr_hex.len() == 8 {
        // IPv4: 4 bytes, little-endian
        let bytes = u32::from_str_radix(addr_hex, 16).ok()?.to_le_bytes();
        Some((
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            port,
        ))
    } else if addr_hex.len() == 32 {
        // IPv6: 16 bytes, four little-endian u32 words
        let mut raw = [0u8; 16];
        for i in 0..4 {
            let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
            raw[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let ip = std::net::Ipv6Addr::from(raw);
        Some((ip.to_string(), port))
    } else {
        None
    }
}

fn read_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid_str = rest.split_whitespace().next()?;
            return uid_str.parse().ok();
        }
    }
    None
}

fn uid_to_username(uid: Option<u32>) -> String {
    let Some(uid) = uid else { return "unknown".into() };
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() > 2 {
                if let Ok(entry_uid) = fields[2].parse::<u32>() {
                    if entry_uid == uid {
                        return fields[0].to_string();
                    }
                }
            }
        }
    }
    uid.to_string()
}
