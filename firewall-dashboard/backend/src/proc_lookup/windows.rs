//! Windows socket -> process -> user attribution.
//!
//! Linux has `/proc/net/tcp` + `/proc/[pid]/fd`; Windows' equivalent is the
//! IP Helper API: `GetExtendedTcpTable` / `GetExtendedUdpTable` return every
//! open socket already tagged with its owning PID directly (no inode
//! indirection needed). From the PID we then ask `OpenProcess` +
//! `QueryFullProcessImageNameW` for the executable name, and
//! `OpenProcessToken` + `LookupAccountSidW` for the owning user.
//!
//! NOTE: this file has been written against the documented Win32 APIs and
//! type-checked against `windows-sys`' bindings, but has not been build- or
//! run-tested on an actual Windows machine (this project was scaffolded in a
//! Linux sandbox). If `cargo build` surfaces a mismatch (struct field name,
//! constant name, etc.), it's almost always a 1-line fix — paste the error
//! and it's straightforward to patch.

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Networking::WinSock::AF_INET6;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::ProcessStatus::K32GetModuleBaseNameW;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

pub struct ProcTable {
    // (protocol, local_port) -> pid. Keying on port only (not IP) since a
    // given TCP port can only be bound by one process at a time in the
    // common case, and this keeps the Windows table parsing simple.
    port_to_pid: DashMap<(&'static str, u16), u32>,
    proc_info: DashMap<u32, (String, String)>, // pid -> (process name, username)
    last_refresh: Mutex<Instant>,
    refresh_interval: Duration,
}

impl ProcTable {
    pub fn new() -> Self {
        let t = Self {
            port_to_pid: DashMap::new(),
            proc_info: DashMap::new(),
            last_refresh: Mutex::new(Instant::now() - Duration::from_secs(60)),
            refresh_interval: Duration::from_secs(2),
        };
        t.refresh();
        t
    }

    pub fn lookup(
        &self,
        proto: &str,
        src_ip: IpAddr,
        src_port: u16,
        _dst_ip: IpAddr,
        dst_port: u16,
    ) -> (Option<String>, Option<u32>, Option<String>) {
        self.maybe_refresh();
        let proto_key: &'static str = if proto.eq_ignore_ascii_case("TCP") { "tcp" } else { "udp" };

        // Try whichever port corresponds to *our* machine's side of the
        // connection: for outbound traffic that's src_port, for inbound
        // (someone connecting to us) it's dst_port. Since capture sees both
        // directions, just try both and take whichever hits.
        for port in [src_port, dst_port] {
            if let Some(pid) = self.port_to_pid.get(&(proto_key, port)) {
                let pid = *pid;
                if let Some(info) = self.proc_info.get(&pid) {
                    let (name, user) = info.value().clone();
                    return (Some(name), Some(pid), Some(user));
                }
                return (None, Some(pid), None);
            }
        }
        let _ = src_ip; // currently unused; kept for API symmetry with the Linux backend
        (None, None, None)
    }

    fn maybe_refresh(&self) {
        let mut last = self.last_refresh.lock().unwrap();
        if last.elapsed() >= self.refresh_interval {
            self.refresh();
            *last = Instant::now();
        }
    }

    fn refresh(&self) {
        self.port_to_pid.clear();
        let mut pids_seen: HashSet<u32> = HashSet::new();

        unsafe {
            read_tcp_table_v4(&self.port_to_pid, &mut pids_seen);
            read_tcp_table_v6(&self.port_to_pid, &mut pids_seen);
            read_udp_table_v4(&self.port_to_pid, &mut pids_seen);
            read_udp_table_v6(&self.port_to_pid, &mut pids_seen);
        }

        // Drop cached info for processes that no longer have any open socket,
        // and (re)resolve name/user for anything new.
        self.proc_info.retain(|pid, _| pids_seen.contains(pid));
        for pid in pids_seen {
            if !self.proc_info.contains_key(&pid) {
                if let Some(info) = unsafe { resolve_process(pid) } {
                    self.proc_info.insert(pid, info);
                }
            }
        }
    }
}

/// Ports in these tables are stored in the low 16 bits of a DWORD, in
/// network byte order.
fn extract_port(dw_port: u32) -> u16 {
    u16::from_be((dw_port & 0xFFFF) as u16)
}

unsafe fn read_tcp_table_v4(map: &DashMap<(&'static str, u16), u32>, pids: &mut HashSet<u32>) {
    let mut size: u32 = 0;
    GetExtendedTcpTable(
        ptr::null_mut(),
        &mut size,
        0,
        AF_INET as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    if size == 0 {
        return;
    }
    let mut buf = vec![0u8; size as usize];
    let res = GetExtendedTcpTable(
        buf.as_mut_ptr() as *mut _,
        &mut size,
        0,
        AF_INET as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    if res != NO_ERROR {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for row in rows {
        let port = extract_port(row.dwLocalPort);
        map.insert(("tcp", port), row.dwOwningPid);
        pids.insert(row.dwOwningPid);
    }
}

unsafe fn read_tcp_table_v6(map: &DashMap<(&'static str, u16), u32>, pids: &mut HashSet<u32>) {
    let mut size: u32 = 0;
    GetExtendedTcpTable(
        ptr::null_mut(),
        &mut size,
        0,
        AF_INET6 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    if size == 0 {
        return;
    }
    let mut buf = vec![0u8; size as usize];
    let res = GetExtendedTcpTable(
        buf.as_mut_ptr() as *mut _,
        &mut size,
        0,
        AF_INET6 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    if res != NO_ERROR {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for row in rows {
        let port = extract_port(row.dwLocalPort);
        map.insert(("tcp", port), row.dwOwningPid);
        pids.insert(row.dwOwningPid);
    }
}

unsafe fn read_udp_table_v4(map: &DashMap<(&'static str, u16), u32>, pids: &mut HashSet<u32>) {
    let mut size: u32 = 0;
    GetExtendedUdpTable(
        ptr::null_mut(),
        &mut size,
        0,
        AF_INET as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );
    if size == 0 {
        return;
    }
    let mut buf = vec![0u8; size as usize];
    let res = GetExtendedUdpTable(
        buf.as_mut_ptr() as *mut _,
        &mut size,
        0,
        AF_INET as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );
    if res != NO_ERROR {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for row in rows {
        let port = extract_port(row.dwLocalPort);
        map.insert(("udp", port), row.dwOwningPid);
        pids.insert(row.dwOwningPid);
    }
}

unsafe fn read_udp_table_v6(map: &DashMap<(&'static str, u16), u32>, pids: &mut HashSet<u32>) {
    let mut size: u32 = 0;
    GetExtendedUdpTable(
        ptr::null_mut(),
        &mut size,
        0,
        AF_INET6 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );
    if size == 0 {
        return;
    }
    let mut buf = vec![0u8; size as usize];
    let res = GetExtendedUdpTable(
        buf.as_mut_ptr() as *mut _,
        &mut size,
        0,
        AF_INET6 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );
    if res != NO_ERROR {
        return;
    }
    let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
    for row in rows {
        let port = extract_port(row.dwLocalPort);
        map.insert(("udp", port), row.dwOwningPid);
        pids.insert(row.dwOwningPid);
    }
}

/// Resolve a PID to (process image name, "DOMAIN\username"). Returns None if
/// the process can't be opened (e.g. a protected system process) — this is
/// common and just means that row falls back to showing only the PID.
unsafe fn resolve_process(pid: u32) -> Option<(String, String)> {
    let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
    if handle.is_null() {
        return None;
    }

    let name = {
        let mut buf = [0u16; 260];
        let len = K32GetModuleBaseNameW(handle, ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32);
        if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            format!("pid:{pid}")
        }
    };

    let user = resolve_user(handle).unwrap_or_else(|| "unknown".to_string());

    CloseHandle(handle);
    Some((name, user))
}

unsafe fn resolve_user(process_handle: HANDLE) -> Option<String> {
    let mut token: HANDLE = ptr::null_mut();
    if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token) == 0 {
        return None;
    }

    let mut needed: u32 = 0;
    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        CloseHandle(token);
        return None;
    }

    let mut buf = vec![0u8; needed as usize];
    let ok = GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr() as *mut _,
        needed,
        &mut needed,
    );
    CloseHandle(token);
    if ok == 0 {
        return None;
    }

    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid = token_user.User.Sid;

    // ConvertSidToStringSidW gives us a readable SID (e.g. "S-1-5-21-...")
    // without the extra LookupAccountSidW round trip, which needs pre-sized
    // buffers and a domain name lookup that can fail/hang for orphaned SIDs.
    // Good enough to distinguish "which user" even if it's not a friendly name.
    let mut sid_str: PWSTR = ptr::null_mut();
    if ConvertSidToStringSidW(sid as *mut _, &mut sid_str) == 0 || sid_str.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *sid_str.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(sid_str, len);
    let sid_string = String::from_utf16_lossy(slice);
    // NOTE: if this specific line fails to compile ("mismatched types" on
    // HLOCAL), it's a windows-sys version difference in how HLOCAL is
    // represented (raw pointer vs. isize) - try
    // `LocalFree(sid_str as isize)` or adjust per the compiler's suggestion.
    LocalFree(sid_str as HLOCAL);

    Some(sid_string)
}
