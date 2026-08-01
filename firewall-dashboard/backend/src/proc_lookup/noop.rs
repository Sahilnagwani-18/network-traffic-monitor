use std::net::IpAddr;

/// Fallback used on platforms (currently: macOS) where we haven't wired up
/// process attribution yet. Capture and L2-L7 parsing still work fully;
/// this just always reports "unknown" for process/user so the UI degrades
/// gracefully instead of failing to compile.
pub struct ProcTable;

impl ProcTable {
    pub fn new() -> Self {
        ProcTable
    }

    pub fn lookup(
        &self,
        _proto: &str,
        _src_ip: IpAddr,
        _src_port: u16,
        _dst_ip: IpAddr,
        _dst_port: u16,
    ) -> (Option<String>, Option<u32>, Option<String>) {
        (None, None, None)
    }
}
