//! Socket -> process -> user attribution.
//!
//! The capture/parsing code (`packet.rs`) is OS-agnostic, but "which process
//! and user owns this socket" is answered completely differently per OS:
//! Linux walks `/proc`, Windows calls `GetExtendedTcpTable`/`GetExtendedUdpTable`.
//! Every backend exposes the same `ProcTable` API (`new()` + `lookup(...)`),
//! so `capture.rs` doesn't need to know which platform it's on.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcTable;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::ProcTable;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod noop;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use noop::ProcTable;
