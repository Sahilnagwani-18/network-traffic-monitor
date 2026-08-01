# Local Firewall — traffic monitor dashboard

Captures live traffic on a network interface, parses it across L2–L7, attributes
each flow to a process/user where possible, and streams it to a browser
dashboard over WebSocket. Runs entirely on localhost.

```
┌─────────────┐   raw frames   ┌────────────────────┐   JSON / WS   ┌───────────────┐
│   NIC (pcap) │ ─────────────▶ │ Rust backend (axum) │ ─────────────▶ │ React dashboard │
└─────────────┘                │  L2-L7 parser        │                └───────────────┘
                                │  /proc socket lookup │
                                └────────────────────┘
```

## What it captures

| Layer | Fields |
|---|---|
| L2 (Data Link) | Source/destination MAC, ARP — shown when you click a row to expand it, not in the main table columns |
| L3 (Network) | Source/destination IP (v4 + v6), direction (inbound/outbound) |
| L4 (Transport) | Protocol (TCP/UDP/ICMP), ports, TCP flags |
| L5–L7 (Session/App) | Best-effort app guess by port, TLS SNI hostname (from ClientHello), DNS query name |
| Attribution | Process name, PID, and OS user, resolved by matching the packet's socket against `/proc/net/{tcp,udp}` and `/proc/[pid]/fd` |

## Requirements

- **Rust** (1.75+) and **cargo**
- **libpcap** dev headers: `sudo apt install libpcap-dev` (Debian/Ubuntu) or `brew install libpcap` (macOS)
- **Node.js** 18+ and npm
- Raw packet capture requires elevated privileges (see below)
- **Windows**: also needs [Npcap](https://npcap.com) (installed in WinPcap-compatible mode) + the Npcap SDK for linking. Process/user attribution uses `GetExtendedTcpTable`/`GetExtendedUdpTable` — see `src/proc_lookup/windows.rs`. This module type-checks but hasn't been build-tested on a real Windows box; if `cargo build` errors inside it, it's almost always a `windows-sys` version-specific field/type name and is a small fix.
- **macOS/other**: capture works, but process/user attribution isn't wired up yet (falls back to empty) — `src/proc_lookup/noop.rs` is the extension point if you want to add it (via `libproc`/`lsof`-equivalent APIs).

## Run it

**1. Build the frontend**

```bash
cd frontend
npm install
npm run build        # outputs to frontend/dist, served by the Rust backend
```

**2. Run the backend**

```bash
cd backend
cargo build --release

# List available interfaces
./target/release/firewall-backend --list-interfaces

# Run (needs raw socket access)
sudo ./target/release/firewall-backend --interface eth0 --port 7878
```

Instead of `sudo`, you can grant the binary capabilities directly on Linux:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/firewall-backend
./target/release/firewall-backend --interface eth0
```

**3. Open the dashboard**

Visit **http://localhost:7878** — the backend serves the built frontend directly.

For frontend development with hot reload instead, run `npm run dev` in
`frontend/` (proxies `/ws` and `/api` to the backend on :7878) and visit
http://localhost:5173.

## Notes & limitations

- This captures traffic visible on the chosen interface (promiscuous mode is
  not enabled by default) — on a laptop that's effectively "all traffic this
  machine sends and receives."
- Process/user attribution is best-effort: short-lived connections can close
  before the `/proc` table is (re)scanned, encrypted traffic obviously can't
  be inspected past the TLS handshake, and container/namespace isolation can
  hide sockets from a simple `/proc` walk.
- TLS SNI and DNS query parsing are intentionally minimal, hand-rolled
  parsers, not full protocol stacks — enough to label a flow, not to decode
  application payloads.
- This is a **monitor**, not an enforcement firewall — it observes and
  displays traffic; it does not drop or block packets. Adding blocking would
  mean integrating with `nftables`/`iptables` (Linux) or `pf` (macOS) and is
  a natural next step if you want enforcement, not just visibility.
