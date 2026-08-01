import { useEffect, useMemo, useRef, useState } from "react";
import { PacketEvent, Stats } from "./types";
import PacketFeed from "./components/PacketFeed";
import StatsPanel from "./components/StatsPanel";
import PacketDrawer from "./components/PacketDrawer";
import { ThroughputSample } from "./components/TrafficChart";

const MAX_ROWS = 400;
const MAX_HISTORY = 40;
const ALL_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP"];
const WS_URL = `${location.protocol === "https:" ? "wss" : "ws"}://${location.hostname}:7878/ws`;

type ConnState = "connecting" | "open" | "closed";

export default function App() {
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [protoChips, setProtoChips] = useState<Set<string>>(new Set());
  const [connState, setConnState] = useState<ConnState>("connecting");
  const [stats, setStats] = useState<Stats>({ total_packets: 0, total_bytes: 0, by_protocol: {}, by_process: {} });
  const [packetsPerSec, setPacketsPerSec] = useState(0);
  const [history, setHistory] = useState<ThroughputSample[]>([]);
  const [selected, setSelected] = useState<{ pkt: PacketEvent; key: string } | null>(null);
  const [appFilter, setAppFilter] = useState<string>("");

  const bufferRef = useRef<PacketEvent[]>([]);
  const countSinceTickRef = useRef(0);
  const bytesSinceTickRef = useRef(0);
  const pausedRef = useRef(paused);
  const filterInputRef = useRef<HTMLInputElement>(null);
  pausedRef.current = paused;

  useEffect(() => {
    let socket: WebSocket;
    let retryTimer: number;

    function connect() {
      setConnState("connecting");
      socket = new WebSocket(WS_URL);

      socket.onopen = () => setConnState("open");
      socket.onclose = () => {
        setConnState("closed");
        retryTimer = window.setTimeout(connect, 2000);
      };
      socket.onerror = () => socket.close();

      socket.onmessage = (evt) => {
        countSinceTickRef.current += 1;
        if (pausedRef.current) return;
        try {
          const pkt: PacketEvent = JSON.parse(evt.data);
          bytesSinceTickRef.current += pkt.length;
          bufferRef.current = [pkt, ...bufferRef.current].slice(0, MAX_ROWS);
        } catch {
          /* ignore malformed frame */
        }
      };
    }

    connect();
    return () => {
      window.clearTimeout(retryTimer);
      socket?.close();
    };
  }, []);

  // Flush buffered packets + sample throughput on a steady interval.
  useEffect(() => {
    const id = setInterval(() => {
      setPackets(bufferRef.current);
      const pkts = countSinceTickRef.current;
      const bytes = bytesSinceTickRef.current;
      setPacketsPerSec(pkts * 2); // 500ms tick -> per-second rate
      setHistory((h) => [...h, { t: Date.now(), packets: pkts * 2, bytes: bytes * 2 }].slice(-MAX_HISTORY));
      countSinceTickRef.current = 0;
      bytesSinceTickRef.current = 0;
    }, 500);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const fetchStats = () =>
      fetch("/api/stats")
        .then((r) => r.json())
        .then(setStats)
        .catch(() => {});
    fetchStats();
    const id = setInterval(fetchStats, 1500);
    return () => clearInterval(id);
  }, []);

  // Keyboard shortcuts: "/" focus filter, "Escape" close drawer, Space pause/resume.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const typing = (e.target as HTMLElement)?.tagName === "INPUT";
      if (e.key === "/" && !typing) {
        e.preventDefault();
        filterInputRef.current?.focus();
      } else if (e.key === "Escape") {
        setSelected(null);
        filterInputRef.current?.blur();
      } else if (e.key === " " && !typing) {
        e.preventDefault();
        setPaused((p) => !p);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const toggleProtoChip = (proto: string) => {
    setProtoChips((prev) => {
      const next = new Set(prev);
      next.has(proto) ? next.delete(proto) : next.add(proto);
      return next;
    });
  };

  const quickFilter = (value: string) => {
    setFilter(value);
    filterInputRef.current?.focus();
  };

  const filtered = useMemo(() => {
    let list = packets;
    if (protoChips.size > 0) {
      list = list.filter((p) => protoChips.has(p.protocol));
    }
    if (appFilter) {
      list = list.filter((p) => p.process === appFilter);
    }
    if (filter.trim()) {
      const f = filter.toLowerCase();
      list = list.filter((p) =>
        [p.src_ip, p.dst_ip, p.process, p.user, p.protocol, p.l7_guess, p.sni, p.dns_query, String(p.src_port), String(p.dst_port)]
          .filter(Boolean)
          .some((v) => v!.toLowerCase().includes(f))
      );
    }
    return list;
  }, [packets, filter, protoChips, appFilter]);

  const appOptions = useMemo(
    () => Object.keys(stats.by_process).sort((a, b) => a.localeCompare(b)),
    [stats.by_process]
  );

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" />
          <div>
            <h1>Local Firewall</h1>
            <span className="brand-sub">traffic monitor · L2–L7</span>
          </div>
        </div>

        <div className="proto-chips">
          {ALL_PROTOCOLS.map((proto) => (
            <button
              key={proto}
              className={`chip chip-toggle ${protoChips.has(proto) ? "chip-active" : ""}`}
              onClick={() => toggleProtoChip(proto)}
            >
              {proto}
            </button>
          ))}
        </div>

        <div className="header-controls">
          <select className="app-select" value={appFilter} onChange={(e) => setAppFilter(e.target.value)}>
            <option value="">All applications</option>
            {appOptions.map((app) => (
              <option key={app} value={app}>
                {app}
              </option>
            ))}
          </select>
          <input
            ref={filterInputRef}
            className="filter-input"
            placeholder="filter · press /"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          {filter && (
            <button className="icon-btn" onClick={() => setFilter("")} aria-label="Clear filter">
              ✕
            </button>
          )}
          <button className={`btn ${paused ? "btn-active" : ""}`} onClick={() => setPaused((p) => !p)}>
            {paused ? "Resume" : "Pause"}
          </button>
          <div className={`conn-badge conn-${connState}`}>
            <span className="conn-dot" />
            {connState === "open" ? "live" : connState === "connecting" ? "connecting…" : "disconnected"}
          </div>
        </div>
      </header>

      <main className="app-body">
        <PacketFeed
          packets={filtered}
          selectedKey={selected?.key ?? null}
          onSelect={(pkt, key) => setSelected({ pkt, key })}
          onQuickFilter={quickFilter}
        />
        <StatsPanel stats={stats} packetsPerSec={packetsPerSec} history={history} onQuickFilter={quickFilter} />
      </main>

      <PacketDrawer pkt={selected?.pkt ?? null} onClose={() => setSelected(null)} onFilter={quickFilter} />
    </div>
  );
}
