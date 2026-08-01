import { PacketEvent } from "../types";

function dirLabel(direction: string): { color: string; label: string } {
  if (direction === "outbound") return { color: "var(--accent-out)", label: "OUT" };
  if (direction === "inbound") return { color: "var(--accent-in)", label: "IN" };
  return { color: "var(--accent-local)", label: "—" };
}

interface Props {
  packets: PacketEvent[];
  selectedKey: string | null;
  onSelect: (pkt: PacketEvent, key: string) => void;
  onQuickFilter: (value: string) => void;
}

export default function PacketFeed({ packets, selectedKey, onSelect, onQuickFilter }: Props) {
  const stop = (fn: () => void) => (e: React.MouseEvent) => {
    e.stopPropagation();
    fn();
  };

  return (
    <div className="feed" role="table" aria-label="Live packet stream">
      <div className="feed-header" role="row">
        <span role="columnheader">Application</span>
        <span role="columnheader">Connection</span>
        <span role="columnheader">Protocol</span>
        <span role="columnheader">App layer</span>
        <span role="columnheader">Size</span>
      </div>

      <div className="feed-body">
        {packets.map((pkt, idx) => {
          const key = `${pkt.ts}-${idx}`;
          const isSelected = selectedKey === key;
          const dir = dirLabel(pkt.direction);
          const time = new Date(pkt.ts).toLocaleTimeString(undefined, {
            hour12: false,
            minute: "2-digit",
            second: "2-digit",
          });
          return (
            <div
              key={key}
              role="row"
              className={`feed-card ${isSelected ? "feed-card-selected" : ""}`}
              onClick={() => onSelect(pkt, key)}
              style={{ borderLeftColor: dir.color }}
            >
              <div className="feed-col feed-col-app" role="cell">
                <span className="feed-dir-badge" style={{ color: dir.color, borderColor: dir.color }}>
                  {dir.label}
                </span>
                <div className="feed-app-text">
                  <span
                    className={pkt.process ? "clickable app-name" : "app-name muted"}
                    onClick={pkt.process ? stop(() => onQuickFilter(pkt.process!)) : undefined}
                  >
                    {pkt.process ?? "unknown"}
                  </span>
                  <span className="feed-meta mono">
                    {pkt.user ?? "—"} · {time}
                  </span>
                </div>
              </div>

              <div className="feed-col feed-col-conn" role="cell">
                <span className="mono clickable" onClick={pkt.src_ip ? stop(() => onQuickFilter(pkt.src_ip!)) : undefined}>
                  {pkt.src_ip ?? pkt.src_mac}
                  {pkt.src_port !== null && <span className="port">:{pkt.src_port}</span>}
                </span>
                <span className="feed-arrow">→</span>
                <span className="mono clickable" onClick={pkt.dst_ip ? stop(() => onQuickFilter(pkt.dst_ip!)) : undefined}>
                  {pkt.dst_ip ?? pkt.dst_mac}
                  {pkt.dst_port !== null && <span className="port">:{pkt.dst_port}</span>}
                </span>
              </div>

              <div className="feed-col" role="cell">
                <span
                  className={`proto-tag proto-${pkt.protocol.toLowerCase()} clickable`}
                  onClick={stop(() => onQuickFilter(pkt.protocol))}
                >
                  {pkt.protocol}
                </span>
              </div>

              <div className="feed-col mono feed-col-l7" role="cell">
                {pkt.sni ?? pkt.dns_query ?? pkt.l7_guess}
              </div>

              <div className="feed-col mono muted feed-col-len" role="cell">
                {pkt.length}B
              </div>
            </div>
          );
        })}
      </div>

      {packets.length === 0 && (
        <div className="empty-state">
          <p>No packets match right now.</p>
          <p className="muted">Waiting for traffic, or your filter is too narrow — try clearing it.</p>
        </div>
      )}
    </div>
  );
}
