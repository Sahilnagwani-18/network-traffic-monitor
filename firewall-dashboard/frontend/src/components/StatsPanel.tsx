import { Stats } from "../types";
import TrafficChart, { ThroughputSample } from "./TrafficChart";
import ProtocolDonut from "./ProtocolDonut";
import AppBarChart from "./AppBarChart";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

interface Props {
  stats: Stats;
  packetsPerSec: number;
  history: ThroughputSample[];
  onQuickFilter: (value: string) => void;
}

export default function StatsPanel({ stats, packetsPerSec, history, onQuickFilter }: Props) {
  const protoEntries = Object.entries(stats.by_protocol).sort((a, b) => b[1] - a[1]).slice(0, 6) as [string, number][];
  const procEntries = Object.entries(stats.by_process).sort((a, b) => b[1] - a[1]).slice(0, 6) as [string, number][];

  return (
    <aside className="stats-panel">
      <div className="stat-tiles">
        <div className="stat-tile">
          <span className="stat-tile-value">{stats.total_packets.toLocaleString()}</span>
          <span className="stat-tile-label">packets</span>
        </div>
        <div className="stat-tile">
          <span className="stat-tile-value">{formatBytes(stats.total_bytes)}</span>
          <span className="stat-tile-label">total</span>
        </div>
        <div className="stat-tile stat-tile-live">
          <span className="stat-tile-value">{packetsPerSec}</span>
          <span className="stat-tile-label">pkt / sec</span>
        </div>
      </div>

      <TrafficChart data={history} />
      <ProtocolDonut data={protoEntries} />
      <AppBarChart data={procEntries} onSelect={onQuickFilter} />
    </aside>
  );
}
