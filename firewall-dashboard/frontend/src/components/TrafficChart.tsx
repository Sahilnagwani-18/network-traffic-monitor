import { AreaChart, Area, ResponsiveContainer, YAxis, Tooltip, CartesianGrid } from "recharts";

export interface ThroughputSample {
  t: number;
  packets: number;
  bytes: number;
}

export default function TrafficChart({ data }: { data: ThroughputSample[] }) {
  return (
    <div className="chart-card">
      <div className="chart-card-head">
        <h3>Throughput</h3>
        <span className="chart-legend">
          <i className="legend-dot" style={{ background: "var(--accent-out)" }} /> packets/s
        </span>
      </div>
      <div className="chart-body">
        <ResponsiveContainer width="100%" height={90}>
          <AreaChart data={data} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="pktGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent-out)" stopOpacity={0.28} />
                <stop offset="100%" stopColor="var(--accent-out)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 4" />
            <YAxis hide domain={[0, "dataMax + 5"]} />
            <Tooltip
              cursor={{ stroke: "var(--border)", strokeWidth: 1 }}
              contentStyle={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                fontSize: 11,
                fontFamily: "var(--mono)",
              }}
              labelFormatter={() => ""}
              formatter={(value) => [`${value} pkt/s`, ""]}
            />
            <Area
              type="monotone"
              dataKey="packets"
              stroke="var(--accent-out)"
              strokeWidth={2}
              fill="url(#pktGradient)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
