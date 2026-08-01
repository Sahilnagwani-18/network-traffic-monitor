import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

const COLORS: Record<string, string> = {
  TCP: "#4f46e5",
  UDP: "#d97706",
  ICMP: "#0891b2",
  ARP: "#dc2626",
};
const FALLBACK = "#94a3b8";

export default function ProtocolDonut({ data }: { data: [string, number][] }) {
  const chartData = data.map(([name, value]) => ({ name, value }));
  const total = chartData.reduce((s, d) => s + d.value, 0);

  return (
    <div className="chart-card">
      <div className="chart-card-head">
        <h3>Protocol mix</h3>
        <span className="chart-legend">{total.toLocaleString()} pkts</span>
      </div>
      {total === 0 ? (
        <p className="empty-hint">Waiting for traffic…</p>
      ) : (
        <div className="donut-row">
          <ResponsiveContainer width={92} height={92}>
            <PieChart>
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="name"
                innerRadius={28}
                outerRadius={44}
                paddingAngle={2}
                strokeWidth={0}
                isAnimationActive={false}
              >
                {chartData.map((d) => (
                  <Cell key={d.name} fill={COLORS[d.name] ?? FALLBACK} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  fontSize: 11,
                  fontFamily: "var(--mono)",
                }}
                formatter={(value, name) => [`${value} pkts`, name]}
              />
            </PieChart>
          </ResponsiveContainer>
          <ul className="donut-legend">
            {chartData
              .sort((a, b) => b.value - a.value)
              .map((d) => (
                <li key={d.name}>
                  <i className="legend-dot" style={{ background: COLORS[d.name] ?? FALLBACK }} />
                  <span className="donut-legend-name">{d.name}</span>
                  <span className="donut-legend-pct">{total > 0 ? Math.round((d.value / total) * 100) : 0}%</span>
                </li>
              ))}
          </ul>
        </div>
      )}
    </div>
  );
}
