import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export default function AppBarChart({
  data,
  onSelect,
}: {
  data: [string, number][];
  onSelect: (app: string) => void;
}) {
  const chartData = data.map(([name, count]) => ({ name: name.length > 16 ? name.slice(0, 15) + "…" : name, full: name, count }));

  return (
    <div className="chart-card">
      <div className="chart-card-head">
        <h3>Top applications</h3>
        <span className="chart-legend">click to filter</span>
      </div>
      {chartData.length === 0 ? (
        <p className="empty-hint">No process attribution yet</p>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(90, chartData.length * 26)}>
          <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              width={100}
              tick={{ fill: "var(--muted)", fontSize: 11, fontFamily: "var(--mono)" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "var(--surface-3)" }}
              contentStyle={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                fontSize: 11,
                fontFamily: "var(--mono)",
              }}
              formatter={(value) => [`${value} pkts`, ""]}
              labelFormatter={(_, payload) => payload?.[0]?.payload?.full ?? ""}
            />
            <Bar
              dataKey="count"
              radius={[0, 4, 4, 0]}
              barSize={14}
              isAnimationActive={false}
              onClick={(d: any) => onSelect(d.full)}
              cursor="pointer"
            >
              {chartData.map((d) => (
                <Cell key={d.full} fill="var(--accent-out)" />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
