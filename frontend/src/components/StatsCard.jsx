export default function StatsCard({ title, rows }) {
  return (
    <div className="stat-card">
      <div className="stat-title">{title}</div>
      {rows.map((r) => (
        <div className="stat-row" key={r.lbl}>
          <div className="stat-lbl">{r.lbl}</div>
          <div className="stat-track">
            <div className="stat-fill" style={{ width: `${r.pct}%`, background: r.color }} />
          </div>
          <div className="stat-num">
            {typeof r.num === 'number' ? Number(r.num).toFixed(1) : (r.num ?? `${Number(r.pct).toFixed(1)}%`)}
          </div>

        </div>
      ))}
    </div>
  );
}