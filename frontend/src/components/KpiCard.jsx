export default function KpiCard({ label, value, trend, trendColor, barColor, borderColor, iconBg, iconStroke, children }) {
  return (
    <div className="kpi-card" style={borderColor ? { borderColor } : {}}>
      <div className="kpi-label">
        {label}
        <div className="kpi-icon" style={{ background: iconBg }}>
          {children}
        </div>
      </div>
      <div className="kpi-value" style={value.color ? { color: value.color } : {}}>
        {value.text}
      </div>
      <div className="kpi-trend" style={{ color: trendColor }}>{trend}</div>
      <div className="kpi-bar" style={{ background: barColor }} />
    </div>
  );
}