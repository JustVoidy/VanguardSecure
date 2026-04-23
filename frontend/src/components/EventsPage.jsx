import React, { useState } from "react";

const SEV_COLOR = {
  CRITICAL: "#ff2d55",
  HIGH:     "#f97316",
  MEDIUM:   "#f59e0b",
  LOW:      "#10b981",
  NORMAL:   "#8b949e",
};

export default function EventsPage({ events = [] }) {
  const [filter, setFilter]         = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");

  const filtered = events.filter(e => {
    const matchesSev    = filter === "ALL" || e.sev === filter;
    const matchesSearch =
      (e.src  || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.type || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.dst  || "").toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const counts = events.reduce((acc, e) => {
    acc[e.sev] = (acc[e.sev] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="content" style={{ animation: "fadeUp 0.4s ease both" }}>
      <div className="section-hd">
        <div className="section-title">Security Threat Logs</div>
        <div className="section-sub">
          {events.length} total events — live updates every 5s
        </div>
      </div>

      {/* Summary badges */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "16px", flexWrap: "wrap" }}>
        {Object.entries(SEV_COLOR).map(([sev, color]) =>
          counts[sev] ? (
            <span key={sev} style={{
              background: color + "22", border: `1px solid ${color}44`,
              color, borderRadius: "6px", padding: "4px 10px",
              fontSize: "11px", fontWeight: 700, letterSpacing: "0.4px",
            }}>
              {counts[sev]} {sev}
            </span>
          ) : null
        )}
      </div>

      {/* Controls */}
      <div className="stat-card" style={{ marginBottom: "20px", padding: "16px" }}>
        <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "200px" }}>
            <input
              type="text"
              placeholder="Search by IP or attack type…"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`notif-filter-btn${filter === f ? " active" : ""}`}
                style={{ padding: "6px 12px", cursor: "pointer" }}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="stat-card" style={{ padding: "0", overflowX: "auto" }}>
        <div className="ms-rules-table" style={{ minWidth: "640px" }}>
          <div className="ms-rules-header">
            <div>EVENT TYPE</div>
            <div>SOURCE IP</div>
            <div>TARGET IP</div>
            <div>SEVERITY</div>
            <div>AI CONFIDENCE</div>
            <div style={{ textAlign: "right" }}>TIMESTAMP</div>
          </div>

          {filtered.length === 0 ? (
            <div style={{ padding: "48px", textAlign: "center", color: "var(--t3)", fontSize: "13px" }}>
              {events.length === 0
                ? "No threat events yet — start capture to begin monitoring."
                : "No events match the current filter."}
            </div>
          ) : (
            filtered.map((e, i) => {
              const color = SEV_COLOR[e.sev] || SEV_COLOR.NORMAL;
              return (
                <div className="ms-rule-row" key={i}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <div className="ev-dot" style={{ background: color }} />
                    <span className="ms-rule-name">{e.type}</span>
                  </div>
                  <div style={{ fontFamily: "monospace", fontSize: "13px" }}>{e.src}</div>
                  <div style={{ fontFamily: "monospace", fontSize: "13px", color: "var(--t3)" }}>
                    {e.dst || "—"}
                  </div>
                  <div>
                    <span style={{
                      background: color + "22", color, border: `1px solid ${color}44`,
                      borderRadius: "4px", padding: "2px 8px",
                      fontSize: "11px", fontWeight: 700, letterSpacing: "0.3px",
                    }}>
                      {e.sev}
                    </span>
                  </div>
                  <div style={{ color: "#00d4ff", fontWeight: 600 }}>{e.score || "—"}</div>
                  <div style={{ textAlign: "right", color: "var(--t3)", fontSize: "12px" }}>{e.time}</div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
