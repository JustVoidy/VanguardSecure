import React, { useState } from "react";

export default function EventsPage({ events = [] }) {
  const [filter, setFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");

  const filtered = events.filter(e => {
    const matchesType = filter === "ALL" || e.sev === filter;
    const matchesSearch = (e.src || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
                          (e.type || '').toLowerCase().includes(searchTerm.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="content" style={{ animation: 'fadeUp 0.4s ease both' }}>
      <div className="section-hd">
        <div className="section-title">Security Threat Logs</div>
        <div className="section-sub">Comprehensive history of detected anomalies and attacks</div>
      </div>

      <div className="stat-card" style={{ marginBottom: '20px', padding: '16px' }}>
        <div className="events-controls" style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="search" style={{ flex: 1, minWidth: '200px' }}>
            <input 
              type="text" 
              placeholder="Search by IP or Attack Type..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {["ALL", "HIGH", "CRITICAL"].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`notif-filter-btn ${filter === f ? 'active' : ''}`}
                style={{ padding: '6px 12px', cursor: 'pointer' }}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="stat-card" style={{ padding: '0', overflowX: 'auto' }}>
        <div className="ms-rules-table" style={{ minWidth: '600px' }}>
          <div className="ms-rules-header">
            <div>EVENT TYPE</div>
            <div>SOURCE IP</div>
            <div>TARGET IP</div>
            <div>SEVERITY</div>
            <div>AI CONFIDENCE</div>
            <div style={{ textAlign: 'right' }}>TIMESTAMP</div>
          </div>
          
          {filtered.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
              No matching security logs found.
            </div>
          ) : filtered.map((e, i) => (
            <div className="ms-rule-row" key={i} style={{ gridTemplateColumns: '1.5fr 1.2fr 1.2fr 1fr 1fr 1fr' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div className="ev-dot" style={{ background: e.col }} />
                <span className="ms-rule-name">{e.type}</span>
              </div>
              <div className="ms-rule-value" style={{ fontFamily: 'monospace', fontSize: '13px' }}>{e.src}</div>
              <div className="ms-rule-value" style={{ fontFamily: 'monospace', fontSize: '13px', color: '#8b949e' }}>{e.dst || "N/A"}</div>

              <div>
                <span 
                  className="ms-ip-badge red" 
                  style={{ 
                    background: e.col + '22', 
                    color: e.col,
                    borderColor: e.col + '44'
                  }}
                >
                  {e.sev}
                </span>
              </div>
              <div style={{ color: '#00d4ff', fontWeight: 600 }}>{e.score || "N/A"}</div>
              <div className="ms-rule-type" style={{ textAlign: 'right' }}>{e.time}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
