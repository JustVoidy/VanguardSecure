import '../App.css';
import { useState, useEffect, useCallback } from 'react';

const BACKEND = typeof window.electronConfig !== 'undefined'
  ? (window.electronConfig.get().backendUrl || 'http://localhost:8000')
  : (process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000');

function apiFetch(url, opts = {}) {
  const token = localStorage.getItem('token');
  return fetch(url, {
    ...opts,
    headers: { ...(opts.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
}

// ── Shared primitives ────────────────────────────────────────────────────────

function SaveBar({ onSave, saving, msg }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '24px' }}>
      <button className="up-btn-primary" onClick={onSave} disabled={saving}>
        {saving ? 'Saving…' : 'Save Changes'}
      </button>
      {msg && (
        <span style={{ fontSize: '12px', color: msg.startsWith('Saved') ? '#10b981' : '#ff2d55' }}>
          {msg}
        </span>
      )}
    </div>
  );
}

function Field({ label, hint, children }) {
  return (
    <div style={{ marginBottom: '20px' }}>
      <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--t2)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>
        {label}
      </label>
      {children}
      {hint && <div style={{ fontSize: '11px', color: 'var(--t3)', marginTop: '5px' }}>{hint}</div>}
    </div>
  );
}

// ── Tab: DDoS Protection ─────────────────────────────────────────────────────

const DDOS_DEFAULTS = [
  { key: 'syn_flood',  name: 'SYN Flood',   sub: 'Block high-rate TCP SYN flows with low ACK ratio',      icon: '⚡', enabled: true  },
  { key: 'udp_flood',  name: 'UDP Flood',    sub: 'Drop anomalous UDP bursts exceeding threshold',          icon: '📡', enabled: true  },
  { key: 'http_flood', name: 'HTTP Flood',   sub: 'Rate-limit HTTP request storms at the application layer', icon: '🌐', enabled: false },
  { key: 'icmp_flood', name: 'ICMP Flood',   sub: 'Limit ICMP echo request volume per source',              icon: '🔔', enabled: false },
];

function TabDDoS({ backend, BACKEND: B }) {
  const [cfg, setCfg]         = useState(null);
  const [protections, setProtections] = useState(DDOS_DEFAULTS);
  const [saving, setSaving]   = useState(false);
  const [msg, setMsg]         = useState('');

  useEffect(() => {
    apiFetch(`${B}/mitigation/capture-config`).then(r => r.json()).then(setCfg).catch(() => {});
    apiFetch(`${B}/mitigation/`).then(r => r.json()).then(data => {
      if (data.ddos && data.ddos.length > 0) {
        setProtections(DDOS_DEFAULTS.map(d => {
          const saved = data.ddos.find(x => x.key === d.key);
          return saved ? { ...d, enabled: saved.enabled } : d;
        }));
      }
    }).catch(() => {});
  }, [B]);

  function toggle(key) {
    setProtections(p => p.map(x => x.key === key ? { ...x, enabled: !x.enabled } : x));
  }

  async function save() {
    setSaving(true); setMsg('');
    try {
      // save detection params
      const cfgRes = await apiFetch(`${B}/mitigation/capture-config`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_threshold:   parseFloat(cfg.alert_threshold),
          min_packets:       parseInt(cfg.min_packets),
          flow_window:       parseFloat(cfg.flow_window),
          min_flow_duration: parseFloat(cfg.min_flow_duration),
          sampling_rate:     parseFloat(cfg.sampling_rate),
          interface:         cfg.interface,
        }),
      });
      // save protection toggles
      const mitRes = await apiFetch(`${B}/mitigation/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ddos: protections.map(({ key, enabled }) => ({ key, enabled })), rates: [], blacklist: [], whitelist: [], rules: [] }),
      });
      setMsg(cfgRes.ok && mitRes.ok ? 'Saved — restart capture to apply.' : 'Save failed.');
    } catch { setMsg('Cannot reach backend.'); }
    finally { setSaving(false); }
  }

  if (!cfg) return <div style={{ color: 'var(--t3)', fontSize: '13px', padding: '10px 0' }}>Loading…</div>;

  return (
    <div className="ms-section">
      <div className="ms-section-title">DDoS Protection</div>
      <p className="ms-section-sub" style={{ marginBottom: '20px' }}>
        Toggle attack type protections and tune detection parameters. Restart capture after saving.
      </p>

      {/* Protection toggles */}
      <div className="ms-toggle-list" style={{ marginBottom: '28px' }}>
        {protections.map(p => (
          <div key={p.key} className={`ms-toggle-card${p.enabled ? ' active' : ''}`}>
            <div className="ms-toggle-left">
              <div className="ms-toggle-icon" style={{ background: p.enabled ? 'rgba(0,212,255,.1)' : 'var(--muted)', fontSize: '16px' }}>
                {p.icon}
              </div>
              <div>
                <div className="ms-toggle-name">{p.name}</div>
                <div className="ms-toggle-sub">{p.sub}</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={`ms-status-pill ${p.enabled ? 'on' : 'off'}`}>{p.enabled ? 'ACTIVE' : 'DISABLED'}</span>
              <button
                onClick={() => toggle(p.key)}
                style={{
                  width: '42px', height: '22px', borderRadius: '11px', border: 'none', cursor: 'pointer',
                  background: p.enabled ? 'var(--cyan)' : 'var(--muted)', position: 'relative', transition: 'background .2s',
                }}
              >
                <span style={{
                  position: 'absolute', top: '3px', left: p.enabled ? '22px' : '3px',
                  width: '16px', height: '16px', borderRadius: '50%', background: '#fff', transition: 'left .2s',
                }} />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Detection parameters */}
      <div className="ms-section-title" style={{ fontSize: '14px', marginBottom: '16px' }}>Detection Parameters</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '0 40px' }}>
        <Field label="Alert Threshold" hint="Probability cutoff for ATTACK (0.0–1.0). Higher = fewer false positives.">
          <input type="number" value={cfg.alert_threshold} min={0} max={1} step={0.01}
            onChange={e => setCfg(p => ({ ...p, alert_threshold: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
        <Field label="Min Packets per Flow" hint="Flows with fewer packets are dropped before scoring.">
          <input type="number" value={cfg.min_packets} min={1} max={100}
            onChange={e => setCfg(p => ({ ...p, min_packets: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
        <Field label="Flow Window (s)" hint="How long to accumulate a flow before scoring.">
          <input type="number" value={cfg.flow_window} min={1} max={60} step={0.5}
            onChange={e => setCfg(p => ({ ...p, flow_window: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
        <Field label="Min Flow Duration (s)" hint="Flows shorter than this are skipped.">
          <input type="number" value={cfg.min_flow_duration} min={0} max={30} step={0.1}
            onChange={e => setCfg(p => ({ ...p, min_flow_duration: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
        <Field label="Sampling Rate" hint="Fraction of flows sent to model (1.0 = all flows).">
          <input type="number" value={cfg.sampling_rate} min={0.01} max={1} step={0.01}
            onChange={e => setCfg(p => ({ ...p, sampling_rate: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
        <Field label="Network Interface" hint="Interface capture sniffs on.">
          <input value={cfg.interface}
            onChange={e => setCfg(p => ({ ...p, interface: e.target.value }))}
            style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 12px', fontSize: '13px', width: '140px' }} />
        </Field>
      </div>

      <SaveBar onSave={save} saving={saving} msg={msg} />
    </div>
  );
}

// ── Tab: Rate Limiting ───────────────────────────────────────────────────────

const RATE_DEFAULTS = [
  { key: 'http_rps',   name: 'HTTP Requests',    limit: 1000, max: 5000, step: 100, unit: 'req/s',  enabled: true  },
  { key: 'syn_pps',    name: 'SYN Packets',       limit: 500,  max: 2000, step: 50,  unit: 'pkt/s',  enabled: true  },
  { key: 'udp_pps',    name: 'UDP Packets',        limit: 500,  max: 2000, step: 50,  unit: 'pkt/s',  enabled: true  },
  { key: 'conn_per_ip',name: 'Connections per IP', limit: 100,  max: 500,  step: 10,  unit: 'conn/s', enabled: false },
];

function TabRateLimit({ BACKEND: B }) {
  const [rates, setRates]   = useState(RATE_DEFAULTS);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  useEffect(() => {
    apiFetch(`${B}/mitigation/`).then(r => r.json()).then(data => {
      if (data.rates && data.rates.length > 0) {
        setRates(RATE_DEFAULTS.map(d => {
          const saved = data.rates.find(x => x.key === d.key);
          return saved ? { ...d, ...saved } : d;
        }));
      }
    }).catch(() => {});
  }, [B]);

  async function save() {
    setSaving(true); setMsg('');
    try {
      const res = await apiFetch(`${B}/mitigation/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ddos: [], rates: rates.map(({ key, limit, enabled }) => ({ key, limit, enabled })), blacklist: [], whitelist: [], rules: [] }),
      });
      setMsg(res.ok ? 'Saved.' : 'Save failed.');
    } catch { setMsg('Cannot reach backend.'); }
    finally { setSaving(false); }
  }

  return (
    <div className="ms-section">
      <div className="ms-section-title">Rate Limiting</div>
      <p className="ms-section-sub" style={{ marginBottom: '20px' }}>
        Set per-source thresholds for each traffic type. Flows exceeding these limits are flagged.
      </p>

      <div className="ms-rate-grid">
        {rates.map(r => (
          <div key={r.key} className="ms-rate-card">
            <div className="ms-rate-top">
              <span className="ms-rate-label">{r.name}</span>
              <span>
                <span className="ms-rate-val">{r.limit}</span>
                <span className="ms-rate-unit"> {r.unit}</span>
              </span>
            </div>
            <input type="range" className="ms-slider"
              min={r.step} max={r.max} step={r.step} value={r.limit}
              onChange={e => setRates(p => p.map(x => x.key === r.key ? { ...x, limit: Number(e.target.value) } : x))}
            />
            <div className="ms-slider-labels"><span>{r.step}</span><span>{r.max / 2}</span><span>{r.max}</span></div>
            <div className="ms-rate-bar"><div className="ms-rate-fill" style={{ width: `${(r.limit / r.max) * 100}%` }} /></div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px' }}>
              <span style={{ fontSize: '11px', color: 'var(--t3)' }}>Enforcement</span>
              <button
                onClick={() => setRates(p => p.map(x => x.key === r.key ? { ...x, enabled: !x.enabled } : x))}
                style={{
                  width: '38px', height: '20px', borderRadius: '10px', border: 'none', cursor: 'pointer',
                  background: r.enabled ? 'var(--cyan)' : 'var(--muted)', position: 'relative', transition: 'background .2s',
                }}
              >
                <span style={{ position: 'absolute', top: '2px', left: r.enabled ? '19px' : '2px', width: '16px', height: '16px', borderRadius: '50%', background: '#fff', transition: 'left .2s' }} />
              </button>
            </div>
          </div>
        ))}
      </div>

      <SaveBar onSave={save} saving={saving} msg={msg} />
    </div>
  );
}

// ── Tab: IP Manager ──────────────────────────────────────────────────────────

function TabIPManager({ BACKEND: B }) {
  const [blacklist, setBlacklist] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [input, setInput]         = useState('');
  const [mode, setMode]           = useState('blacklist');
  const [saving, setSaving]       = useState(false);
  const [msg, setMsg]             = useState('');

  useEffect(() => {
    apiFetch(`${B}/mitigation/`).then(r => r.json()).then(data => {
      setBlacklist(data.blacklist || []);
      setWhitelist(data.whitelist || []);
    }).catch(() => {});
  }, [B]);

  function addIP() {
    const ip = input.trim();
    if (!ip) return;
    if (mode === 'blacklist' && !blacklist.includes(ip)) setBlacklist(p => [...p, ip]);
    if (mode === 'whitelist' && !whitelist.includes(ip)) setWhitelist(p => [...p, ip]);
    setInput('');
  }

  function removeIP(ip, list) {
    if (list === 'blacklist') setBlacklist(p => p.filter(x => x !== ip));
    else setWhitelist(p => p.filter(x => x !== ip));
  }

  async function save() {
    setSaving(true); setMsg('');
    try {
      const res = await apiFetch(`${B}/mitigation/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ddos: [], rates: [], blacklist, whitelist, rules: [] }),
      });
      setMsg(res.ok ? 'Saved.' : 'Save failed.');
    } catch { setMsg('Cannot reach backend.'); }
    finally { setSaving(false); }
  }

  return (
    <div className="ms-section">
      <div className="ms-section-title">IP Manager</div>
      <p className="ms-section-sub" style={{ marginBottom: '20px' }}>
        Blacklisted IPs are blocked outright. Whitelisted IPs bypass all detection.
      </p>

      {/* Add IP row */}
      <div className="ms-ip-add-card">
        <div className="ms-ip-mode-tabs">
          <button className={`ms-ip-mode-tab${mode === 'blacklist' ? ' active-red' : ''}`}   onClick={() => setMode('blacklist')}>Blacklist</button>
          <button className={`ms-ip-mode-tab${mode === 'whitelist' ? ' active-green' : ''}`} onClick={() => setMode('whitelist')}>Whitelist</button>
        </div>
        <div className="ms-ip-input-row">
          <input className="ms-ip-input" placeholder="Enter IP address or CIDR (e.g. 192.168.1.1 or 10.0.0.0/8)"
            value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addIP()} />
          <button className="up-btn-primary" onClick={addIP}>Add</button>
        </div>
      </div>

      {/* Lists */}
      <div className="ms-ip-grid">
        {[['blacklist', blacklist, 'red', 'BLOCKED'], ['whitelist', whitelist, 'green', 'ALLOWED']].map(([key, list, color, badge]) => (
          <div key={key} className="ms-ip-col">
            <div className={`ms-ip-col-header ${color}`}>
              {key === 'blacklist' ? '⛔' : '✅'} {key.charAt(0).toUpperCase() + key.slice(1)}
              <span className="ms-ip-count">{list.length}</span>
            </div>
            {list.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', fontSize: '12px', color: 'var(--t3)' }}>No IPs added</div>
            ) : list.map(ip => (
              <div key={ip} className="ms-ip-row">
                <span className="ms-ip-addr">{ip}</span>
                <span className={`ms-ip-badge ${color}`}>{badge}</span>
                <button className="ms-ip-del" onClick={() => removeIP(ip, key)}>✕</button>
              </div>
            ))}
          </div>
        ))}
      </div>

      <SaveBar onSave={save} saving={saving} msg={msg} />
    </div>
  );
}

// ── Tab: Firewall Rules ──────────────────────────────────────────────────────

const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ANY'];
const ACTIONS   = ['BLOCK', 'ALLOW', 'LOG'];

function TabFirewall({ BACKEND: B }) {
  const [rules, setRules]   = useState([]);
  const [draft, setDraft]   = useState({ name: '', protocol: 'TCP', port: '', action: 'BLOCK' });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  useEffect(() => {
    apiFetch(`${B}/mitigation/`).then(r => r.json()).then(data => {
      setRules(data.rules || []);
    }).catch(() => {});
  }, [B]);

  function addRule() {
    if (!draft.name) return;
    setRules(p => [...p, { id: Date.now(), ...draft }]);
    setDraft({ name: '', protocol: 'TCP', port: '', action: 'BLOCK' });
  }

  async function save() {
    setSaving(true); setMsg('');
    try {
      const res = await apiFetch(`${B}/mitigation/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ddos: [], rates: [], blacklist: [], whitelist: [], rules }),
      });
      setMsg(res.ok ? 'Saved.' : 'Save failed.');
    } catch { setMsg('Cannot reach backend.'); }
    finally { setSaving(false); }
  }

  const selectStyle = { background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--t1)', padding: '8px 10px', fontSize: '13px' };
  const ACTION_COLOR = { BLOCK: '#ff2d55', ALLOW: '#10b981', LOG: '#f59e0b' };

  return (
    <div className="ms-section">
      <div className="ms-section-title">Firewall Rules</div>
      <p className="ms-section-sub" style={{ marginBottom: '20px' }}>
        Define custom traffic filtering rules. Rules are evaluated in order.
      </p>

      {/* Rule builder */}
      <div className="ms-ip-add-card" style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ flex: 2, minWidth: '160px' }}>
          <div style={{ fontSize: '11px', color: 'var(--t3)', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Rule Name</div>
          <input className="ms-ip-input" placeholder="e.g. Block SSH" value={draft.name}
            onChange={e => setDraft(p => ({ ...p, name: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && addRule()} />
        </div>
        <div>
          <div style={{ fontSize: '11px', color: 'var(--t3)', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Protocol</div>
          <select style={selectStyle} value={draft.protocol} onChange={e => setDraft(p => ({ ...p, protocol: e.target.value }))}>
            {PROTOCOLS.map(p => <option key={p}>{p}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: '11px', color: 'var(--t3)', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Port</div>
          <input className="ms-ip-input" placeholder="any" style={{ width: '80px' }} value={draft.port}
            onChange={e => setDraft(p => ({ ...p, port: e.target.value }))} />
        </div>
        <div>
          <div style={{ fontSize: '11px', color: 'var(--t3)', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Action</div>
          <select style={selectStyle} value={draft.action} onChange={e => setDraft(p => ({ ...p, action: e.target.value }))}>
            {ACTIONS.map(a => <option key={a}>{a}</option>)}
          </select>
        </div>
        <button className="up-btn-primary" onClick={addRule}>Add Rule</button>
      </div>

      {/* Rules table */}
      <div className="ms-rules-table" style={{ marginTop: '16px' }}>
        <div className="ms-rules-header">
          <div>RULE NAME</div>
          <div>PROTOCOL</div>
          <div>PORT</div>
          <div>ACTION</div>
          <div></div>
          <div></div>
        </div>
        {rules.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', fontSize: '13px', color: 'var(--t3)' }}>No rules defined yet.</div>
        ) : rules.map((r, i) => (
          <div key={r.id || i} className="ms-rule-row">
            <div className="ms-rule-name">{r.name}</div>
            <div className="ms-rule-value" style={{ fontFamily: 'monospace', fontSize: '12px' }}>{r.protocol}</div>
            <div className="ms-rule-value" style={{ fontFamily: 'monospace', fontSize: '12px' }}>{r.port || 'any'}</div>
            <div>
              <span style={{
                background: (ACTION_COLOR[r.action] || '#8b949e') + '22',
                color: ACTION_COLOR[r.action] || '#8b949e',
                border: `1px solid ${(ACTION_COLOR[r.action] || '#8b949e')}44`,
                borderRadius: '4px', padding: '2px 8px', fontSize: '11px', fontWeight: 700,
              }}>
                {r.action}
              </span>
            </div>
            <div />
            <div style={{ textAlign: 'right' }}>
              <button className="ms-ip-del" onClick={() => setRules(p => p.filter((_, j) => j !== i))}>✕</button>
            </div>
          </div>
        ))}
      </div>

      <SaveBar onSave={save} saving={saving} msg={msg} />
    </div>
  );
}

// ── Tab: User Management ─────────────────────────────────────────────────────

function TabUsers({ BACKEND: B }) {
  const [users, setUsers]   = useState([]);
  const [draft, setDraft]   = useState({ name: '', email: '', password: '' });
  const [creating, setCreating] = useState(false);
  const [msg, setMsg]       = useState('');

  const loadUsers = useCallback(() => {
    apiFetch(`${B}/auth/users`).then(r => r.json()).then(setUsers).catch(() => {});
  }, [B]);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  async function createUser() {
    if (!draft.name || !draft.email || !draft.password) { setMsg('All fields required.'); return; }
    setCreating(true); setMsg('');
    try {
      const res = await apiFetch(`${B}/auth/signup`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      });
      const data = await res.json();
      if (!res.ok) { setMsg(data.detail || 'Failed to create user.'); return; }
      setMsg(`User ${draft.email} created.`);
      setDraft({ name: '', email: '', password: '' });
      loadUsers();
    } catch { setMsg('Cannot reach backend.'); }
    finally { setCreating(false); }
  }

  return (
    <div className="ms-section">
      <div className="ms-section-title">User Management</div>
      <p className="ms-section-sub" style={{ marginBottom: '20px' }}>
        All users are stored in the backend database and can log in to the admin dashboard.
      </p>

      {/* Create user form */}
      <div className="ms-ip-add-card" style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {[['Full Name', 'name', 'text'], ['Email', 'email', 'email'], ['Password', 'password', 'password']].map(([label, key, type]) => (
          <div key={key} style={{ flex: 1, minWidth: '140px' }}>
            <div style={{ fontSize: '11px', color: 'var(--t3)', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '0.4px' }}>{label}</div>
            <input className="ms-ip-input" type={type} placeholder={label} value={draft[key]}
              onChange={e => setDraft(p => ({ ...p, [key]: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && createUser()} />
          </div>
        ))}
        <button className="up-btn-primary" onClick={createUser} disabled={creating}>
          {creating ? 'Creating…' : 'Add User'}
        </button>
      </div>
      {msg && (
        <div style={{ marginTop: '10px', fontSize: '12px', color: msg.includes('created') ? '#10b981' : '#ff2d55' }}>
          {msg}
        </div>
      )}

      {/* Users table */}
      <div className="ms-rules-table" style={{ marginTop: '20px' }}>
        <div className="ms-rules-header" style={{ gridTemplateColumns: '1fr 2fr 1fr 1fr 1fr 1fr' }}>
          <div>#</div><div>EMAIL</div><div>NAME</div><div /><div /><div />
        </div>
        {users.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', fontSize: '13px', color: 'var(--t3)' }}>No users found.</div>
        ) : users.map((u, i) => (
          <div key={u.id} className="ms-rule-row" style={{ gridTemplateColumns: '1fr 2fr 1fr 1fr 1fr 1fr' }}>
            <div style={{ fontSize: '12px', color: 'var(--t3)' }}>#{u.id}</div>
            <div style={{ fontFamily: 'monospace', fontSize: '13px' }}>{u.email}</div>
            <div>{u.name}</div>
            <div><span className="ms-ip-badge green">ADMIN</span></div>
            <div /><div />
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Root component ───────────────────────────────────────────────────────────

const TABS = [
  { id: 'ddos',      label: 'DDoS Protection' },
  { id: 'ratelimit', label: 'Rate Limiting' },
  { id: 'ipmgr',     label: 'IP Manager' },
  { id: 'rules',     label: 'Firewall Rules' },
  { id: 'users',     label: 'User Management' },
];

export default function MitigationSettings({ onBack }) {
  const [activeTab, setActiveTab] = useState('ddos');

  const TAB_COMPONENT = {
    ddos:      <TabDDoS      BACKEND={BACKEND} />,
    ratelimit: <TabRateLimit BACKEND={BACKEND} />,
    ipmgr:     <TabIPManager BACKEND={BACKEND} />,
    rules:     <TabFirewall  BACKEND={BACKEND} />,
    users:     <TabUsers     BACKEND={BACKEND} />,
  };

  return (
    <div className="up-shell">
      <div className="up-topbar">
        <button className="up-back-btn" onClick={onBack}>← Back</button>
        <div className="up-topbar-title">Settings</div>
      </div>
      <div className="ms-tabbar">
        {TABS.map(t => (
          <button key={t.id}
            className={`ms-tab${activeTab === t.id ? ' active' : ''}`}
            onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <div className="ms-body">
        {TAB_COMPONENT[activeTab]}
      </div>
    </div>
  );
}
