import '../App.css';
import { useState } from 'react';

export default function MitigationSettings({ onBack }) {

  const [activeTab, setActiveTab] = useState('ddos');

  const [users, setUsers] = useState(() => {
    const saved = localStorage.getItem("users");
    return saved ? JSON.parse(saved) : [];
  });

  const [newUser, setNewUser] = useState({
    name: "",
    email: "",
    password: "",
    permissions: []
  });

  function togglePermission(p) {
    setNewUser(prev => ({
      ...prev,
      permissions: prev.permissions.includes(p)
        ? prev.permissions.filter(x => x !== p)
        : [...prev.permissions, p]
    }));
  }

  function addUser() {
    if (!newUser.name || !newUser.email || !newUser.password) return;

    const updated = [...users, { id: Date.now(), ...newUser, role: "user" }];
    setUsers(updated);
    localStorage.setItem("users", JSON.stringify(updated));

    setNewUser({ name: "", email: "", password: "", permissions: [] });
  }

  const TABS = [
    { id: 'ddos', label: 'DDoS Protection' },
    { id: 'ratelimit', label: 'Rate Limiting' },
    { id: 'ipmgr', label: 'IP Manager' },
    { id: 'rules', label: 'Firewall Rules' },
    { id: 'users', label: 'User Management' },
  ];

  return (
    <div className="up-shell">

      {/* Top */}
      <div className="up-topbar">
        <button className="up-back-btn" onClick={onBack}>← Back</button>
        <div className="up-topbar-title">Settings</div>
      </div>

      {/* Tabs */}
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

        {/* ✅ DDoS */}
        {activeTab === 'ddos' && (
          <div className="ms-section">
            <div className="ms-section-title">DDoS Protection</div>
            <p style={{ color: "#8b949e", marginTop: "10px" }}>
              Enable protection against SYN floods, UDP floods, and HTTP attacks.
            </p>
          </div>
        )}

        {/* ✅ Rate Limit */}
        {activeTab === 'ratelimit' && (
          <div className="ms-section">
            <div className="ms-section-title">Rate Limiting</div>
            <p style={{ color: "#8b949e", marginTop: "10px" }}>
              Control request thresholds to prevent abuse.
            </p>
          </div>
        )}

        {/* ✅ IP Manager */}
        {activeTab === 'ipmgr' && (
          <div className="ms-section">
            <div className="ms-section-title">IP Manager</div>
            <p style={{ color: "#8b949e", marginTop: "10px" }}>
              Manage whitelist and blacklist IPs.
            </p>
          </div>
        )}

        {/* ✅ Firewall Rules */}
        {activeTab === 'rules' && (
          <div className="ms-section">
            <div className="ms-section-title">Firewall Rules</div>
            <p style={{ color: "#8b949e", marginTop: "10px" }}>
              Define custom filtering rules for traffic.
            </p>
          </div>
        )}

        {/* ✅ USERS TAB */}
        {activeTab === 'users' && (
          <div className="ms-section">

            <div className="ms-section-title">User Management</div>

            {/* Add User */}
            <div className="ms-rule-form">

              <input className="ms-ip-input" placeholder="Full Name"
                value={newUser.name}
                onChange={e => setNewUser({ ...newUser, name: e.target.value })} />

              <input className="ms-ip-input" placeholder="Email"
                value={newUser.email}
                onChange={e => setNewUser({ ...newUser, email: e.target.value })} />

              <input className="ms-ip-input" placeholder="Password" type="password"
                value={newUser.password}
                onChange={e => setNewUser({ ...newUser, password: e.target.value })} />

              {/* Permissions */}
              <div style={{ display: "flex", gap: "10px", marginTop: "10px" }}>
                <label><input type="checkbox" onChange={() => togglePermission('dashboard')} /> Dashboard</label>
                <label><input type="checkbox" onChange={() => togglePermission('mitigation')} /> Mitigation</label>
                <label><input type="checkbox" onChange={() => togglePermission('settings')} /> Settings</label>
              </div>

              <button className="up-btn-primary" onClick={addUser}>Add User</button>
            </div>

            {/* Users Table */}
            <div className="ms-rules-table" style={{ marginTop: "20px" }}>
              <div className="ms-rules-header">
                <span>Name</span>
                <span>Email</span>
                <span>Permissions</span>
              </div>

              {users.map(u => (
                <div key={u.id} className="ms-rule-row">
                  <span>{u.name}</span>
                  <span>{u.email}</span>
                  <span>{u.permissions.join(", ")}</span>
                </div>
              ))}

            </div>

          </div>
        )}

      </div>
    </div>
  );
}