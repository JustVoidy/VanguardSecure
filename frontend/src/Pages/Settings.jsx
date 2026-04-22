import "../App.css";
import { useState } from "react";

export default function UserProfile({ userName, onBack, backendUrl: initialBackendUrl, onBackendChange }) {
  const [activeTab, setActiveTab] = useState("profile");
  const [editMode, setEditMode] = useState(false);
  const [saved, setSaved] = useState(false);

  const [profile, setProfile] = useState({
    name: userName || "Admin",
    email: `${userName || "admin"}@netshield.com`,
    phone: "+91 98765 43210",
    role: "Administrator",
    location: "New Delhi, India",
    joined: "March 2024",
    lastLogin: "Today at 6:31 PM",
    twoFA: true,
    alerts: true,
    reports: false,
  });

  const [showAddUser, setShowAddUser] = useState(false);
  const [newUser, setNewUser] = useState({ name: "", email: "", role: "" });
  const [users, setUsers] = useState([]);

  // Connection settings
  const [connUrl, setConnUrl]     = useState(initialBackendUrl || "http://localhost:8000");
  const [connIface, setConnIface] = useState(() => {
    if (typeof window.electronConfig !== "undefined") {
      return window.electronConfig.get().interface || "eth0";
    }
    return "eth0";
  });
  const [connSaved, setConnSaved] = useState(false);

  function saveConnection() {
    const cfg = { backendUrl: connUrl, interface: connIface };
    if (typeof window.electronConfig !== "undefined") {
      window.electronConfig.set(cfg);
    }
    if (onBackendChange) onBackendChange(connUrl);
    setConnSaved(true);
    setTimeout(() => setConnSaved(false), 3000);
  }

  function handleChange(field, value) {
    setProfile((p) => ({ ...p, [field]: value }));
  }

  function handleSave() {
    setEditMode(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  function handleDeleteUser(index) {
    setUsers((prev) => {
      const updated = prev.filter((_, i) => i !== index);
      localStorage.setItem("users", JSON.stringify(updated));
      return updated;
    });
  }

  return (
    <div className="up-shell">

      {/* Top bar */}
      <div className="up-topbar">
        <button className="up-back-btn" onClick={onBack}>
          Back to Dashboard
        </button>

        <div className="up-topbar-title">Settings</div>

        {/* Profile tab actions */}
        {activeTab === "profile" && (
          <div style={{ display: "flex", gap: "8px" }}>
            {saved && <div className="up-saved-badge">✓ Changes saved</div>}
            {editMode ? (
              <>
                <button className="up-btn-ghost" onClick={() => setEditMode(false)}>Cancel</button>
                <button className="up-btn-primary" onClick={handleSave}>Save Changes</button>
              </>
            ) : (
              <button className="up-btn-primary" onClick={() => setEditMode(true)}>Edit Profile</button>
            )}
          </div>
        )}


      </div>

      {/* Tab Switcher */}
      <div style={{
        display: "flex",
        gap: "0",
        borderBottom: "1px solid rgba(255,255,255,0.1)",
        marginBottom: "20px",
        paddingLeft: "4px",
      }}>
        {["profile", "users", "connection"].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              background: "none",
              border: "none",
              borderBottom: activeTab === tab ? "2px solid var(--cyan, #00e5ff)" : "2px solid transparent",
              color: activeTab === tab ? "var(--cyan, #00e5ff)" : "rgba(255,255,255,0.5)",
              padding: "10px 22px",
              fontSize: "14px",
              fontWeight: activeTab === tab ? "600" : "400",
              cursor: "pointer",
              transition: "all 0.2s",
              letterSpacing: "0.3px",
            }}
          >
            {tab === "profile" ? "Admin Profile" : tab === "users" ? "User Management" : "Connection"}
          </button>
        ))}
      </div>

      {/* ── TAB 1: Admin Profile ── */}
      {activeTab === "profile" && (
        <div className="up-body">
          {/* Left: Avatar card */}
          <div className="up-left">
            <div className="up-avatar-card">
              <div className="up-avatar">
                {profile.name.charAt(0).toUpperCase()}
              </div>
              <div className="up-avatar-name">{profile.name}</div>
              <div className="up-avatar-role">{profile.role}</div>
            </div>
          </div>

          {/* Right: Fields */}
          <div className="up-right">
            <div className="up-section-card">
              <div className="up-section-header">Personal Information</div>
              <div className="up-fields-grid">

                <div className="up-field">
                  <label className="up-field-label">Full Name</label>
                  {editMode ? (
                    <input className="up-field-input" value={profile.name}
                      onChange={(e) => handleChange("name", e.target.value)} />
                  ) : (
                    <div className="up-field-value">{profile.name}</div>
                  )}
                </div>

                <div className="up-field">
                  <label className="up-field-label">Email</label>
                  {editMode ? (
                    <input className="up-field-input" value={profile.email}
                      onChange={(e) => handleChange("email", e.target.value)} />
                  ) : (
                    <div className="up-field-value">{profile.email}</div>
                  )}
                </div>

                <div className="up-field">
                  <label className="up-field-label">Phone</label>
                  {editMode ? (
                    <input className="up-field-input" value={profile.phone}
                      onChange={(e) => handleChange("phone", e.target.value)} />
                  ) : (
                    <div className="up-field-value">{profile.phone}</div>
                  )}
                </div>

                <div className="up-field">
                  <label className="up-field-label">Location</label>
                  {editMode ? (
                    <input className="up-field-input" value={profile.location}
                      onChange={(e) => handleChange("location", e.target.value)} />
                  ) : (
                    <div className="up-field-value">{profile.location}</div>
                  )}
                </div>

                <div className="up-field">
                  <label className="up-field-label">Role</label>
                  <div className="up-field-value">{profile.role}</div>
                </div>

                <div className="up-field">
                  <label className="up-field-label">Joined</label>
                  <div className="up-field-value">{profile.joined}</div>
                </div>

                <div className="up-field">
                  <label className="up-field-label">Last Login</label>
                  <div className="up-field-value">{profile.lastLogin}</div>
                </div>

              </div>
            </div>

            {/* Preferences */}
            <div className="up-section-card" style={{ marginTop: "16px" }}>
              <div className="up-section-header">Preferences</div>
              <div className="up-fields-grid">
                {[
                  { label: "Two-Factor Authentication", key: "twoFA" },
                  { label: "Email Alerts", key: "alerts" },
                  { label: "Weekly Reports", key: "reports" },
                ].map(({ label, key }) => (
                  <div key={key} className="up-field" style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}>
                    <label className="up-field-label" style={{ marginBottom: 0 }}>{label}</label>
                    <div
                      onClick={() => editMode && handleChange(key, !profile[key])}
                      style={{
                        width: "36px", height: "20px", borderRadius: "10px",
                        background: profile[key] ? "var(--cyan, #00e5ff)" : "rgba(255,255,255,0.2)",
                        cursor: editMode ? "pointer" : "default",
                        position: "relative", transition: "background 0.2s",
                      }}
                    >
                      <div style={{
                        width: "14px", height: "14px", borderRadius: "50%", background: "#fff",
                        position: "absolute", top: "3px",
                        left: profile[key] ? "19px" : "3px",
                        transition: "left 0.2s",
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: User Management ── */}
      {activeTab === "users" && (
        <div style={{ padding: "0 4px" }}>

          {/* Add User Button */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "12px" }}>
            <button
              className="up-btn-primary"
              onClick={() => setShowAddUser(true)}
              style={{ padding: "8px 16px", fontSize: "13px" }}
            >
              + Add User
            </button>
          </div>

          {/* Users Table */}
          <div className="up-section-card">
            <div className="up-section-header" style={{ marginBottom: "12px" }}>
              Users List
              <span style={{
                marginLeft: "10px", fontSize: "12px",
                background: "rgba(0,229,255,0.15)", color: "var(--cyan, #00e5ff)",
                padding: "2px 8px", borderRadius: "10px",
              }}>
                {users.length} {users.length === 1 ? "user" : "users"}
              </span>
            </div>

            {users.length === 0 ? (
              <div style={{
                padding: "40px", textAlign: "center",
                opacity: 0.5, fontSize: "14px",
              }}>
                No users added yet. Click "+ Add User" to get started.
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "14px" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.12)" }}>
                    {["#", "Name", "Email", "Role", "Action"].map((h) => (
                      <th key={h} style={{
                        padding: "10px 14px", textAlign: "left",
                        color: "rgba(255,255,255,0.5)", fontWeight: "500", fontSize: "12px",
                        textTransform: "uppercase", letterSpacing: "0.5px",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((user, index) => (
                    <tr key={index} style={{
                      borderBottom: "1px solid rgba(255,255,255,0.06)",
                      transition: "background 0.15s",
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ padding: "12px 14px", opacity: 0.5 }}>{index + 1}</td>
                      <td style={{ padding: "12px 14px", fontWeight: "500" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <div style={{
                            width: "30px", height: "30px", borderRadius: "50%",
                            background: "var(--cyan, #00e5ff)", color: "#000",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            fontSize: "13px", fontWeight: "700", flexShrink: 0,
                          }}>
                            {user.name.charAt(0).toUpperCase()}
                          </div>
                          {user.name}
                        </div>
                      </td>
                      <td style={{ padding: "12px 14px", opacity: 0.7 }}>{user.email}</td>
                      <td style={{ padding: "12px 14px" }}>
                        <span style={{
                          background: user.role === "Admin"
                            ? "rgba(0,229,255,0.15)"
                            : user.role === "Analyst"
                              ? "rgba(255,200,0,0.15)"
                              : "rgba(255,255,255,0.1)",
                          color: user.role === "Admin"
                            ? "var(--cyan, #00e5ff)"
                            : user.role === "Analyst"
                              ? "#ffc800"
                              : "rgba(255,255,255,0.7)",
                          padding: "3px 10px", borderRadius: "10px", fontSize: "12px",
                        }}>
                          {user.role}
                        </span>
                      </td>
                      <td style={{ padding: "12px 14px" }}>
                        <button
                          onClick={() => handleDeleteUser(index)}
                          style={{
                            background: "rgba(255,80,80,0.12)", border: "none",
                            color: "#ff5050", padding: "4px 12px", borderRadius: "6px",
                            cursor: "pointer", fontSize: "12px",
                          }}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 3: Connection ── */}
      {activeTab === "connection" && (
        <div style={{ padding: "0 4px", maxWidth: "520px" }}>
          <div className="up-section-card">
            <div className="up-section-header">Backend Server</div>
            <div style={{ marginBottom: "16px", fontSize: "13px", opacity: 0.6 }}>
              Set the URL of your hosted NetShield backend (Render, Railway, etc.).
              Restart the app after saving for WebSocket connections to reconnect.
            </div>

            <div className="up-field" style={{ marginBottom: "14px" }}>
              <label className="up-field-label">Backend API URL</label>
              <input
                className="up-field-input"
                placeholder="https://your-app.onrender.com"
                value={connUrl}
                onChange={(e) => setConnUrl(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>

            <div className="up-field" style={{ marginBottom: "20px" }}>
              <label className="up-field-label">Network Interface (for capture)</label>
              <input
                className="up-field-input"
                placeholder="eth0"
                value={connIface}
                onChange={(e) => setConnIface(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <button className="up-btn-primary" onClick={saveConnection}>
                Save &amp; Apply
              </button>
              {connSaved && (
                <span style={{ fontSize: "13px", color: "#10b981" }}>
                  ✓ Saved — restart the app to reconnect WebSockets
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Add User Modal ── */}
      {showAddUser && (
        <div className="modal-overlay">
          <div className="modal-box">
            <h3 style={{ marginBottom: "16px", fontSize: "16px" }}>Add New User</h3>

            <input
              className="up-field-input"
              placeholder="Full Name"
              value={newUser.name}
              style={{ marginBottom: "10px", display: "block", width: "100%" }}
              onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
            />

            <input
              className="up-field-input"
              placeholder="Email"
              value={newUser.email}
              style={{ marginBottom: "10px", display: "block", width: "100%" }}
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
            />

            <select
              className="up-field-input"
              value={newUser.role}
              style={{ marginBottom: "16px", display: "block", width: "100%" }}
              onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
            >
              <option value="">Select Role</option>
              <option value="Admin">Admin</option>
              <option value="Analyst">Analyst</option>
              <option value="Viewer">Viewer</option>
            </select>

            <div style={{ display: "flex", gap: "10px" }}>
              <button
                className="up-btn-primary"
                onClick={() => {
                  if (!newUser.name || !newUser.email || !newUser.role) {
                    alert("Please fill all fields");
                    return;
                  }
                  const updated = [...users, newUser];
                  setUsers(updated);
                  localStorage.setItem("users", JSON.stringify(updated));
                  setShowAddUser(false);
                  setNewUser({ name: "", email: "", role: "" });
                }}
              >
                Add User
              </button>
              <button className="up-btn-ghost" onClick={() => setShowAddUser(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
