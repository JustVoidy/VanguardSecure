import { useEffect, useState, useRef, useCallback } from "react";

const INITIAL_NOTIFS = [
  {
    id: 1,
    type: "critical",
    title: "SYN Flood Detected",
    msg: "Attack from 14.6.x.x — 4,200 pkt/s",
    time: "2s ago",
    read: false,
  },
  {
    id: 2,
    type: "blocked",
    title: "IP Blocked",
    msg: "63.92.10.5 added to blacklist automatically",
    time: "14s ago",
    read: false,
  },
  {
    id: 3,
    type: "login",
    title: "New Login Detected",
    msg: "Admin logged in from 192.168.1.1",
    time: "1m ago",
    read: false,
  },
  {
    id: 4,
    type: "system",
    title: "System Update Available",
    msg: "NetShield v2.5.0 is ready to install",
    time: "5m ago",
    read: true,
  },
  {
    id: 5,
    type: "critical",
    title: "UDP Flood Mitigated",
    msg: "10.0.x.x blocked after 1,800 pkt/s spike",
    time: "12m ago",
    read: true,
  },
  {
    id: 6,
    type: "blocked",
    title: "IP Blocked",
    msg: "89.2.4.x flagged for port scanning",
    time: "18m ago",
    read: true,
  },
  {
    id: 7,
    type: "login",
    title: "Failed Login Attempt",
    msg: "3 failed logins from 45.33.x.x",
    time: "22m ago",
    read: true,
  },
  {
    id: 8,
    type: "system",
    title: "DDoS Shield Active",
    msg: "HTTP flood protection triggered at 03:41",
    time: "1h ago",
    read: true,
  },
];

const TYPE_CONFIG = {
  critical: {
    color: "#ff2d55",
    bg: "rgba(255,45,85,.1)",
    border: "rgba(255,45,85,.2)",
    label: "Critical",
  },
  blocked: {
    color: "#f97316",
    bg: "rgba(249,115,22,.1)",
    border: "rgba(249,115,22,.2)",
    label: "Blocked",
  },
  login: {
    color: "#8b5cf6",
    bg: "rgba(139,92,246,.1)",
    border: "rgba(139,92,246,.2)",
    label: "Login",
  },
  system: {
    color: "#3b82f6",
    bg: "rgba(59,130,246,.1)",
    border: "rgba(59,130,246,.2)",
    label: "System",
  },
};

function TypeIcon({ type }) {
  if (type === "critical")
    return (
      <svg
        width="13"
        height="13"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <path d="M8 2L1 14h14L8 2z" />
        <path d="M8 7v3M8 11.5v.5" />
      </svg>
    );
  if (type === "blocked")
    return (
      <svg
        width="13"
        height="13"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <circle cx="8" cy="8" r="6" />
        <path d="M4 8h8" />
      </svg>
    );
  if (type === "login")
    return (
      <svg
        width="13"
        height="13"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <circle cx="8" cy="6" r="3" />
        <path d="M2 14c0-3.3 2.7-6 6-6s6 2.7 6 6" />
      </svg>
    );
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
    >
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1v2M8 13v2M1 8h2M13 8h2" />
    </svg>
  );
}

const BACKEND =
  typeof window.electronConfig !== "undefined"
    ? (window.electronConfig.get().backendUrl || "http://localhost:8000")
    : (process.env.REACT_APP_BACKEND_URL || "http://localhost:8000");

export default function Header({ onToggleSidebar }) {
  const [dotVisible, setDotVisible] = useState(true);

  // ── Capture process state (Electron IPC) ──────────────────────────────────
  const [captureRunning, setCaptureRunning] = useState(false);
  const [captureLoading, setCaptureLoading] = useState(false);
  const [selectedIface, setSelectedIface] = useState(() => {
    if (typeof window.electronConfig !== "undefined") {
      return window.electronConfig.get().interface || "eth0";
    }
    return "eth0";
  });

  const fetchCaptureStatus = useCallback(async () => {
    try {
      if (window.capture) {
        const data = await window.capture.status();
        setCaptureRunning(data.running);
        if (data.running && data.iface) setSelectedIface(data.iface);
      } else {
        const res  = await fetch(`${BACKEND}/capture/status`);
        const data = await res.json();
        setCaptureRunning(data.running);
        if (data.running && data.iface) setSelectedIface(data.iface);
      }
    } catch { }
  }, []);

  useEffect(() => {
    fetchCaptureStatus();
    const id = setInterval(fetchCaptureStatus, 3000);
    return () => clearInterval(id);
  }, [fetchCaptureStatus]);

  const toggleCapture = async () => {
    setCaptureLoading(true);
    try {
      if (window.capture) {
        if (captureRunning) {
          await window.capture.stop();
        } else {
          await window.capture.start({ iface: selectedIface });
        }
      } else {
        if (captureRunning) {
          await fetch(`${BACKEND}/capture/stop`, { method: "POST" });
        } else {
          await fetch(`${BACKEND}/capture/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ iface: selectedIface }),
          });
        }
      }
      setTimeout(fetchCaptureStatus, 600);
    } catch { } finally {
      setCaptureLoading(false);
    }
  };

  // ── Notifications ──────────────────────────────────────────────────────────
  const [open, setOpen] = useState(false);
  const [notifs, setNotifs] = useState(INITIAL_NOTIFS);
  const [filter, setFilter] = useState("all");
  const panelRef = useRef(null);

  const unread = notifs.filter((n) => !n.read).length;

  // Pulse live dot
  useEffect(() => {
    const id = setInterval(() => setDotVisible((v) => !v), 800);
    return () => clearInterval(id);
  }, []);

  // Close panel on outside click
  useEffect(() => {
    function handleClick(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  // Simulate live notifications
  useEffect(() => {
    const id = setInterval(() => {
      if (Math.random() < 0.3) {
        const types = ["critical", "blocked", "system", "login"];
        const type = types[Math.floor(Math.random() * types.length)];
        const msgs = {
          critical: {
            title: "New Attack Detected",
            msg: "Spike detected from unknown IP",
          },
          blocked: {
            title: "IP Auto-Blocked",
            msg: "Threshold exceeded — IP blacklisted",
          },
          login: {
            title: "Login Activity",
            msg: "New session started from dashboard",
          },
          system: {
            title: "System Health Check",
            msg: "All modules running normally",
          },
        };
        setNotifs((prev) => [
          {
            id: Date.now(),
            type,
            title: msgs[type].title,
            msg: msgs[type].msg,
            time: "just now",
            read: false,
          },
          ...prev.slice(0, 19),
        ]);
      }
    }, 8000);
    return () => clearInterval(id);
  }, []);

  function markRead(id) {
    setNotifs((n) => n.map((x) => (x.id === id ? { ...x, read: true } : x)));
  }
  function markAllRead() {
    setNotifs((n) => n.map((x) => ({ ...x, read: true })));
  }
  function clearAll() {
    setNotifs([]);
  }
  function deleteNotif(id) {
    setNotifs((n) => n.filter((x) => x.id !== id));
  }

  const filtered =
    filter === "all"
      ? notifs
      : filter === "unread"
        ? notifs.filter((n) => !n.read)
        : notifs.filter((n) => n.type === filter);

  return (
    <header className="header">
      <div className="sidebar-toggle" onClick={onToggleSidebar}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </div>
      <div className="live-dot" style={{ opacity: dotVisible ? 1 : 0.2 }} />
      <div className="live-label">LIVE</div>
      <div className="h-div" />
      <div className="h-title">Dashboard</div>

      {/* Interface selector + Capture Start / Stop */}
      <div className="capture-controls">
        <input
          className="iface-select"
          list="iface-list"
          value={selectedIface}
          onChange={(e) => setSelectedIface(e.target.value)}
          disabled={captureRunning || captureLoading}
          placeholder="interface…"
          title="Network interface to capture on"
          spellCheck={false}
          autoComplete="off"
        />
        <datalist id="iface-list">
          {["eth0","ens3","wlan0","wlp2s0","lo","en0","en1"].map((iface) => (
            <option key={iface} value={iface} />
          ))}
        </datalist>

        <button
          className={`capture-btn${captureRunning ? " running" : ""}`}
          onClick={toggleCapture}
          disabled={captureLoading || !selectedIface}
          title={captureRunning ? `Stop capture on ${selectedIface}` : `Start capture on ${selectedIface}`}
        >
          <span className={`capture-dot${captureRunning ? " active" : ""}`} />
          {captureLoading
            ? "..."
            : captureRunning
            ? "Stop Capture"
            : "Start Capture"}
        </button>
      </div>

      {/* Bell + Notifications Panel */}
      <div className="notif-wrap" ref={panelRef}>
        {/* Bell button */}
        <div className="icon-btn" onClick={() => setOpen((v) => !v)}>
          {unread > 0 && (
            <div className="notif-count">{unread > 9 ? "9+" : unread}</div>
          )}
          <svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            stroke="#8b949e"
            strokeWidth="1.5"
          >
            <path d="M8 2a4 4 0 00-4 4c0 4-2 5-2 5h12s-2-1-2-5a4 4 0 00-4-4z" />
            <path d="M9.7 13a2 2 0 01-3.4 0" />
          </svg>
        </div>
        {/* Logout Button */}

        {/* Dropdown panel */}
        {open && (
          <div className="notif-panel">
            {/* Header */}
            <div className="notif-header">
              <div className="notif-header-left">
                <span className="notif-title">Notifications</span>
                {unread > 0 && (
                  <span className="notif-unread-badge">{unread} new</span>
                )}
              </div>
              <div className="notif-header-actions">
                <button className="notif-action-btn" onClick={markAllRead}>
                  Mark all read
                </button>
                <button className="notif-action-btn red" onClick={clearAll}>
                  Clear all
                </button>
              </div>
            </div>

            {/* Filter tabs */}
            <div className="notif-filters">
              {["all", "unread", "critical", "blocked", "login", "system"].map(
                (f) => (
                  <button
                    key={f}
                    className={`notif-filter-btn${filter === f ? " active" : ""}`}
                    onClick={() => setFilter(f)}
                  >
                    {f.charAt(0).toUpperCase() + f.slice(1)}
                  </button>
                ),
              )}
            </div>

            {/* Notification list */}
            <div className="notif-list">
              {filtered.length === 0 && (
                <div className="notif-empty">
                  <svg
                    width="32"
                    height="32"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="var(--t3)"
                    strokeWidth="1.5"
                  >
                    <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
                    <path d="M13.73 21a2 2 0 01-3.46 0" />
                  </svg>
                  <div>No notifications</div>
                </div>
              )}

              {filtered.map((n) => {
                const cfg = TYPE_CONFIG[n.type];
                return (
                  <div
                    key={n.id}
                    className={`notif-item${n.read ? " read" : ""}`}
                    onClick={() => markRead(n.id)}
                  >
                    {!n.read && (
                      <div
                        className="notif-dot"
                        style={{ background: cfg.color }}
                      />
                    )}
                    <div
                      className="notif-icon"
                      style={{
                        background: cfg.bg,
                        border: `1px solid ${cfg.border}`,
                        color: cfg.color,
                      }}
                    >
                      <TypeIcon type={n.type} />
                    </div>
                    <div className="notif-content">
                      <div className="notif-item-title">{n.title}</div>
                      <div className="notif-item-msg">{n.msg}</div>
                      <div className="notif-item-meta">
                        <span
                          className="notif-type-badge"
                          style={{
                            background: cfg.bg,
                            color: cfg.color,
                            border: `1px solid ${cfg.border}`,
                          }}
                        >
                          {cfg.label}
                        </span>
                        <span className="notif-time">{n.time}</span>
                      </div>
                    </div>
                    <button
                      className="notif-del"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteNotif(n.id);
                      }}
                    >
                      ✕
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
      <div className="header-right">
        {/* Logout Button */}
        <button
          className="logout-btn"
          onClick={() => {
            localStorage.removeItem("adminLoggedIn");
            localStorage.removeItem("token");
            window.location.reload();
          }}
        >
          Logout
        </button>
      </div>

    </header>
  );
}
