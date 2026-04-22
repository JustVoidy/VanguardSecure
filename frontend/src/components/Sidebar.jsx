import { useState } from "react";

const NAV = [
  { label: "Home", section: "OVERVIEW" },
  { label: "Threat Logs", section: "" },
  { label: "Mitigation Settings", section: "SETTINGS" },
  { label: "Users", section: "USERS" },
];

export default function Sidebar({
  isDark,
  setIsDark,
  onHomeClick,
  onMitigationClick,
  onProfileClick,
  onEventsClick,
  isOpen,
  onClose,
}) {

  const [active, setActive] = useState("Home");

  return (
    <aside className={`sidebar${isOpen ? " open" : ""}`}>
      {/* Mobile Close Button */}
      <div className="sidebar-mobile-close" onClick={onClose} style={{
        display: "none",
        position: "absolute",
        right: "12px",
        top: "12px",
        cursor: "pointer",
        color: "var(--t3)"
      }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 6L6 18M6 6l12 12" />
        </svg>
      </div>
      {/* Logo */}
      <div className="logo">
        <div className="logo-icon">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path
              d="M8 1L2 4v4c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V4L8 1z"
              fill="rgba(0,212,255,.6)"
              stroke="#00d4ff"
              strokeWidth="1"
            />
          </svg>
        </div>
        <div>
          <div className="logo-name">VanguardSecurity</div>
          <div className="logo-sub">ADMIN PANEL</div>
        </div>
      </div>

      {/* Nav Items */}
      {NAV.map((item) => (
        <div key={item.label}>
          {item.section && (
            <div className="nav-section">{item.section}</div>
          )}
          <div
            className={`nav-item${active === item.label ? " active" : ""}`}
    onClick={() => {
      setActive(item.label);
      if (item.label === "Users" && onProfileClick) {
        onProfileClick();
      }
      if (item.label === "Threat Logs" && onEventsClick) {
        onEventsClick();
      }
      if (item.label === "Mitigation Settings" && onMitigationClick) {
        onMitigationClick();
      }
      if (item.label === "Home") {
        // reset both pages when Home is clicked
        onProfileClick && onProfileClick();
        onEventsClick && onEventsClick(true); // pass true to hide
      }
      if (item.label === "Home" && onHomeClick) {
        onHomeClick();
      }

    }}
  >
            <div className="nav-icon">
              <svg
                width="14"
                height="14"
                viewBox="0 0 16 16"
                fill="none"
                stroke={active === item.label ? "#00d4ff" : "#8b949e"}
                strokeWidth="1.5"
              >
                <rect x="1" y="1" width="6" height="6" rx="1" />
                <rect x="9" y="1" width="6" height="6" rx="1" />
                <rect x="1" y="9" width="6" height="6" rx="1" />
                <rect x="9" y="9" width="6" height="6" rx="1" />
              </svg>
            </div>
            <span>{item.label}</span>
          </div>
        </div>
      ))}

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="toggle-row">
          <svg
            width="14"
            height="14"
            viewBox="0 0 16 16"
            fill="none"
            stroke="#8b949e"
            strokeWidth="1.5"
          >
            <circle cx="8" cy="8" r="3" />
            <path d="M8 1v2M8 13v2M1 8h2M13 8h2" />
          </svg>
          <span>Light / Dark Mode</span>
          <div
            className={`tog${isDark ? " on" : ""}`}
            onClick={() => setIsDark((v) => !v)}
          />
        </div>
      </div>
    </aside>
  );
}