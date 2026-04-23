import { useState } from "react";

const API = typeof window.electronConfig !== "undefined"
  ? (window.electronConfig.get().backendUrl || "http://localhost:8000")
  : (process.env.REACT_APP_BACKEND_URL || "http://localhost:8000");

export default function AdminLogin({ onLogin }) {
  const [isSignup, setIsSignup]       = useState(false);
  const [name, setName]               = useState("");
  const [email, setEmail]             = useState("");
  const [password, setPassword]       = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError]             = useState("");
  const [loading, setLoading]         = useState(false);

  async function handleSubmit() {
    setError("");
    if (!email || !password || (isSignup && !name)) {
      setError("Please fill in all fields.");
      return;
    }

    setLoading(true);
    try {
      const endpoint = isSignup ? "/auth/signup" : "/auth/login";
      const body     = isSignup
        ? { name, email, password }
        : { email, password };

      const res = await fetch(`${API}${endpoint}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        const detail = data.detail;
        setError(
          Array.isArray(detail)
            ? detail.map((e) => e.msg).join(", ")
            : detail || "Authentication failed."
        );
        return;
      }

      localStorage.setItem("adminLoggedIn", "true");
      if (data.token) {
        localStorage.setItem("token", data.token);
        if (typeof window.electronConfig !== "undefined") {
          window.electronConfig.set({ token: data.token });
        }
      }
      onLogin(true);
    } catch (e) {
      setError("Cannot reach the backend. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter") handleSubmit();
  }

  return (
    <div className="lp-shell">
      <div className="lp-grid" />
      <div className="lp-orb lp-orb-1" />
      <div className="lp-orb lp-orb-2" />

      <div className="lp-center">

        <div className="lp-status-bar">
          <div className="lp-status-dot" />
          <span>All systems operational</span>
          <div className="lp-status-divider" />
          <span>NetShield v2.4</span>
        </div>

        <div className="lp-form-box">

          <div className="lp-logo">
            <div className="lp-logo-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <div className="lp-logo-name">VanguardSecure</div>
              <div className="lp-logo-sub">ADMIN PANEL</div>
            </div>
          </div>

          <div className="lp-heading">{isSignup ? "Create account" : "Welcome back"}</div>
          <div className="lp-subheading">
            {isSignup ? "Set up your admin account" : "Sign in to access the admin dashboard"}
          </div>

          {error && (
            <div style={{
              background: "rgba(255,45,85,.1)", border: "1px solid rgba(255,45,85,.3)",
              borderRadius: "8px", padding: "10px 14px", fontSize: "12px",
              color: "#ff2d55", marginBottom: "14px", display: "flex",
              alignItems: "center", gap: "6px",
            }}>
              ⚠ {error}
            </div>
          )}

          {isSignup && (
            <div className="lp-group">
              <label className="lp-label">Full Name</label>
              <div className="lp-input-wrap">
                <input
                  className="lp-input"
                  type="text"
                  placeholder="Enter your name"
                  value={name}
                  onChange={(e) => { setName(e.target.value); setError(""); }}
                  onKeyDown={handleKeyDown}
                  style={{ paddingLeft: "40px" }}
                />
                <span style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--t3)" }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
                  </svg>
                </span>
              </div>
            </div>
          )}

          <div className="lp-group">
            <label className="lp-label">Email</label>
            <div className="lp-input-wrap">
              <input
                className="lp-input"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => { setEmail(e.target.value); setError(""); }}
                onKeyDown={handleKeyDown}
                style={{ paddingLeft: "40px" }}
              />
              <span style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--t3)" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
                </svg>
              </span>
            </div>
          </div>

          <div className="lp-group">
            <label className="lp-label">Password</label>
            <div className="lp-input-wrap">
              <input
                className="lp-input"
                type={showPassword ? "text" : "password"}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(""); }}
                onKeyDown={handleKeyDown}
                style={{ paddingLeft: "40px" }}
              />
              <span style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--t3)" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </span>
              <button className="lp-eye" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                ) : (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <button
            className={`lp-btn${loading ? " loading" : ""}`}
            onClick={handleSubmit}
            disabled={loading}
          >
            {loading ? (
              <><span className="lp-spinner" />{isSignup ? "Creating account..." : "Authenticating..."}</>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" /><polyline points="10 17 15 12 10 7" /><line x1="15" y1="12" x2="3" y2="12" />
                </svg>
                {isSignup ? "Create Account" : "Sign In to Dashboard"}
              </>
            )}
          </button>

          <div style={{ textAlign: "center", fontSize: "12px", color: "var(--t3)", marginTop: "-6px" }}>
            {isSignup ? "Already have an account?" : "No account yet?"}{" "}
            <span
              onClick={() => { setIsSignup(!isSignup); setError(""); }}
              style={{ color: "var(--cyan)", cursor: "pointer", textDecoration: "underline" }}
            >
              {isSignup ? "Sign in" : "Create one"}
            </span>
          </div>

        </div>

        <div className="lp-bottom-info">
          <span>© 2024 VanguardSecure</span>
          <span className="lp-dot-sep">•</span>
          <span>Secured by NetShield</span>
          <span className="lp-dot-sep">•</span>
          <span>v2.4.1</span>
        </div>

      </div>
    </div>
  );
}
