import "./App.css";
import { useState, useEffect, useRef, useCallback } from "react";

function apiFetch(url, opts = {}) {
  const token = localStorage.getItem("token");
  return fetch(url, {
    ...opts,
    headers: { ...(opts.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
}
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";
import KpiCard from "./components/KpiCard";
import ChartCard from "./components/ChartCard";
import StatsCard from "./components/StatsCard";
import UserProfile from "./Pages/Settings";
import MitigationSettings from "./Pages/MitigationSettings";
import EventsPage from "./components/EventsPage";

import { COUNTRY_STATS } from "./data/mockData";
import { useSocket } from "./hooks/useSocket";

export default function App() {
  const [isDark, setIsDark] = useState(true);
  const [showMitigation, setShowMitigation] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showEvents, setShowEvents] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const toggleSidebar = () => setSidebarOpen(!sidebarOpen);
  const closeSidebar = () => setSidebarOpen(false);

  const [backendUrl, setBackendUrl] = useState(() => {
    if (typeof window.electronConfig !== "undefined") {
      return window.electronConfig.get().backendUrl || "http://localhost:8000";
    }
    return "http://localhost:8000";
  });

  // 📡 REAL-TIME DATA HOOKS
  const wsBase = backendUrl.replace(/^http/, "ws");
  const { data: aiStats } = useSocket(`${wsBase}/ws/ai`);
  const { data: netStats } = useSocket(`${wsBase}/ws/net`);
  const [events, setEvents] = useState([]);

  // Persist top IPs so they don't vanish when a broadcast arrives with an empty list
  const [topIps, setTopIps] = useState([]);
  useEffect(() => {
    if (netStats?.top_ips?.length > 0) setTopIps(netStats.top_ips);
  }, [netStats]);

  // Historical data for charts (Last 20 points)
  const [history, setHistory] = useState({
    fps: Array(20).fill(0),
    bw: Array(20).fill(0),
    flows: Array(20).fill(0),
    confidence: Array(20).fill(0),
    syn: Array(20).fill(0),
    udp: Array(20).fill(0)
  });

  useEffect(() => {
    document.body.classList.toggle("light", !isDark);
  }, [isDark]);

  // Refs to hold latest stats for the chart timer
  const aiStatsRef = useRef(aiStats);
  const netStatsRef = useRef(netStats);

  useEffect(() => {
    aiStatsRef.current = aiStats;
  }, [aiStats]);

  useEffect(() => {
    netStatsRef.current = netStats;
  }, [netStats]);

  // Update history series on a fixed 1-second interval for smooth charts
  useEffect(() => {
    const id = setInterval(() => {
      setHistory(prev => {
        const curAi = aiStatsRef.current;
        const curNet = netStatsRef.current;
        
        return {
          fps: [...prev.fps.slice(1), curAi?.fps || 0],
          bw: [...prev.bw.slice(1), (curNet?.total_bw || 0) / 1024], // KB/s
          flows: [...prev.flows.slice(1), curNet?.active_flows || 0],
          confidence: [...prev.confidence.slice(1), curAi?.threat_level === "HIGH" ? 99 : curAi?.threat_level === "MEDIUM" ? 75 : 10],
          syn: [...prev.syn.slice(1), curNet?.syn_rate || 0],
          udp: [...prev.udp.slice(1), curNet?.udp_rate || 0]
        };
      });
    }, 1000);
    return () => clearInterval(id);
  }, []);


  // Poll for events from Backend API
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await apiFetch(`${backendUrl}/dashboard/events`);
        const data = await res.json();
        setEvents(data);
      } catch (e) {
        console.error("Failed to fetch events:", e);
      }
    };
    fetchEvents();
    const id = setInterval(fetchEvents, 5000);
    return () => clearInterval(id);
  }, []);



  return (
    <div className="shell">
      <div className={`sidebar-overlay${sidebarOpen ? " open" : ""}`} onClick={closeSidebar} />
      <Sidebar
        isDark={isDark}
        setIsDark={setIsDark}
        isOpen={sidebarOpen}
        onClose={closeSidebar}
        onHomeClick={() => { setShowProfile(false); setShowMitigation(false); setShowEvents(false); closeSidebar(); }}
        onProfileClick={() => { setShowProfile(true); setShowMitigation(false); setShowEvents(false); closeSidebar(); }}
        onMitigationClick={() => { setShowMitigation(true); setShowProfile(false); setShowEvents(false); closeSidebar(); }}
        onEventsClick={(hide = false) => { if (hide) setShowEvents(false); else { setShowEvents(true); setShowProfile(false); setShowMitigation(false); } closeSidebar(); }}
      />
      <main className="main">
        <Header onProfileClick={() => setShowProfile(true)} onToggleSidebar={toggleSidebar} />

        {showProfile ? (
          <UserProfile
            onBack={() => setShowProfile(false)}
            backendUrl={backendUrl}
            onBackendChange={setBackendUrl}
          />
        ) : showMitigation ? (
          <MitigationSettings onBack={() => setShowMitigation(false)} />
        ) : showEvents ? (
          <EventsPage events={events} />
        ) : (
          <div className="content">
            <div className="section-hd">
              <div className="section-title">Key Performance Indexes</div>
              <div style={{ fontSize: "12px", opacity: 0.5 }}>
                {aiStats ? "🟢 AI Engine Connected" : "🔴 AI Engine Offline"}
              </div>
            </div>

            <div className="kpi-grid">
              <KpiCard
                label="Current Threat Level"
                value={{ 
                  text: aiStats?.threat_level || "UNKNOWN", 
                  color: aiStats?.threat_level === "HIGH" ? "#ff2d55" : aiStats?.threat_level === "MEDIUM" ? "#f97316" : "#10b981" 
                }}
                trend={aiStats?.threat_level === "HIGH" ? "↑ CRITICAL" : "→ STABLE"}
                trendColor={aiStats?.threat_level === "HIGH" ? "#ff2d55" : "#10b981"}
                barColor={aiStats?.threat_level === "HIGH" ? "#ff2d55" : "#00d4ff"}
              />

              <KpiCard
                label="Attacks Detected"
                value={{ text: aiStats?.total_alerts || "0" }}
                trend={`Total Scored: ${aiStats?.total_scored || 0}`}
                trendColor="#8b949e"
                barColor="#ff2d55"
              />

              <KpiCard
                label="Inference Speed"
                value={{ text: Number(aiStats?.fps || 0).toFixed(1) }}
                trend="Flows / Second"
                trendColor="#00d4ff"
                barColor="#8b5cf6"
              />

              <KpiCard
                label="Network Bandwidth"
                value={{ text: ((netStats?.total_bw || 0) / 1024).toFixed(1) }}
                trend="KB / Second"
                trendColor="#10b981"
                barColor="#10b981"
              />
            </div>

            <div className="charts-grid">
              <ChartCard 
                label="INFERENCE THROUGHPUT" 
                color="#8b5cf6" 
                unit=" fps" 
                dataSeries={history.fps}
                pillBg="rgba(139,92,246,0.1)"
                pillColor="#8b5cf6"
              />
              <ChartCard 
                label="NETWORK TRAFFIC (SCAPY)" 
                color="#00d4ff" 
                unit=" KB/s" 
                dataSeries={history.bw}
                pillBg="rgba(0,212,255,0.1)"
                pillColor="#00d4ff"
              />
              <ChartCard 
                label="ACTIVE FLOWS" 
                color="#10b981" 
                unit=" flows" 
                dataSeries={history.flows}
                pillBg="rgba(16,185,129,0.1)"
                pillColor="#10b981"
              />
              <ChartCard 
                label="MODEL CONFIDENCE" 
                color="#ff2d55" 
                unit="%" 
                dataSeries={history.confidence}
                pillBg="rgba(255,45,85,0.1)"
                pillColor="#ff2d55"
              />
              <ChartCard 
                label="TCP SYN RATE" 
                color="#f59e0b" 
                unit=" syn/s" 
                dataSeries={history.syn}
                pillBg="rgba(245,158,11,0.1)"
                pillColor="#f59e0b"
              />
              <ChartCard 
                label="UDP FLOOD RATE" 
                color="#f97316" 
                unit=" pkt/s" 
                dataSeries={history.udp}
                pillBg="rgba(249,115,22,0.1)"
                pillColor="#f97316"
              />
            </div>


            <div className="stats-grid">
              <StatsCard
                title="Top Source IPs (Session)"
                rows={(() => {
                  const maxCount = Math.max(...topIps.map(i => i.count), 0) || 1;
                  return topIps.map(item => ({
                    lbl: item.ip,
                    pct: (item.count / maxCount) * 100,
                    num: item.count,
                    color: "#00d4ff"
                  }));
                })()}
              />

              <StatsCard
                title="Global Threat Map"
                rows={netStats?.countries?.length > 0 ? netStats.countries : COUNTRY_STATS}
              />
            </div>


          </div>
        )}
      </main>
    </div>


  );
}
