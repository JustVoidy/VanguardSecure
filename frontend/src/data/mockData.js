export const EVENTS = [
  { type: 'SYN Flood',   src: '14.6.x.x',    time: '2s ago',  sev: 'CRITICAL', col: '#ff2d55' },
  { type: 'UDP Flood',   src: '10.0.x.x',    time: '8s ago',  sev: 'HIGH',     col: '#f97316' },
  { type: 'Port Scan',   src: '63.92.x.x',   time: '15s ago', sev: 'MEDIUM',   col: '#f59e0b' },
  { type: 'Brute Force', src: '89.2.4.x',    time: '1m ago',  sev: 'HIGH',     col: '#f97316' },
  { type: 'DNS Amplify', src: '192.168.x.x', time: '3m ago',  sev: 'LOW',      col: '#10b981' },
];

export const COUNTRY_STATS = [
  { lbl: 'IND', pct: 92, color: '#00d4ff' },
  { lbl: 'USA', pct: 75, color: '#3b82f6' },
  { lbl: 'RUS', pct: 58, color: '#8b5cf6' },
  { lbl: 'UAE', pct: 32, color: '#f59e0b' },
  { lbl: 'CHN', pct: 20, color: '#f97316' },
];

export const IP_STATS = [
  { lbl: '10.0.x.x',   pct: 92, num: '1840', color: '#ff2d55' },
  { lbl: '14.6.x.x',   pct: 81, num: '1620', color: '#f97316' },
  { lbl: '63.92.x.x',  pct: 49, num: '980',  color: '#f59e0b' },
  { lbl: '89.2.4.x',   pct: 32, num: '640',  color: '#10b981' },
  { lbl: '192.168.x',  pct: 20, num: '410',  color: '#484f58' },
];

export const CHART_SERIES = [
  { id: 'c1', color: '#00d4ff', base: 47, label: 'PACKETS / SEC',        unit: ' pkt/s'  },
  { id: 'c2', color: '#3b82f6', base: 27, label: 'BYTES / SEC',          unit: ' KB/s'   },
  { id: 'c3', color: '#8b5cf6', base: 16, label: 'TCP SYN RATE',         unit: ' syn/s'  },
  { id: 'c4', color: '#f97316', base: 11, label: 'UDP FLOOD RATE',       unit: ' pkt/s'  },
  { id: 'c5', color: '#ff2d55', base: 78, label: 'ATTACK CONFIDENCE',    unit: '%'       },
  { id: 'c6', color: '#10b981', base: 37, label: 'NEW CONNECTIONS / SEC',unit: ' conn/s' },
];