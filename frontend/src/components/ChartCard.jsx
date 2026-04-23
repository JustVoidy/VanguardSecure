import { useEffect, useState } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  LineElement, PointElement, LinearScale,
  CategoryScale, Filler, Tooltip,
} from 'chart.js';

ChartJS.register(LineElement, PointElement, LinearScale, CategoryScale, Filler, Tooltip);

function seedData(base, len = 20) {
  const d = [];
  let v = base;
  for (let i = 0; i < len; i++) {
    v = Math.max(1, v + (Math.random() - 0.45) * v * 0.25);
    d.push(Math.round(v));
  }
  return d;
}

export default function ChartCard({ label, color, base, unit, pillBg, pillColor, dataSeries }) {
  const [internalData, setInternalData] = useState(() => seedData(base));

  // Use external data if provided, else use internal mock data
  const data = dataSeries || internalData;

  useEffect(() => {
    if (dataSeries) return;

    const id = setInterval(() => {
      setInternalData(prev => {
        const last = prev[prev.length - 1];
        const next = Math.max(1, Math.round(last + (Math.random() - 0.45) * last * 0.2));
        return [...prev.slice(1), next];
      });
    }, 2000);
    return () => clearInterval(id);
  }, [dataSeries]);

  const current = data[data.length - 1];
  const prev = data[data.length - 2] ?? current;
  const delta = current - prev;

  const sign = delta >= 0 ? '+' : '';

  const chartData = {
    labels: data.map((_, i) => i),
    datasets: [{
      data,
      borderColor: color,
      borderWidth: 1.5,
      fill: true,
      backgroundColor: color + '22',
      pointRadius: 0,
      tension: 0.4,
    }],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    scales: { x: { display: false }, y: { display: false } },
    plugins: { legend: { display: false }, tooltip: { enabled: false } },
  };

  return (
    <div className="chart-card">
      <div className="chart-top">
        <div className="chart-label">{label}</div>
        <div className="chart-pill" style={{ background: pillBg, color: pillColor }}>
          {sign}{Number(delta).toFixed(1)}{unit.trim()}
        </div>
      </div>
      <div className="chart-val" style={{ color }}>
        {Number(current).toFixed(1)}<span className="chart-unit">{unit}</span>
      </div>
      <div className="chart-wrap">
        <Line data={chartData} options={options} />
      </div>
    </div>
  );
}