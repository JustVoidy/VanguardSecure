# VanguardSecure — NetShield

A real-time DDoS detection and mitigation dashboard. Packets are captured on the user's machine, scored by a hosted ML inference server, and visualized in an Electron desktop app backed by a cloud API.

---

## Architecture

```
[Desktop App — Electron]
  └── React UI (dashboard, charts, alerts)
  └── Capture subprocess (Scapy)
        │
        ├── POST /predict ──────────► [Inference Server — Render]
        │                               FFNN model (TensorFlow)
        │                               47-feature DDoS classifier
        │
        └── POST /events/ingest ────► [Backend API — Render]
                                        FastAPI + PostgreSQL
                                        WebSocket /ws/ai /ws/net
                                              │
                                        React dashboard ◄──────┘
```

---

## Features

- **Live packet capture** — Scapy sniffs network traffic, extracts 47 flow features per connection
- **ML inference** — Feed-forward neural network (256→128→64→1) trained on CIC-DDoS2019, classifies SYN and UDP floods
- **Real-time dashboard** — WebSocket-powered charts: threat level, active flows, top attacker IPs, bandwidth, SYN/UDP rates
- **Mitigation controls** — Blacklist/whitelist management, configurable alert threshold
- **JWT authentication** — Bcrypt password hashing, 8-hour token sessions
- **Electron desktop** — Native installer for Linux, macOS, and Windows; capture runs as a managed subprocess

---

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app, WebSocket servers, startup
│   │   ├── routes/          # auth, dashboard, inference, mitigation, profile
│   │   ├── models/          # SQLAlchemy ORM (Event, User)
│   │   ├── services/        # PredictorService (local inference)
│   │   └── utils/           # JWT helpers
│   ├── server.py            # Standalone inference server (port 8001)
│   └── render.yaml          # Render deployment config
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Root component, WebSocket hooks, event polling
│   │   ├── components/      # Header, Sidebar, KpiCard, ChartCard, EventsPage
│   │   └── Pages/           # AdminLoginPage, Settings, MitigationSettings
│   ├── main.js              # Electron main process, IPC capture control
│   └── preload.js           # Context bridge (electronConfig, capture APIs)
├── scripts/
│   └── capture.py           # Scapy capture + flow builder + ingest client
├── Training/
│   └── trainer.py           # PyTorch FFNN trainer (outputs .keras + .pt)
├── config/
│   └── settings.json        # Runtime config (threshold, interface, URLs)
├── capture.spec             # PyInstaller spec for capture binary
├── build.sh                 # Full build pipeline (capture binary + Electron)
└── requirements.txt
```

---

## Getting Started (Development)

### Prerequisites
- Python 3.10+
- Node.js 18+
- Linux with `CAP_NET_RAW` or run capture as root

### Backend

```bash
python -m venv .venv
source .venv/bin/activate        # or: . .venv/bin/activate.fish
pip install -r requirements.txt

# Set required env vars
export ENV=development
export JWT_SECRET=your-dev-secret

# Start inference server (port 8001)
cd backend
python server.py

# Start main API (port 8000) — new terminal
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend (Electron)

```bash
cd frontend
npm install
npm run electron-dev
```

The app opens at `localhost:3000` inside Electron. Go to **Settings → Connection** and set your backend URL.

---

## Deployment (Render)

Two services are defined in `backend/render.yaml`:

| Service | Purpose | Start Command |
|---|---|---|
| `netshield-api` | FastAPI backend + WebSocket | `uvicorn app.main:app` |
| `netshield-inference` | TensorFlow inference server | `uvicorn server:app` |

**Required environment variables for `netshield-api`:**

| Variable | Value |
|---|---|
| `JWT_SECRET` | A strong random secret (generate with `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `DATABASE_URL` | PostgreSQL connection string (from Render database) |
| `CORS_ORIGINS` | `*` (or your specific domain) |
| `ENV` | `production` |

---

## Building the Desktop App

```bash
# From project root (venv active)
./build.sh
```

This produces:
- `dist/capture` — standalone capture binary (PyInstaller)
- `frontend/dist/` — Electron installer for your platform

---

## Model Training

```bash
cd Training
python trainer.py --syn data/Syn.csv --udp data/UDP.csv
```

Outputs to project root: `ddos_ffnn.keras`, `ddos_ffnn.pt`, `ddos_scaler.pkl`, `ddos_features.pkl`, `ddos_metrics.json`.

Training data: [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) — not included in this repo due to size.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop | Electron 41, React 19, Chart.js 4 |
| Backend API | FastAPI, SQLAlchemy, PostgreSQL |
| Inference | TensorFlow / Keras, scikit-learn |
| Training | PyTorch, NumPy, pandas |
| Capture | Scapy, Python |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Packaging | PyInstaller, electron-builder |
