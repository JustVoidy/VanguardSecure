const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const fs   = require("fs");
const os   = require("os");
const { spawn } = require("child_process");

// ── User config (persisted to ~/.netshield/config.json) ───────────────────────

const CONFIG_DIR  = path.join(os.homedir(), ".netshield");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

function readConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8")); }
  catch { return {}; }
}

function writeConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

ipcMain.handle("config:get", () => readConfig());
ipcMain.handle("config:set", (_e, cfg) => {
  writeConfig({ ...readConfig(), ...cfg });
});

// ── Capture subprocess ────────────────────────────────────────────────────────

// Prefer PyInstaller binary in resources, fall back to script
const CAPTURE_BIN = path.join(process.resourcesPath || __dirname, "capture");
const CAPTURE_PY  = path.join(__dirname, "..", "scripts", "capture.py");

function captureCmd() {
  if (fs.existsSync(CAPTURE_BIN))                   return [CAPTURE_BIN, []];
  if (fs.existsSync(CAPTURE_BIN + ".exe"))           return [CAPTURE_BIN + ".exe", []];
  const py = process.platform === "win32" ? "python" : "python3";
  return [py, [CAPTURE_PY]];
}

let captureProc = null;

function startCapture({ iface, serverUrl, backendUrl } = {}) {
  if (captureProc && captureProc.exitCode === null) {
    return { status: "already_running", pid: captureProc.pid };
  }

  const cfg  = readConfig();
  iface      = iface      || cfg.interface   || "eth0";
  serverUrl  = serverUrl  || cfg.serverUrl   || "http://localhost:8001";
  backendUrl = backendUrl || cfg.backendUrl  || "http://localhost:8000";

  const [exe, prefix] = captureCmd();
  const args = [...prefix, "--iface", iface, "--server", serverUrl, "--backend-url", backendUrl];

  const logPath = path.join(os.homedir(), ".netshield", "capture.log");
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const log = fs.openSync(logPath, "a");

  const token = cfg.token || "";
  captureProc = spawn(exe, args, {
    stdio: ["ignore", log, log],
    env: { ...process.env, NETSHIELD_TOKEN: token },
  });
  captureProc.on("exit", () => { captureProc = null; });

  return { status: "started", pid: captureProc.pid, iface, serverUrl, backendUrl };
}

function stopCapture() {
  if (!captureProc || captureProc.exitCode !== null) return { status: "not_running" };
  const pid = captureProc.pid;
  captureProc.kill("SIGTERM");
  captureProc = null;
  return { status: "stopped", pid };
}

ipcMain.handle("capture:start",  (_e, opts) => startCapture(opts));
ipcMain.handle("capture:stop",   () => stopCapture());
ipcMain.handle("capture:status", () => ({
  running: captureProc !== null && captureProc.exitCode === null,
  pid:     captureProc?.pid ?? null,
}));

// ── Window ────────────────────────────────────────────────────────────────────

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    backgroundColor: "#0d1117",
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  const isDev = process.env.NODE_ENV === "development" || !app.isPackaged;
  if (isDev) {
    win.loadURL("http://localhost:3000");
  } else {
    win.loadFile(path.join(__dirname, "build", "index.html"));
  }
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopCapture();
  if (process.platform !== "darwin") app.quit();
});
