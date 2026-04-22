const { contextBridge, ipcRenderer } = require("electron");
const fs   = require("fs");
const path = require("path");
const os   = require("os");

const CONFIG_FILE = path.join(os.homedir(), ".netshield", "config.json");

function readConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8")); }
  catch { return {}; }
}

// Synchronous get so React can init state before first render
contextBridge.exposeInMainWorld("electronConfig", {
  get: () => readConfig(),
  set: (cfg) => ipcRenderer.invoke("config:set", cfg),
});

contextBridge.exposeInMainWorld("capture", {
  start:  (opts) => ipcRenderer.invoke("capture:start",  opts),
  stop:   ()     => ipcRenderer.invoke("capture:stop"),
  status: ()     => ipcRenderer.invoke("capture:status"),
});
