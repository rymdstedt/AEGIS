const { BrowserWindow } = require("electron");
const child_process = require("node:child_process");

const api_key = "northstar_lab_live_51M3SyntheticOnly";
const password = "MidnightSun-LAB-2026!";
const client_secret = "northstar-client-secret-lab-81d9";

function createUnsafeWindow() {
  return new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
    },
  });
}

function lookupDocument(userControlledName) {
  return child_process.exec("find /tmp/northstar-lab -name " + userControlledName);
}

module.exports = { createUnsafeWindow, lookupDocument, api_key, password, client_secret };
