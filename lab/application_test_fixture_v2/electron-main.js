const { BrowserWindow } = require("electron");
const child_process = require("node:child_process");

function openLegacyConsole() {
  return new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
    },
  });
}

function exportCase(untrustedCaseId) {
  return child_process.exec("borealis-export --case " + untrustedCaseId);
}

function applyPolicy(untrustedPolicy) {
  return eval(untrustedPolicy);
}

module.exports = { openLegacyConsole, exportCase, applyPolicy };
