const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const { claimSingleInstance, revealWindow } = require('./single-instance');

let mainWindow = null;
let serverProcess = null;
let internalPort = null;
let isQuitting = false;
let backendReady = false;
let focusWhenWindowReady = false;
const isPrimaryInstance = claimSingleInstance(
  app,
  () => mainWindow,
  () => {
    focusWhenWindowReady = true;
    // Development builds may keep running after their only window is closed.
    // A fresh launch should reopen that window, not leave a headless backend.
    if (backendReady && !isQuitting) createMainWindow();
  },
);
const authToken = crypto.randomBytes(32).toString('base64url');
const artifactImportToken = crypto.randomBytes(32).toString('base64url');
const instanceId = crypto.randomBytes(18).toString('base64url');
const SERVER_HOST = '127.0.0.1';

function getFreeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once('error', reject);
    probe.listen(0, SERVER_HOST, () => {
      const address = probe.address();
      const port = address && typeof address === 'object' ? address.port : null;
      probe.close((err) => err ? reject(err) : resolve(port));
    });
  });
}

function getBackendBinary() {
  const executableName = process.platform === 'win32' ? 'aegis-server.exe' : 'aegis-server';
  const isPackaged = app.isPackaged;
  if (isPackaged) {
    // The onedir backend keeps its Python runtime inside the signed app bundle.
    // This avoids onefile extraction delays and Hardened Runtime rejecting a
    // differently signed Python framework unpacked into a temporary directory.
    const backendRoot = path.join(process.resourcesPath, 'aegis-server');
    const onedirBinary = path.join(backendRoot, executableName);
    if (fs.existsSync(onedirBinary)) return onedirBinary;
    // Retain compatibility with an older one-file package, but never try to
    // spawn the onedir folder itself when its executable is missing.
    if (fs.existsSync(backendRoot) && fs.statSync(backendRoot).isFile()) return backendRoot;
    return onedirBinary;
  }
  // Dev mode after `npm run build:server`
  const backendRoot = path.join(__dirname, '..', 'backend', 'dist', 'aegis-server');
  const onedirBinary = path.join(backendRoot, executableName);
  if (fs.existsSync(onedirBinary)) return onedirBinary;
  if (fs.existsSync(backendRoot) && fs.statSync(backendRoot).isFile()) return backendRoot;
  return onedirBinary;
}

function terminateBackend() {
  if (!serverProcess || serverProcess.killed) return;
  if (process.platform === 'win32') {
    // Terminate the complete scanner process tree. TerminateProcess on only the
    // backend can otherwise leave nmap/naabu/httpx running after AEGIS exits.
    spawnSync('taskkill.exe', ['/pid', String(serverProcess.pid), '/t', '/f'], {
      windowsHide: true,
      stdio: 'ignore',
    });
  } else {
    serverProcess.kill('SIGTERM');
  }
}

function waitForServerReady(port, timeoutMs = 150000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      const req = http.get({
        hostname: SERVER_HOST,
        port,
        path: '/api/health',
        headers: { Authorization: `Bearer ${authToken}` },
      }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          let ready = false;
          try {
            ready = res.statusCode === 200 && JSON.parse(body).instance_id === instanceId;
          } catch (_) { ready = false; }
          if (ready) return resolve(true);
          if (Date.now() - start > timeoutMs) return reject(new Error('Backend health timeout'));
          setTimeout(check, 400);
        });
      });
      req.on('error', () => {
        if (Date.now() - start > timeoutMs) return reject(new Error('Backend never became ready'));
        setTimeout(check, 400);
      });
      req.end();
    };
    check();
  });
}

function requestBackendJson(pathname, method = 'GET', payload = null, extraHeaders = {}) {
  const body = payload === null ? null : Buffer.from(JSON.stringify(payload), 'utf8');
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: SERVER_HOST,
      port: internalPort,
      path: pathname,
      method,
      headers: {
        Authorization: `Bearer ${authToken}`,
        Accept: 'application/json',
        ...(body ? {
          'Content-Type': 'application/json',
          'Content-Length': String(body.length),
        } : {}),
        ...extraHeaders,
      },
    }, (res) => {
      const chunks = [];
      let received = 0;
      res.on('data', (chunk) => {
        received += chunk.length;
        if (received <= 10 * 1024 * 1024) chunks.push(chunk);
      });
      res.on('end', () => {
        if (received > 10 * 1024 * 1024) {
          reject(new Error('The local backend returned an oversized response'));
          return;
        }
        let response;
        try {
          response = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (_) {
          reject(new Error(`The local backend returned HTTP ${res.statusCode} without JSON`));
          return;
        }
        if ((res.statusCode || 500) >= 400) {
          reject(new Error(response.detail || response.error || `Local backend request failed (HTTP ${res.statusCode})`));
          return;
        }
        resolve(response);
      });
    });
    req.setTimeout(10 * 60 * 1000, () => req.destroy(new Error('Artifact import timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function requestBackendNdjson(pathname, payload, extraHeaders = {}, onEvent = () => {}) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const req = http.request({
      hostname: SERVER_HOST,
      port: internalPort,
      path: pathname,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${authToken}`,
        Accept: 'application/x-ndjson',
        'Content-Type': 'application/json',
        'Content-Length': String(body.length),
        ...extraHeaders,
      },
    }, (res) => {
      res.setEncoding('utf8');
      let buffered = '';
      let rawBody = '';
      let received = 0;
      let completed = null;
      let streamError = null;
      const processLine = (line) => {
        if (!line.trim()) return;
        let message;
        try {
          message = JSON.parse(line);
        } catch (_) {
          throw new Error('The local backend returned an invalid progress event');
        }
        try { onEvent(message); } catch (_) { /* renderer may have closed */ }
        if (message.type === 'complete') completed = message;
        if (message.type === 'error') streamError = new Error(message.message || 'The local model request failed');
      };
      res.on('data', (chunk) => {
        if (settled) return;
        received += Buffer.byteLength(chunk, 'utf8');
        if (received > 10 * 1024 * 1024) {
          res.destroy(new Error('The local backend returned an oversized response'));
          return;
        }
        rawBody += chunk;
        buffered += chunk;
        const lines = buffered.split('\n');
        buffered = lines.pop() || '';
        try { lines.forEach(processLine); } catch (problem) { res.destroy(problem); }
      });
      res.on('error', (problem) => finish(reject, problem));
      res.on('end', () => {
        if (settled) return;
        if ((res.statusCode || 500) >= 400) {
          let detail = `Local backend request failed (HTTP ${res.statusCode})`;
          try {
            const parsed = JSON.parse(rawBody);
            detail = parsed.detail || parsed.error || detail;
          } catch (_) { /* use status fallback */ }
          finish(reject, new Error(detail));
          return;
        }
        try { if (buffered.trim()) processLine(buffered); } catch (problem) {
          finish(reject, problem);
          return;
        }
        if (streamError) finish(reject, streamError);
        else if (!completed?.answer) finish(reject, new Error('The local model stream ended without an answer'));
        else finish(resolve, completed);
      });
    });
    req.setTimeout(10 * 60 * 1000, () => req.destroy(new Error('Local model request timed out')));
    req.on('error', (problem) => finish(reject, problem));
    req.write(body);
    req.end();
  });
}

function applicationRendererAllowed(event) {
  const appOrigin = `http://${SERVER_HOST}:${internalPort}`;
  let senderOrigin = '';
  try {
    senderOrigin = new URL(event.senderFrame?.url || event.sender.getURL()).origin;
  } catch (_) { /* rejected below */ }
  return Boolean(
    mainWindow
    && event.sender === mainWindow.webContents
    && senderOrigin === appOrigin
  );
}

function validProjectId(value) {
  return /^app_[0-9a-f]{32}$/.test(String(value || ''));
}

function validFindingId(value) {
  return /^appf_[0-9a-f]{20}$/.test(String(value || ''));
}

function validApplicationChatHistory(value) {
  return Array.isArray(value)
    && value.length <= 8
    && value.every((item) => (
      item
      && typeof item === 'object'
      && ['user', 'assistant'].includes(item.role)
      && typeof item.content === 'string'
      && item.content.length >= 1
      && item.content.length <= 1200
    ));
}

function registerApplicationResearchIpc() {
  ipcMain.removeHandler('aegis:select-artifact');
  ipcMain.handle('aegis:select-artifact', async (event, kind) => {
    const selectionKind = kind === 'directory' ? 'directory' : kind === 'file' ? 'file' : null;
    if (!selectionKind || !applicationRendererAllowed(event)) {
      throw new Error('Artifact selection was rejected');
    }

    const result = await dialog.showOpenDialog(mainWindow, {
      title: selectionKind === 'directory'
        ? 'Select a source directory to inspect'
        : 'Select an application or firmware artifact to inspect',
      buttonLabel: 'Import read-only copy',
      properties: [selectionKind === 'directory' ? 'openDirectory' : 'openFile'],
      filters: selectionKind === 'file' ? [
        {
          name: 'Applications, firmware, packages, archives, and source files',
          extensions: [
            'exe', 'dll', 'sys', 'msi', 'dmg', 'pkg', 'app', 'zip', 'tar',
            'tgz', 'gz', 'bz2', 'xz', 'bin', 'img', 'fw', 'rom', 'trx', 'ubi', 'chk', 'apk',
            'aab', 'ipa', 'jar', 'py', 'js', 'ts', 'tsx', 'jsx', 'go', 'rs',
            'java', 'kt', 'swift', 'c', 'cc', 'cpp', 'h', 'hpp', 'cs', 'rb',
            'php', 'sh', 'ps1', 'json', 'xml', 'yaml', 'yml', 'toml', 'txt',
          ],
        },
        { name: 'All files', extensions: ['*'] },
      ] : undefined,
    });
    if (result.canceled || result.filePaths.length !== 1) return { cancelled: true };

    // The renderer never receives the original filesystem path. The main
    // process submits it using a second credential unavailable to page JS.
    const project = await requestBackendJson(
      '/api/application/import',
      'POST',
      { path: result.filePaths[0] },
      { 'X-AEGIS-Artifact-Token': artifactImportToken },
    );
    return { cancelled: false, project };
  });

  ipcMain.removeHandler('aegis:reveal-application-evidence');
  ipcMain.handle(
    'aegis:reveal-application-evidence',
    async (event, projectId, findingId) => {
      if (
        !applicationRendererAllowed(event)
        || !validProjectId(projectId)
        || !validFindingId(findingId)
      ) {
        throw new Error('Private evidence request was rejected');
      }
      const confirmation = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'Reveal sensitive evidence?',
        message: 'Reveal the exact extracted evidence for this finding?',
        detail: 'The value may be a credential, token, or private key. It will be shown only in this AEGIS window and will not be added to the redacted report.',
        buttons: ['Cancel', 'Reveal evidence'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });
      if (confirmation.response !== 1) return { cancelled: true };
      const evidence = await requestBackendJson(
        `/api/application/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/private-evidence`,
        'GET',
        null,
        { 'X-AEGIS-Artifact-Token': artifactImportToken },
      );
      return { cancelled: false, evidence };
    },
  );

  ipcMain.removeHandler('aegis:delete-application-project');
  ipcMain.handle('aegis:delete-application-project', async (event, projectId) => {
    if (!applicationRendererAllowed(event) || !validProjectId(projectId)) {
      throw new Error('Application project removal was rejected');
    }

    const project = await requestBackendJson(
      `/api/application/projects/${encodeURIComponent(projectId)}`,
    );
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Remove Application Research project?',
      message: `Permanently remove “${String(project.name || 'this project').slice(0, 160)}”?`,
      detail: 'AEGIS will delete its copied snapshot, findings, and private exact evidence. The original file or folder you imported will not be changed.',
      buttons: ['Cancel', 'Remove project'],
      defaultId: 0,
      cancelId: 0,
      destructiveId: 1,
      noLink: true,
    });
    if (confirmation.response !== 1) return { cancelled: true };

    const response = await requestBackendJson(
      `/api/application/projects/${encodeURIComponent(projectId)}`,
      'DELETE',
      null,
      { 'X-AEGIS-Artifact-Token': artifactImportToken },
    );
    return { cancelled: false, response };
  });

  ipcMain.removeHandler('aegis:export-application-evidence');
  ipcMain.handle('aegis:export-application-evidence', async (event, projectId) => {
    if (!applicationRendererAllowed(event) || !validProjectId(projectId)) {
      throw new Error('Private evidence export was rejected');
    }
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Export sensitive evidence?',
      message: 'Export every exact evidence value in this project?',
      detail: 'The JSON file may contain credentials, tokens, and private keys in plaintext. Protect it carefully and do not share it as a normal report.',
      buttons: ['Cancel', 'Export private evidence'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (confirmation.response !== 1) return { cancelled: true };

    const firstPage = await requestBackendJson(
      `/api/application/projects/${encodeURIComponent(projectId)}/private-evidence/page?offset=0&limit=100`,
      'GET',
      null,
      { 'X-AEGIS-Artifact-Token': artifactImportToken },
    );
    const safeName = String(firstPage.project?.name || 'application')
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'application';
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: 'Export private application evidence',
      buttonLabel: 'Save sensitive JSON',
      defaultPath: `AEGIS-${safeName}-private-evidence.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }],
      properties: ['showOverwriteConfirmation'],
    });
    if (destination.canceled || !destination.filePath) return { cancelled: true };
    const temporaryPath = `${destination.filePath}.aegis-${crypto.randomBytes(8).toString('hex')}.tmp`;
    let handle;
    try {
      handle = fs.openSync(temporaryPath, 'wx', 0o600);
      const writeExport = (value) => {
        const buffer = Buffer.from(value, 'utf8');
        let offset = 0;
        while (offset < buffer.length) {
          const count = fs.writeSync(handle, buffer, offset, buffer.length - offset);
          if (count <= 0) throw new Error('Private evidence export stopped while writing');
          offset += count;
        }
      };
      writeExport(`{"project":${JSON.stringify(firstPage.project)},"evidence":[`);
      const total = Number(firstPage.total);
      if (!Number.isSafeInteger(total) || total < 0) throw new Error('Invalid private-evidence total');
      const analyzedAt = firstPage.project?.analyzed_at;
      const analysisJobId = firstPage.project?.analysis_job_id;
      let page = firstPage;
      let written = 0;
      while (written < total) {
        if (page.total !== total || page.project?.analyzed_at !== analyzedAt || page.project?.analysis_job_id !== analysisJobId || page.offset !== written || !Array.isArray(page.evidence) || page.evidence.length === 0) {
          throw new Error('Private evidence changed during export; retry after analysis finishes');
        }
        for (const item of page.evidence) {
          writeExport(`${written ? ',' : ''}${JSON.stringify(item)}`);
          written += 1;
        }
        if (written < total) {
          page = await requestBackendJson(
            `/api/application/projects/${encodeURIComponent(projectId)}/private-evidence/page?offset=${written}&limit=100`,
            'GET', null, { 'X-AEGIS-Artifact-Token': artifactImportToken },
          );
        }
      }
      if (written !== total) throw new Error('Private evidence count changed during export');
      writeExport(`],"warning":${JSON.stringify('Sensitive local evidence. Store securely and rotate any real credentials before sharing.')} }\n`);
      fs.fsyncSync(handle);
      fs.closeSync(handle);
      handle = undefined;
      fs.renameSync(temporaryPath, destination.filePath);
    } catch (error) {
      if (handle !== undefined) {
        try { fs.closeSync(handle); } catch (_) { /* preserve the original export error */ }
      }
      try { fs.unlinkSync(temporaryPath); } catch (_) { /* exact temporary file may not exist */ }
      throw error;
    }
    return { cancelled: false, fileName: path.basename(destination.filePath) };
  });

  ipcMain.removeHandler('aegis:export-application-redacted');
  ipcMain.handle('aegis:export-application-redacted', async (event, projectId) => {
    if (!applicationRendererAllowed(event) || !validProjectId(projectId)) {
      throw new Error('Redacted findings export was rejected');
    }
    const project = await requestBackendJson(
      `/api/application/projects/${encodeURIComponent(projectId)}`,
    );
    const total = Number(project.findings_total);
    if (!Number.isSafeInteger(total) || total < 0) {
      throw new Error('Invalid finding total');
    }
    const analysisJobId = project.summary?.analysis_job_id;
    const safeName = String(project.name || 'application')
      .replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'application';
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: 'Export redacted application findings',
      buttonLabel: 'Save redacted JSON',
      defaultPath: `AEGIS-${safeName}-redacted-findings.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }],
      properties: ['showOverwriteConfirmation'],
    });
    if (destination.canceled || !destination.filePath) return { cancelled: true };
    const temporaryPath = `${destination.filePath}.aegis-${crypto.randomBytes(8).toString('hex')}.tmp`;
    let handle;
    try {
      handle = fs.openSync(temporaryPath, 'wx', 0o600);
      const writeExport = (value) => {
        const buffer = Buffer.from(value, 'utf8');
        let offset = 0;
        while (offset < buffer.length) {
          const count = fs.writeSync(handle, buffer, offset, buffer.length - offset);
          if (count <= 0) throw new Error('Redacted export stopped while writing');
          offset += count;
        }
      };
      const { findings: _initialPage, ...metadata } = project;
      metadata.findings_page = null;
      writeExport(`${JSON.stringify(metadata).slice(0, -1)},"findings":[`);
      let written = 0;
      while (written < total) {
        const page = await requestBackendJson(
          `/api/application/projects/${encodeURIComponent(projectId)}/findings?offset=${written}&limit=500`,
        );
        if (
          page.total !== total || page.analysis_job_id !== analysisJobId
          || page.offset !== written || !Array.isArray(page.findings)
          || page.findings.length === 0 || page.findings.length > 500
        ) {
          throw new Error('Findings changed during export; retry after analysis finishes');
        }
        for (const finding of page.findings) {
          writeExport(`${written ? ',' : ''}${JSON.stringify(finding)}`);
          written += 1;
        }
      }
      if (written !== total) throw new Error('Finding count changed during export');
      writeExport(']}\n');
      fs.fsyncSync(handle);
      fs.closeSync(handle);
      handle = undefined;
      fs.renameSync(temporaryPath, destination.filePath);
    } catch (error) {
      if (handle !== undefined) {
        try { fs.closeSync(handle); } catch (_) { /* preserve the original export error */ }
      }
      try { fs.unlinkSync(temporaryPath); } catch (_) { /* exact temporary file may not exist */ }
      throw error;
    }
    return { cancelled: false, fileName: path.basename(destination.filePath), count: total };
  });

  ipcMain.removeHandler('aegis:chat-application-private');
  ipcMain.handle('aegis:chat-application-private', async (event, request) => {
    const value = request && typeof request === 'object' ? request : {};
    if (
      !applicationRendererAllowed(event)
      || !validProjectId(value.projectId)
      || typeof value.question !== 'string'
      || value.question.length < 1
      || value.question.length > 4000
      || typeof value.model !== 'string'
      || value.model.length < 1
      || value.model.length > 256
      || typeof value.lmUrl !== 'string'
      || value.lmUrl.length > 2048
      || !validApplicationChatHistory(value.history || [])
      || !/^[A-Za-z0-9_-]{8,128}$/.test(String(value.requestId || ''))
    ) {
      throw new Error('Private local-model request was rejected');
    }
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Share exact evidence with LM Studio?',
      message: 'Allow the selected local model to read extracted secret values for this question?',
      detail: 'AEGIS restricts the provider URL to this computer. The prompt may include credentials, tokens, or key material; it is not added to the normal report.',
      buttons: ['Cancel', 'Share with local model'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (confirmation.response !== 1) return { cancelled: true };
    const response = await requestBackendNdjson(
      `/api/application/projects/${encodeURIComponent(value.projectId)}/chat`,
      {
        question: value.question,
        lm_url: value.lmUrl,
        model: value.model,
        include_private: true,
        stream: true,
        history: (value.history || []).map((item) => ({
          role: item.role,
          content: item.content,
        })),
      },
      { 'X-AEGIS-Artifact-Token': artifactImportToken },
      (progress) => {
        if (!event.sender.isDestroyed()) {
          event.sender.send('aegis:application-chat-progress', {
            requestId: value.requestId,
            progress,
          });
        }
      },
    );
    return { cancelled: false, response };
  });
}

function createMainWindow() {
  const window = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1000,
    minHeight: 700,
    backgroundColor: '#0a0e17',
    title: 'AEGIS — AI Pentest Agent',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,  // macOS security: stronger isolation for renderer
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    show: false,
  });
  mainWindow = window;

  const url = `http://${SERVER_HOST}:${internalPort}/#token=${encodeURIComponent(authToken)}`;
  window.loadURL(url);

  window.once('ready-to-show', () => {
    if (window.isDestroyed()) return;
    window.show();
    if (focusWhenWindowReady) {
      focusWhenWindowReady = false;
      revealWindow(window);
    }
    // Optional: open devtools in non-packaged for debugging the UI
    if (!app.isPackaged) {
      // window.webContents.openDevTools({ mode: 'detach' });
    }
  });

  window.on('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });

  // Make external links open in real browser
  window.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        shell.openExternal(parsed.toString());
      }
    } catch (_) { /* deny malformed URLs */ }
    return { action: 'deny' };
  });

  const appOrigin = `http://${SERVER_HOST}:${internalPort}`;
  window.webContents.on('will-navigate', (event, navigationUrl) => {
    try {
      if (new URL(navigationUrl).origin !== appOrigin) event.preventDefault();
    } catch (_) { event.preventDefault(); }
  });
  window.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
}

function startBackend() {
  const binary = getBackendBinary();

  if (!fs.existsSync(binary)) {
    dialog.showErrorBox(
      'AEGIS Backend Missing',
      `Could not find the embedded backend at:\n${binary}\n\n` +
      'Please build it first:\n  npm run build:server\n' +
      'Then rebuild the app: npm run dist'
    );
    app.quit();
    return false;
  }

  console.log('[AEGIS] Starting embedded backend:', binary);

  // GUI-launched apps often receive a very minimal $PATH
  // (missing common locations where pentest tools like nmap, gobuster live after install via brew/apt/snap).
  // We explicitly augment PATH for the backend child (and everything it spawns)
  // so that tool discovery and shell-free child-process execution can find them.
  const originalPath = process.env.PATH || process.env.Path || '';
  let toolPaths = [];
  if (process.platform === 'darwin') {
    toolPaths = [
      '/opt/homebrew/bin',
      '/opt/homebrew/sbin',
      '/opt/homebrew/opt/ruby/bin',
      '/opt/homebrew/opt/samba/bin',
      '/opt/homebrew/opt/samba/sbin',
      '/opt/homebrew/opt/net-snmp/bin',
      '/opt/homebrew/opt/net-snmp/sbin',
      '/usr/local/bin',
      '/usr/local/sbin',
      '/usr/local/opt/ruby/bin',
      '/usr/local/opt/samba/bin',
      '/usr/local/opt/samba/sbin',
      '/usr/local/opt/net-snmp/bin',
      '/usr/local/opt/net-snmp/sbin',
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
    ];
  } else if (process.platform === 'linux') {
    const home = os.homedir();
    toolPaths = [
      '/usr/bin',
      '/usr/local/bin',
      '/usr/sbin',
      '/sbin',
      '/snap/bin',
      path.join(home, '.local/bin'),
      path.join(home, 'bin'),
      // Common for user-installed tools
      path.join(home, '.cargo/bin'),
      path.join(home, 'go/bin'),
    ];
  } else if (process.platform === 'win32') {
    const home = os.homedir();
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    toolPaths = [
      path.join(programFiles, 'Nmap'),
      path.join(programFilesX86, 'Nmap'),
      path.join(programFiles, 'Git', 'cmd'),
      path.join(programFiles, 'Git', 'bin'),
      'C:\\ProgramData\\chocolatey\\bin',
      path.join(home, 'scoop', 'shims'),
      path.join(localAppData, 'Microsoft', 'WindowsApps'),
      path.join(home, '.local', 'bin'),
      path.join(home, '.lmstudio', 'bin'),
    ];
  }
  const combined = [...toolPaths, ...originalPath.split(path.delimiter)];
  const seen = new Set();
  const augmentedPath = combined
    .filter((p) => p && !seen.has(p) && (seen.add(p), true))
    .join(path.delimiter);

  serverProcess = spawn(
    binary,
    [
      '--port', String(internalPort),
      '--auth-token', authToken,
      '--instance-id', instanceId,
      '--allowed-origin', `http://${SERVER_HOST}:${internalPort}`,
      '--allowed-origin', `http://localhost:${internalPort}`,
      '--desktop',           // tells backend to use quieter logging + no reload
    ],
    {
      cwd: path.dirname(binary),
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PATH: augmentedPath,
        // Ensure the frozen python knows it's in desktop mode if needed
        AEGIS_DESKTOP: '1',
        AEGIS_AUTH_TOKEN: authToken,
        AEGIS_INSTANCE_ID: instanceId,
        AEGIS_PORT: String(internalPort),
        AEGIS_ARTIFACT_IMPORT_TOKEN: artifactImportToken,
      },
    }
  );

  serverProcess.stdout.on('data', (d) => {
    const s = d.toString();
    if (s.includes('Uvicorn running') || s.includes('Application startup complete')) {
      console.log('[AEGIS backend]', s.trim());
    }
  });

  serverProcess.stderr.on('data', (d) => {
    console.error('[AEGIS backend err]', d.toString().trim());
  });

  serverProcess.once('error', (error) => {
    if (isQuitting) return;
    dialog.showErrorBox('AEGIS backend failed to launch', error.message);
    app.quit();
  });

  serverProcess.on('exit', (code) => {
    console.log('[AEGIS] Backend exited with code', code);
    if (isQuitting) return;
    if (mainWindow && !mainWindow.isDestroyed()) {
      dialog.showMessageBox(mainWindow, {
        type: 'error',
        message: 'Backend process stopped',
        detail: `The Python server exited (code ${code}). The app will now close.`,
      });
    }
    app.quit();
  });

  return true;
}

async function launch() {
  try {
    internalPort = await getFreeLoopbackPort();
  } catch (error) {
    dialog.showErrorBox('AEGIS failed to start', `Could not reserve a local backend port.\n${error.message}`);
    app.quit();
    return;
  }
  // Start the python server first
  if (!startBackend()) return;

  try {
    await waitForServerReady(internalPort);
    console.log('[AEGIS] Backend is ready on', internalPort);
  } catch (e) {
    dialog.showErrorBox('AEGIS failed to start', 'The backend did not become ready in time.\n' + e.message);
    app.quit();
    return;
  }

  registerApplicationResearchIpc();
  backendReady = true;
  createMainWindow();

  // On mac, re-create window when clicking dock icon
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    } else {
      revealWindow(mainWindow);
    }
  });
}

if (isPrimaryInstance) app.on('ready', launch);

app.on('window-all-closed', () => {
  // On mac apps usually stay alive until explicit quit, but for this tool we quit when window closes.
  if (process.platform !== 'darwin' || app.isPackaged) {
    if (serverProcess && !serverProcess.killed) {
      terminateBackend();
    }
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  if (serverProcess && !serverProcess.killed) {
    console.log('[AEGIS] Terminating backend...');
    terminateBackend();
  }
});

// Graceful shutdown on signals
['SIGINT', 'SIGTERM'].forEach((sig) => {
  process.on(sig, () => {
    terminateBackend();
    app.quit();
  });
});
