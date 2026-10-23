const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const Module = require('node:module');
const fs = require('node:fs');
const test = require('node:test');

async function runStartupCase({ portError = false, lockAvailable = true } = {}) {
  const app = new EventEmitter();
  const errors = [];
  let quitCount = 0;
  let spawnCount = 0;
  let finish;
  const quit = new Promise((resolve) => { finish = resolve; });
  app.isPackaged = false;
  app.requestSingleInstanceLock = () => lockAvailable;
  app.quit = () => {
    quitCount += 1;
    app.emit('before-quit');
    finish();
  };

  const fakeFs = Object.create(fs);
  fakeFs.existsSync = (file) => String(file).replaceAll('\\', '/').includes('/backend/dist/aegis-server')
    ? false : fs.existsSync(file);
  const fakeNet = {
    createServer() {
      const probe = new EventEmitter();
      probe.unref = () => {};
      probe.address = () => ({ port: 18123 });
      probe.close = (callback) => setImmediate(() => callback(null));
      probe.listen = (_port, _host, callback) => {
        setImmediate(() => portError
          ? probe.emit('error', new Error('port unavailable')) : callback());
      };
      return probe;
    },
  };

  const mainPath = require.resolve('../../electron/main.js');
  const originalLoad = Module._load;
  const originalSignals = new Map(
    ['SIGINT', 'SIGTERM'].map((signal) => [signal, new Set(process.listeners(signal))]),
  );
  let timeout;
  try {
    Module._load = function load(request, parent, isMain) {
      if (parent?.filename === mainPath) {
        if (request === 'electron') {
          return {
            app,
            BrowserWindow: class {},
            dialog: { showErrorBox: (...args) => errors.push(args) },
            ipcMain: {},
            shell: {},
          };
        }
        if (request === 'fs') return fakeFs;
        if (request === 'net') return fakeNet;
        if (request === 'child_process') {
          return {
            spawn: () => { spawnCount += 1; throw new Error('backend must not spawn'); },
            spawnSync: () => {},
          };
        }
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    delete require.cache[mainPath];
    require(mainPath);
    if (lockAvailable) app.emit('ready');
    await Promise.race([
      quit,
      new Promise((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('startup did not quit')), 1000);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
    Module._load = originalLoad;
    delete require.cache[mainPath];
    for (const [signal, previous] of originalSignals) {
      for (const listener of process.listeners(signal)) {
        if (!previous.has(listener)) process.removeListener(signal, listener);
      }
    }
  }
  return { errors, quitCount, spawnCount, readyListeners: app.listenerCount('ready') };
}

test('a second desktop process does not register startup or spawn a backend', async () => {
  const result = await runStartupCase({ lockAvailable: false });
  assert.equal(result.quitCount, 1);
  assert.equal(result.readyListeners, 0);
  assert.equal(result.spawnCount, 0);
});

test('a missing bundled backend fails immediately without a readiness wait', async () => {
  const result = await runStartupCase();
  assert.equal(result.quitCount, 1);
  assert.equal(result.spawnCount, 0);
  assert.match(result.errors[0][0], /Backend Missing/);
});

test('a loopback port failure exits without starting the backend', async () => {
  const result = await runStartupCase({ portError: true });
  assert.equal(result.quitCount, 1);
  assert.equal(result.spawnCount, 0);
  assert.match(result.errors[0][1], /port unavailable/);
});
