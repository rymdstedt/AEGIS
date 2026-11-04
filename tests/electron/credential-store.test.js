const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createCredentialStore } = require('../../electron/credential-store');

function fixture(t, { platform = 'darwin', available = true, backend = 'keychain' } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-credentials-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const safeStorage = {
    async isAsyncEncryptionAvailable() { return available; },
    getSelectedStorageBackend() { return backend; },
    async encryptStringAsync(value) { return Buffer.from(`protected:${value}`, 'utf8'); },
    async decryptStringAsync(value) {
      const encoded = value.toString('utf8');
      if (!encoded.startsWith('protected:')) throw new Error('bad ciphertext');
      return { result: encoded.slice('protected:'.length), shouldReEncrypt: false };
    },
  };
  const app = { getPath(name) {
    assert.equal(name, 'userData');
    return directory;
  } };
  return { directory, store: createCredentialStore({ app, safeStorage, platform }) };
}

test('provider credentials are encrypted on disk and restored for the desktop renderer', async (t) => {
  const { directory, store } = fixture(t);
  const saved = await store.save({ censys: 'censys-secret-value' });
  assert.deepEqual(saved.stored, ['censys']);

  const credentialPath = path.join(directory, 'provider-credentials.v1.json');
  const raw = fs.readFileSync(credentialPath, 'utf8');
  assert.doesNotMatch(raw, /censys-secret-value/);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(credentialPath).mode & 0o777, 0o600);
  }

  await store.save({ netlas: 'netlas-secret-value' });
  const loaded = await store.load();
  assert.equal(loaded.protection, 'macOS Keychain');
  assert.deepEqual(loaded.credentials, {
    censys: 'censys-secret-value',
    netlas: 'netlas-secret-value',
  });
  assert.deepEqual(loaded.stored, ['censys', 'netlas']);
});

test('invalid secrets are rejected before a credential file is created', async (t) => {
  const { directory, store } = fixture(t);
  await assert.rejects(store.save({ censys: 'short' }), /10 to 512/);
  assert.equal(fs.existsSync(path.join(directory, 'provider-credentials.v1.json')), false);
});

test('forget removes the exact credential file and does not return saved values', async (t) => {
  const { directory, store } = fixture(t);
  await store.save({ netlas: 'netlas-secret-value' });
  assert.deepEqual(await store.clear(), { cleared: true, stored: [] });
  assert.equal(fs.existsSync(path.join(directory, 'provider-credentials.v1.json')), false);
  const loaded = await store.load();
  assert.deepEqual(loaded.credentials, {});
});

test('Linux basic text fallback is refused instead of pretending to protect keys', async (t) => {
  const { directory, store } = fixture(t, { platform: 'linux', backend: 'basic_text' });
  const loaded = await store.load();
  assert.equal(loaded.available, false);
  await assert.rejects(store.save({ netlas: 'netlas-secret-value' }), /unavailable/);
  assert.equal(fs.existsSync(path.join(directory, 'provider-credentials.v1.json')), false);
});
