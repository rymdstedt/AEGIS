const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SUPPORTED_PROVIDERS = Object.freeze(['censys', 'netlas']);
const MAX_FILE_BYTES = 64 * 1024;
const MAX_CIPHERTEXT_BYTES = 8 * 1024;

function validateSecret(value, provider) {
  if (
    typeof value !== 'string'
    || value.length < 10
    || value.length > 512
    || [...value].some((character) => {
      const code = character.codePointAt(0);
      return code < 33 || code > 126;
    })
  ) {
    throw new Error(`${provider} credential must be a single printable token of 10 to 512 characters`);
  }
  return value;
}

function createCredentialStore({ app, safeStorage, platform = process.platform }) {
  const credentialPath = path.join(app.getPath('userData'), 'provider-credentials.v1.json');

  async function availability() {
    if (!safeStorage || typeof safeStorage.isAsyncEncryptionAvailable !== 'function') {
      return { available: false, protection: 'unavailable' };
    }
    try {
      if (!await safeStorage.isAsyncEncryptionAvailable()) {
        return { available: false, protection: 'unavailable' };
      }
      if (
        platform === 'linux'
        && typeof safeStorage.getSelectedStorageBackend === 'function'
        && safeStorage.getSelectedStorageBackend() === 'basic_text'
      ) {
        return { available: false, protection: 'unavailable' };
      }
      return {
        available: true,
        protection: platform === 'darwin'
          ? 'macOS Keychain'
          : platform === 'win32'
            ? 'Windows user protection'
            : 'system secret service',
      };
    } catch (_) {
      return { available: false, protection: 'unavailable' };
    }
  }

  function readDocument() {
    if (!fs.existsSync(credentialPath)) return { version: 1, credentials: {} };
    const stat = fs.statSync(credentialPath);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) {
      throw new Error('Saved provider credentials could not be read safely');
    }
    let document;
    try {
      document = JSON.parse(fs.readFileSync(credentialPath, 'utf8'));
    } catch (_) {
      throw new Error('Saved provider credentials could not be read safely');
    }
    if (document?.version !== 1 || !document.credentials || typeof document.credentials !== 'object') {
      throw new Error('Saved provider credentials use an unsupported format');
    }
    const credentials = {};
    for (const provider of SUPPORTED_PROVIDERS) {
      const encoded = document.credentials[provider];
      if (encoded === undefined) continue;
      if (
        typeof encoded !== 'string'
        || encoded.length > MAX_CIPHERTEXT_BYTES * 2
        || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)
      ) {
        throw new Error('Saved provider credentials could not be read safely');
      }
      const encrypted = Buffer.from(encoded, 'base64');
      if (!encrypted.length || encrypted.length > MAX_CIPHERTEXT_BYTES) {
        throw new Error('Saved provider credentials could not be read safely');
      }
      credentials[provider] = encoded;
    }
    return { version: 1, credentials };
  }

  function writeDocument(document) {
    fs.mkdirSync(path.dirname(credentialPath), { recursive: true, mode: 0o700 });
    const temporaryPath = `${credentialPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(temporaryPath, `${JSON.stringify(document)}\n`, {
        encoding: 'utf8', flag: 'wx', mode: 0o600,
      });
      try { fs.chmodSync(temporaryPath, 0o600); } catch (_) { /* Windows ignores POSIX modes. */ }
      try {
        fs.renameSync(temporaryPath, credentialPath);
      } catch (error) {
        if (!['EEXIST', 'EPERM'].includes(error.code)) throw error;
        fs.unlinkSync(credentialPath);
        fs.renameSync(temporaryPath, credentialPath);
      }
    } catch (error) {
      try { fs.unlinkSync(temporaryPath); } catch (_) { /* The exact temp file may not exist. */ }
      throw error;
    }
  }

  async function load() {
    const status = await availability();
    if (!status.available) return { ...status, credentials: {}, stored: [] };
    const document = readDocument();
    const credentials = {};
    let rotated = false;
    for (const provider of SUPPORTED_PROVIDERS) {
      const encoded = document.credentials[provider];
      if (!encoded) continue;
      try {
        const decrypted = await safeStorage.decryptStringAsync(Buffer.from(encoded, 'base64'));
        credentials[provider] = validateSecret(decrypted.result, provider);
        if (decrypted.shouldReEncrypt) {
          const replacement = await safeStorage.encryptStringAsync(credentials[provider]);
          document.credentials[provider] = replacement.toString('base64');
          rotated = true;
        }
      } catch (_) {
        throw new Error('Saved provider credentials could not be unlocked');
      }
    }
    if (rotated) writeDocument(document);
    return { ...status, credentials, stored: Object.keys(credentials) };
  }

  async function save(updates) {
    const status = await availability();
    if (!status.available) throw new Error('Protected credential storage is unavailable on this device');
    if (!updates || typeof updates !== 'object') {
      throw new Error('Provider credential update was rejected');
    }
    const document = readDocument();
    for (const provider of SUPPORTED_PROVIDERS) {
      if (updates[provider] === undefined) continue;
      const secret = validateSecret(updates[provider], provider);
      const encrypted = await safeStorage.encryptStringAsync(secret);
      if (!Buffer.isBuffer(encrypted) || !encrypted.length || encrypted.length > MAX_CIPHERTEXT_BYTES) {
        throw new Error('Protected credential storage returned an invalid value');
      }
      document.credentials[provider] = encrypted.toString('base64');
    }
    writeDocument(document);
    return { ...status, stored: Object.keys(document.credentials) };
  }

  async function clear(provider = 'all') {
    if (provider !== 'all' && !SUPPORTED_PROVIDERS.includes(provider)) {
      throw new Error('Unsupported provider credential');
    }
    if (!fs.existsSync(credentialPath)) return { cleared: true, stored: [] };
    if (provider === 'all') {
      fs.unlinkSync(credentialPath);
      return { cleared: true, stored: [] };
    }
    const document = readDocument();
    delete document.credentials[provider];
    if (Object.keys(document.credentials).length) writeDocument(document);
    else fs.unlinkSync(credentialPath);
    return { cleared: true, stored: Object.keys(document.credentials) };
  }

  return Object.freeze({ availability, load, save, clear });
}

module.exports = { createCredentialStore, SUPPORTED_PROVIDERS };
