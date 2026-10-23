const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
// Isolate verification builds so the normal development app (which may be
// running) is not removed while Electron Builder prepares its output.
const outputSubdirectory = process.env.AEGIS_DEV_OUTPUT_SUBDIR;
if (outputSubdirectory && !/^coverage-[a-z0-9-]{1,40}$/.test(outputSubdirectory)) {
  throw new Error('AEGIS_DEV_OUTPUT_SUBDIR must be a coverage-* directory name.');
}
const outputRoot = path.join(
  projectRoot,
  'dist-electron',
  ...(outputSubdirectory ? [outputSubdirectory] : []),
);
const outputDirectory = path.join(outputRoot, 'mac-arm64');
const appPath = path.join(outputDirectory, 'AEGIS.app');
const backendPath = path.join(
  appPath,
  'Contents',
  'Resources',
  'aegis-server',
  'aegis-server',
);

function installedSigningIdentities() {
  try {
    const output = execFileSync(
      '/usr/bin/security',
      ['find-identity', '-v', '-p', 'codesigning'],
      { encoding: 'utf8' },
    );
    return [...output.matchAll(/^\s*\d+\)\s+[0-9A-F]+\s+"([^"]+)"/gm)]
      .map((match) => match[1]);
  } catch (_) {
    return [];
  }
}

function chooseSigningIdentity() {
  if (process.env.CSC_NAME) return process.env.CSC_NAME;
  const identities = installedSigningIdentities();
  return identities.find((name) => name.startsWith('Apple Development:'))
    || identities.find((name) => name.startsWith('Developer ID Application:'))
    || '-';
}

function inspectSignature(file) {
  const result = spawnSync('/usr/bin/codesign', ['-dvvv', file], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function hasAppleTeam(signature) {
  const match = signature.match(/^TeamIdentifier=(.+)$/m);
  return Boolean(match && match[1].trim() !== 'not set');
}

if (process.platform !== 'darwin') {
  throw new Error('The macOS development package must be built on macOS.');
}

const identity = chooseSigningIdentity();
const builder = path.join(projectRoot, 'node_modules', '.bin', 'electron-builder');
const args = [
  '--mac',
  '--arm64',
  '--dir',
  '-c.mac.notarize=false',
  '-c.mac.timestamp=none',
  `-c.mac.identity=${identity}`,
];
if (outputSubdirectory) {
  args.push(`-c.directories.output=${outputRoot}`);
}

if (identity === '-') {
  const devEntitlements = path.join(projectRoot, 'build', 'entitlements.mac.dev.plist');
  args.push(`-c.mac.entitlements=${devEntitlements}`);
  args.push(`-c.mac.entitlementsInherit=${devEntitlements}`);
  console.warn('No Apple code-signing identity found; using an ad-hoc development signature.');
  console.warn('macOS Local Network privacy may not track ad-hoc builds reliably.');
} else {
  console.log(`Signing the local AEGIS build as: ${identity}`);
}

// Electron Builder occasionally leaves only Finder's .DS_Store behind after
// replacing a previous directory build, then fails its own non-recursive rmdir.
// This path is the architecture-specific generated output, never source data.
fs.rmSync(outputDirectory, {
  recursive: true,
  force: true,
  maxRetries: 3,
  retryDelay: 100,
});

const build = spawnSync(builder, args, {
  cwd: projectRoot,
  env: process.env,
  stdio: 'inherit',
});
if (build.error) throw build.error;
if (build.status !== 0) process.exit(build.status || 1);

execFileSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath], {
  stdio: 'inherit',
});

const appSignature = inspectSignature(appPath);
const backendSignature = inspectSignature(backendPath);
if (!appSignature.includes('Identifier=ai.aegis.pentest')) {
  throw new Error(`AEGIS was not signed with its bundle identity:\n${appSignature}`);
}
if (identity !== '-' && !hasAppleTeam(appSignature)) {
  throw new Error(`AEGIS is missing its Apple signing team identity:\n${appSignature}`);
}
if (identity !== '-' && !hasAppleTeam(backendSignature)) {
  throw new Error(`The bundled backend was not signed as application code:\n${backendSignature}`);
}

console.log(`Verified signed development app: ${appPath}`);
