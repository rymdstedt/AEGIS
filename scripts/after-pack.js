const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

/**
 * Electron's base macOS plist enables arbitrary network loads. AEGIS only
 * needs plain HTTP for its authenticated loopback backend, so enforce the
 * narrower policy after Electron Builder has merged its template.
 */
module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== 'darwin') return;

  const appName = `${context.packager.appInfo.productFilename}.app`;
  const infoPlist = path.join(context.appOutDir, appName, 'Contents', 'Info.plist');
  if (!fs.existsSync(infoPlist)) {
    throw new Error(`Packaged Info.plist not found: ${infoPlist}`);
  }

  execFileSync('/usr/bin/plutil', [
    '-replace',
    'NSAppTransportSecurity.NSAllowsArbitraryLoads',
    '-bool',
    'NO',
    infoPlist,
  ]);

  const policy = execFileSync('/usr/bin/plutil', [
    '-extract',
    'NSAppTransportSecurity.NSAllowsArbitraryLoads',
    'raw',
    '-o',
    '-',
    infoPlist,
  ], { encoding: 'utf8' }).trim();
  if (policy !== 'false') {
    throw new Error('Failed to disable arbitrary network loads in packaged app');
  }

  const localNetworkDescription = execFileSync('/usr/bin/plutil', [
    '-extract',
    'NSLocalNetworkUsageDescription',
    'raw',
    '-o',
    '-',
    infoPlist,
  ], { encoding: 'utf8' }).trim();
  if (!localNetworkDescription.includes('local network access')) {
    throw new Error('Packaged app is missing its local-network privacy description');
  }
};
