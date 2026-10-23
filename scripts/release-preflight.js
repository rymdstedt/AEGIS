const requiredSigning = ['CSC_LINK', 'CSC_KEY_PASSWORD'];
const appleIdNotarization = ['APPLE_ID', 'APPLE_APP_SPECIFIC_PASSWORD', 'APPLE_TEAM_ID'];
const apiKeyNotarization = ['APPLE_API_KEY', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER'];

function missing(names) {
  return names.filter((name) => !process.env[name]);
}

const signingMissing = missing(requiredSigning);
const hasAppleId = missing(appleIdNotarization).length === 0;
const hasApiKey = missing(apiKeyNotarization).length === 0;

if (signingMissing.length || (!hasAppleId && !hasApiKey)) {
  const details = [];
  if (signingMissing.length) details.push(`signing: ${signingMissing.join(', ')}`);
  if (!hasAppleId && !hasApiKey) {
    details.push('notarization: provide either APPLE_ID credentials or APPLE_API_KEY credentials');
  }
  console.error(`Release build blocked; missing ${details.join('; ')}.`);
  console.error('Use npm run dist:dev for an unsigned local build.');
  process.exit(1);
}

console.log('Release signing and notarization credentials are configured.');
