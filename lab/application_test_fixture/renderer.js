process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function applyRemoteRule(untrustedRule) {
  return eval(untrustedRule);
}

module.exports = { applyRemoteRule };
