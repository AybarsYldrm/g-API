'use strict';

const { URL } = require('url');

const authority = process.env.MSFT_AUTHORITY || 'https://login.microsoftonline.com/fitfak.net';
const redirectUri = process.env.MSFT_REDIRECT_URI || 'https://fitfak.net/callback';

const normalizeArray = (value) => Array.isArray(value) ? value : (value ? [value] : []);

const trimSlashes = (segment = '') => String(segment).replace(/^\/+|\/+$/g, '');

const collectDefaultIssuers = () => {
  const defaults = new Set();

  let parsed;
  try {
    parsed = new URL(authority);
  } catch (err) {
    parsed = null;
  }

  const authorityWithoutSlash = String(authority).replace(/\/$/, '');
  defaults.add(`${authorityWithoutSlash}/v2.0`);

  if (parsed) {
    const origin = `${parsed.protocol}//${parsed.host}`;
    const tenantSegment = trimSlashes(parsed.pathname);

    if (tenantSegment) {
      defaults.add(`${origin}/${tenantSegment}/v2.0`);
      defaults.add(`${origin}/${tenantSegment}`);
    }

    defaults.add(`${origin}/{tenantId}/v2.0`);
    defaults.add(`${origin}/{tenantId}`);
  }

  // Legacy Azure AD tokens sometimes emit the sts.windows.net issuer.
  defaults.add('https://sts.windows.net/{tenantId}/');
  defaults.add('https://sts.windows.net/{tenantId}');

  return Array.from(defaults);
};

let expectedIssuers = collectDefaultIssuers();
if (process.env.MSFT_EXPECTED_ISSUERS) {
  try {
    const parsed = JSON.parse(process.env.MSFT_EXPECTED_ISSUERS);
    expectedIssuers = normalizeArray(parsed).map((entry) => String(entry));
  } catch (err) {
    console.warn('Failed to parse MSFT_EXPECTED_ISSUERS env, falling back to defaults.');
  }
}

const expectedIssuer = process.env.MSFT_EXPECTED_ISSUER || expectedIssuers[0];

module.exports = {
  authority,
  clientId: process.env.MSFT_CLIENT_ID || '', 
  clientSecret: process.env.MSFT_CLIENT_SECRET || '',
  redirectUri,
  postLogoutRedirectUri: process.env.MSFT_POST_LOGOUT_REDIRECT_URI || "https://fitfak.net",
  scope: process.env.MSFT_SCOPE || 'openid profile email offline_access',
  expectedIssuer,
  expectedIssuers,
  jwks: {
    keys: process.env.MSFT_JWKS ? JSON.parse(process.env.MSFT_JWKS).keys : []
  }
};
