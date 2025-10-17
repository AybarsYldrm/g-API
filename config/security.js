'use strict';

const crypto = require('crypto');
const { permissionMaskFrom, normalizePermissionMask } = require('../src/utils/permissions');
const { parseStringList } = require('./utils');

const sessionTtlSeconds = Number(process.env.SESSION_TTL_SECONDS || 3600);

let sessionJwk = null;
if (process.env.SESSION_JWK) {
  try {
    sessionJwk = JSON.parse(process.env.SESSION_JWK);
  } catch (err) {
    console.warn('Failed to parse SESSION_JWK env, ignoring.');
  }
}

if (!sessionJwk) {
  sessionJwk = {
    kty: 'oct',
    kid: 'local-dev',
    k: Buffer.from('graph-api-local-session-secret').toString('base64')
  };
}

const defaultRolePermissions = {
  admin: ['SUPER_ADMIN', 'MANAGE_TENANT', 'MANAGE_ALL_EVENTS', 'MANAGE_EVENTS'],
  manager: ['MANAGE_ALL_EVENTS', 'MANAGE_EVENTS'],
  member: ['BASIC']
};

let configuredRolePermissions = defaultRolePermissions;
if (process.env.SECURITY_ROLE_PERMISSIONS) {
  try {
    const parsed = JSON.parse(process.env.SECURITY_ROLE_PERMISSIONS);
    if (parsed && typeof parsed === 'object') configuredRolePermissions = parsed;
  } catch (err) {
    console.warn('Failed to parse SECURITY_ROLE_PERMISSIONS env, falling back to defaults.');
  }
}

const rolePermissionMap = Object.entries(configuredRolePermissions).reduce((acc, [role, value]) => {
  try {
    acc[role.toLowerCase()] = normalizePermissionMask(permissionMaskFrom(value));
  } catch (err) {
    console.warn(`Unable to normalize permissions for role "${role}": ${err.message}`);
  }
  return acc;
}, {});

const defaultPermissionMask = (() => {
  try {
    return normalizePermissionMask(permissionMaskFrom(process.env.DEFAULT_PERMISSION_MASK || ['BASIC']));
  } catch (err) {
    console.warn('Failed to read DEFAULT_PERMISSION_MASK env, using BASIC preset.');
    return normalizePermissionMask(permissionMaskFrom(['BASIC']));
  }
})();

const downloadTokenSecret = process.env.DOWNLOAD_TOKEN_SECRET
  || sessionJwk.k
  || crypto.createHash('sha256').update('graph-api-download-secret').digest('hex');
const downloadTokenTtlSeconds = Number(process.env.DOWNLOAD_TOKEN_TTL || 300);
const allowedOrigins = parseStringList(process.env.SECURITY_ALLOWED_ORIGINS, ['https://fitfak.net', 'http://localhost']);

module.exports = {
  sessionCookieName: process.env.SESSION_COOKIE_NAME || 'ms_session',
  sessionCookieSecure: process.env.SESSION_COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  sessionCookieSameSite: process.env.SESSION_COOKIE_SAMESITE || 'Lax',
  sessionCookieDomain: process.env.SESSION_COOKIE_DOMAIN || undefined,
  sessionTtlSeconds,
  sessionIssuer: process.env.SESSION_ISSUER || 'urn:graph-api:session',
  sessionAudience: process.env.SESSION_AUDIENCE || process.env.MSFT_CLIENT_ID || '00000000-0000-0000-0000-000000000000',
  sessionJwk,
  rolePermissionMap,
  defaultPermissionMask,
  operationEpoch: Number(process.env.OPERATION_EPOCH_MS || Date.UTC(2023, 0, 1)),
  allowedOrigins,
  downloadTokens: {
    secret: downloadTokenSecret,
    ttlSeconds: Number.isFinite(downloadTokenTtlSeconds) ? downloadTokenTtlSeconds : 300
  }
};
