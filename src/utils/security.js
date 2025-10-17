'use strict';

const { canOverrideOwnership } = require('./permissions');

function buildSecurityError(message, code, statusCode) {
  const err = new Error(message);
  err.statusCode = statusCode;
  err.extensions = Object.assign({
    code,
    httpStatus: statusCode
  }, err.extensions || {});
  return err;
}

function stripCertificatePaths(container) {
  if (!container || typeof container !== 'object') return;
  const cert = container.certificate;
  if (!cert || typeof cert !== 'object') return;
  const sanitized = Object.assign({}, cert);
  delete sanitized.keyPath;
  delete sanitized.certPath;
  delete sanitized.csrPath;
  delete sanitized.publicKeyPath;
  delete sanitized.privateKeyPath;
  delete sanitized.configPath;
  delete sanitized.rawPem;
  container.certificate = sanitized;
}

function sanitizeUser(user) {
  if (!user) return null;
  const { password, passwordHash, secretToken, ...rest } = user;
  const clone = JSON.parse(JSON.stringify(rest));
  stripCertificatePaths(clone);
  if (clone.pki && typeof clone.pki === 'object') {
    stripCertificatePaths(clone.pki);
  }
  return clone;
}

function ensureOwnership(user, ownerId) {
  if (!user) throw buildSecurityError('Authentication required', 'UNAUTHENTICATED', 401);
  if (canOverrideOwnership(user)) return true;
  if (user.id !== ownerId) {
    throw buildSecurityError('Forbidden', 'FORBIDDEN', 403);
  }
  return true;
}

module.exports = { sanitizeUser, ensureOwnership, buildSecurityError };
