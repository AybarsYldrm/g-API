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

function sanitizeUser(user) {
  if (!user) return null;
  const { password, passwordHash, secretToken, ...rest } = user;
  return rest;
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
