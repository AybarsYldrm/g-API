'use strict';

const PERMISSION_MASK_MAX = (1 << 18) - 1;

const PERMISSIONS = Object.freeze({
  VIEW_SELF: 1 << 0,
  EDIT_SELF: 1 << 1,
  MANAGE_EVENTS: 1 << 2,
  MANAGE_PARTICIPANTS: 1 << 3,
  MANAGE_REPORTS: 1 << 4,
  MANAGE_ALL_EVENTS: 1 << 10,
  MANAGE_TENANT: 1 << 16,
  SUPER_ADMIN: 1 << 17
});

const BASIC_MASK = PERMISSIONS.VIEW_SELF | PERMISSIONS.EDIT_SELF | PERMISSIONS.MANAGE_EVENTS;

function normalizePermissionMask(mask) {
  const numeric = Number(mask) || 0;
  return numeric & PERMISSION_MASK_MAX;
}

function permissionMaskFrom(input) {
  if (input == null) return 0;
  if (typeof input === 'number') return normalizePermissionMask(input);
  if (typeof input === 'bigint') return normalizePermissionMask(Number(input));
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return 0;
    if (/^0x/i.test(trimmed)) return normalizePermissionMask(parseInt(trimmed, 16));
    if (/^0b/i.test(trimmed)) return normalizePermissionMask(parseInt(trimmed.slice(2), 2));
    if (/^\d+$/.test(trimmed)) return normalizePermissionMask(parseInt(trimmed, 10));

    const alias = trimmed.toUpperCase();
    if (alias === 'BASIC') return BASIC_MASK;
    if (alias === 'ALL') return PERMISSION_MASK_MAX;
    if (PERMISSIONS[alias] !== undefined) return normalizePermissionMask(PERMISSIONS[alias]);
    throw new Error(`Unknown permission alias "${input}"`);
  }
  if (Array.isArray(input)) {
    return normalizePermissionMask(input.reduce((mask, item) => mask | permissionMaskFrom(item), 0));
  }
  if (typeof input === 'object') {
    if (Object.prototype.hasOwnProperty.call(input, 'mask')) {
      return permissionMaskFrom(input.mask);
    }
  }
  throw new Error(`Unsupported permission descriptor: ${input}`);
}

function combinePermissions(...inputs) {
  return normalizePermissionMask(inputs.reduce((mask, entry) => mask | permissionMaskFrom(entry), 0));
}

function hasPermission(subject, required) {
  const mask = typeof subject === 'number'
    ? normalizePermissionMask(subject)
    : normalizePermissionMask(subject && subject.permissions);
  const requiredMask = permissionMaskFrom(required);
  return (mask & requiredMask) === requiredMask;
}

function ensurePermission(user, required, message = 'Forbidden') {
  if (!user) {
    const err = new Error('Authentication required');
    err.statusCode = 401;
    err.extensions = { code: 'UNAUTHENTICATED', httpStatus: 401 };
    throw err;
  }
  if (!hasPermission(user, required)) {
    const err = new Error(message);
    err.statusCode = 403;
    err.extensions = { code: 'FORBIDDEN', httpStatus: 403 };
    throw err;
  }
  return true;
}

function maskToArray(mask) {
  const normalized = normalizePermissionMask(mask);
  return Object.entries(PERMISSIONS)
    .filter(([, bit]) => (normalized & bit) === bit)
    .map(([key]) => key);
}

function canOverrideOwnership(user) {
  return hasPermission(user, PERMISSIONS.MANAGE_ALL_EVENTS)
    || hasPermission(user, PERMISSIONS.MANAGE_TENANT)
    || hasPermission(user, PERMISSIONS.SUPER_ADMIN);
}

module.exports = {
  PERMISSIONS,
  BASIC_MASK,
  PERMISSION_MASK_MAX,
  normalizePermissionMask,
  permissionMaskFrom,
  combinePermissions,
  hasPermission,
  ensurePermission,
  maskToArray,
  canOverrideOwnership
};
