'use strict';

function parseNumber(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseStringList(value, fallback = []) {
  if (Array.isArray(value)) {
    const out = value
      .map((entry) => (typeof entry === 'string' ? entry.trim() : String(entry || '').trim()))
      .filter(Boolean);
    return out.length ? out : fallback.slice();
  }
  if (value === undefined || value === null || value === '') {
    return fallback.slice();
  }
  const normalized = String(value)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  return normalized.length ? normalized : fallback.slice();
}

module.exports = {
  parseNumber,
  parseBoolean,
  parseStringList
};
