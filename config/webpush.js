'use strict';

const path = require('path');

function parseNumber(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

module.exports = {
  enabled: process.env.WEBPUSH_ENABLED !== 'false',
  dataDir: process.env.WEBPUSH_DATA_DIR ? path.resolve(process.env.WEBPUSH_DATA_DIR) : null,
  rateLimitWindowMs: parseNumber(process.env.WEBPUSH_RATE_LIMIT_WINDOW_MS, 60 * 1000),
  rateLimitMax: parseNumber(process.env.WEBPUSH_RATE_LIMIT_MAX, 30),
  defaultTtl: parseNumber(process.env.WEBPUSH_DEFAULT_TTL, 2419200),
  subject: process.env.WEBPUSH_SUBJECT || 'mailto:network@fitfak.net'
};
