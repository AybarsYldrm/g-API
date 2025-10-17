'use strict';

module.exports = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 465),
  username: process.env.SMTP_USERNAME || '',
  password: process.env.SMTP_PASSWORD || '',
  secure: process.env.SMTP_SECURE !== 'false',
  rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== 'false',
  defaultFrom: process.env.SMTP_FROM || process.env.SMTP_USERNAME || 'network@fitfak.net',
  timeoutMs: Number(process.env.SMTP_TIMEOUT_MS || 15000),
  appBaseUrl: process.env.APP_BASE_URL || '',
};
