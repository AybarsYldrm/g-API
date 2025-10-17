'use strict';

const path = require('path');

const { parseNumber, parseBoolean, parseStringList } = require('./utils');

function buildHeaders() {
  const headerValue = process.env.PADES_TSA_AUTH_HEADER || process.env.PADES_TSA_AUTHORIZATION;
  if (!headerValue) return {};
  return { Authorization: headerValue };
}

const defaultUploadDir = path.join(process.cwd(), 'data', 'uploads', 'pades');
const defaultAcceptTypes = ['application/pdf'];

const uploadAccept = (() => {
  const configured = parseStringList(process.env.PADES_UPLOAD_ACCEPT, defaultAcceptTypes);
  return configured.length ? configured : defaultAcceptTypes.slice();
})();

module.exports = {
  enabled: parseBoolean(process.env.PADES_ENABLED, true) !== false,
  tsaUrl: process.env.PADES_TSA_URL || 'http://timestamp.digicert.com',
  tsaOptions: {
    hashName: process.env.PADES_TSA_HASH || process.env.PADES_TSA_HASH_NAME || 'sha256',
    certReq: parseBoolean(process.env.PADES_TSA_CERT_REQ, true) !== false,
    allowMissingNonce: parseBoolean(process.env.PADES_TSA_ALLOW_MISSING_NONCE, false) === true,
    reqPolicyOid: process.env.PADES_TSA_POLICY_OID || null,
    nonceBytes: parseNumber(process.env.PADES_TSA_NONCE_BYTES, undefined)
  },
  tsaHeaders: buildHeaders(),
  placeholderHexLen: parseNumber(process.env.PADES_PLACEHOLDER_HEX_LEN, 120000),
  defaultFieldName: process.env.PADES_FIELD_NAME || null,
  documentTimestamp: {
    append: parseBoolean(process.env.PADES_DOC_TS_APPEND, false) === true,
    fieldName: process.env.PADES_DOC_TS_FIELD || null,
    placeholderHexLen: parseNumber(process.env.PADES_DOC_TS_PLACEHOLDER_HEX_LEN, 64000)
  },
  upload: {
    directory: process.env.PADES_UPLOAD_DIR || defaultUploadDir,
    maxBytes: parseNumber(process.env.PADES_UPLOAD_MAX_BYTES, 20 * 1024 * 1024),
    accept: uploadAccept
  },
  download: {
    directory: process.env.PADES_DOWNLOAD_DIR || 'pades',
    filenamePrefix: process.env.PADES_DOWNLOAD_PREFIX || 'signed',
    disposition: process.env.PADES_DOWNLOAD_DISPOSITION || 'attachment',
    expiresIn: parseNumber(process.env.PADES_DOWNLOAD_EXPIRES_IN, 15 * 60)
  }
};
