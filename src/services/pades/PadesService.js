'use strict';

const crypto = require('crypto');
const path = require('path');

const { PAdESManager } = require('../../pades/pades_manager');

const DEFAULT_PLACEHOLDER = 120000;
const DEFAULT_DOC_TS_PLACEHOLDER = 64000;
const DEFAULT_UPLOAD_ACCEPT = ['application/pdf'];

function parsePositiveInt(value, fallback = null) {
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  const intVal = Math.trunc(num);
  return intVal > 0 ? intVal : fallback;
}

function parseBoolean(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  return undefined;
}

function sanitizeFilenamePart(value) {
  if (!value) return '';
  return String(value)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 64);
}

class PadesService {
  constructor({ pkiService, config = {}, logger = null } = {}) {
    if (!pkiService) throw new Error('PadesService requires pkiService');

    this.pki = pkiService;
    this.config = Object.assign({
      tsaUrl: 'http://timestamp.digicert.com',
      tsaOptions: {},
      tsaHeaders: {},
      placeholderHexLen: DEFAULT_PLACEHOLDER,
      defaultFieldName: null,
      documentTimestamp: { append: false, fieldName: null, placeholderHexLen: DEFAULT_DOC_TS_PLACEHOLDER },
      upload: { directory: path.join(process.cwd(), 'data', 'uploads', 'pades'), maxBytes: 20 * 1024 * 1024, accept: DEFAULT_UPLOAD_ACCEPT.slice() },
      download: { directory: 'pades', filenamePrefix: 'signed', disposition: 'attachment', expiresIn: 15 * 60 }
    }, config || {});

    this.manager = new PAdESManager({
      tsaUrl: this.config.tsaUrl,
      tsaOptions: this.#cleanOptions(this.config.tsaOptions),
      tsaHeaders: this.#cleanOptions(this.config.tsaHeaders),
      logger: logger || null
    });
  }

  getUploadOptions() {
    const cfg = this.config.upload || {};
    const maxBytes = parsePositiveInt(cfg.maxBytes, 20 * 1024 * 1024);
    const folder = cfg.directory || path.join(process.cwd(), 'data', 'uploads', 'pades');
    const accept = Array.isArray(cfg.accept) && cfg.accept.length ? cfg.accept.slice() : DEFAULT_UPLOAD_ACCEPT.slice();
    return {
      folder,
      maxBytes,
      accept,
      naming: (orig) => this.#buildUploadName(orig)
    };
  }

  getDownloadOptions() {
    const cfg = this.config.download || {};
    return {
      directory: cfg.directory || 'pades',
      filenamePrefix: cfg.filenamePrefix || 'signed',
      disposition: cfg.disposition || 'attachment',
      expiresIn: parsePositiveInt(cfg.expiresIn, 15 * 60) || 15 * 60
    };
  }

  generateArtifactInfo(downloadRoot, { originalName = null, user = null, mode = null } = {}) {
    if (!downloadRoot) throw new Error('downloadRoot is required');
    const { directory } = this.getDownloadOptions();
    const targetDir = path.join(downloadRoot, directory);
    const filename = this.#buildSignedFilename(originalName, user, mode);
    const absolutePath = path.join(targetDir, filename);
    return { directory: targetDir, filename, absolutePath };
  }

  async signForUser(user, pdfBuffer, options = {}) {
    if (!user || !user.id) throw new Error('user with id is required');
    if (!Buffer.isBuffer(pdfBuffer)) throw new Error('pdfBuffer must be a Buffer');

    const forceRenew = options.forceRenew === true;
    const material = await this.pki.getUserSigningMaterial(user, { forceRenew });
    if (!material || !material.keyPem || !material.certPem) {
      throw new Error('User signing material missing');
    }

    const placeholderHexLen = parsePositiveInt(options.placeholderHexLen, this.config.placeholderHexLen || DEFAULT_PLACEHOLDER)
      || DEFAULT_PLACEHOLDER;
    const fieldName = this.#normalizeFieldName(options.fieldName !== undefined ? options.fieldName : this.config.defaultFieldName);
    const documentTimestamp = this.#resolveDocumentTimestamp(options.documentTimestamp);

    const chainPems = Array.isArray(material.chainPems) ? material.chainPems.filter(Boolean) : [];

    const result = await this.manager.signPAdES_T({
      pdfBuffer,
      keyPem: material.keyPem,
      certPem: material.certPem,
      chainPems,
      fieldName,
      placeholderHexLen,
      documentTimestamp
    });

    return Object.assign({
      pdf: result.pdf,
      mode: result.mode,
      documentTimestamp,
      fieldName,
      placeholderHexLen
    }, material);
  }

  #cleanOptions(obj) {
    const out = {};
    if (!obj || typeof obj !== 'object') return out;
    for (const [key, value] of Object.entries(obj)) {
      if (value === undefined || value === null || value === '') continue;
      out[key] = value;
    }
    return out;
  }

  #normalizeFieldName(value) {
    if (!value || typeof value !== 'string') {
      const configured = this.config.defaultFieldName;
      return typeof configured === 'string' && configured.trim() ? configured.trim() : null;
    }
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  }

  #resolveDocumentTimestamp(override) {
    const base = this.config.documentTimestamp && typeof this.config.documentTimestamp === 'object'
      ? Object.assign({}, this.config.documentTimestamp)
      : {};

    if (override && typeof override === 'object') {
      if (override.append !== undefined) {
        const parsed = parseBoolean(override.append);
        if (parsed !== undefined) base.append = parsed;
      }
      if (override.fieldName !== undefined) base.fieldName = override.fieldName;
      if (override.placeholderHexLen !== undefined) base.placeholderHexLen = override.placeholderHexLen;
    }

    const append = base.append === true;
    const fieldName = this.#normalizeFieldName(base.fieldName || null);
    const placeholderHexLen = parsePositiveInt(base.placeholderHexLen, DEFAULT_DOC_TS_PLACEHOLDER) || DEFAULT_DOC_TS_PLACEHOLDER;

    return { append, fieldName, placeholderHexLen };
  }

  #buildUploadName(original) {
    const ext = path.extname(original || '').toLowerCase() || '.pdf';
    const base = path.basename(original || 'upload', ext);
    const sanitized = sanitizeFilenamePart(base) || 'upload';
    const nonce = crypto.randomBytes(6).toString('hex');
    return `${sanitized}-${nonce}${ext}`;
  }

  #buildSignedFilename(originalName, user, mode) {
    const cfg = this.getDownloadOptions();
    const prefix = sanitizeFilenamePart(cfg.filenamePrefix) || 'signed';
    const base = path.basename(originalName || '', path.extname(originalName || ''));
    const sanitizedBase = sanitizeFilenamePart(base);
    const suffixParts = [];
    if (user && user.id) {
      const idPart = sanitizeFilenamePart(String(user.id).slice(-8));
      if (idPart) suffixParts.push(idPart);
    }
    if (mode) {
      const modePart = sanitizeFilenamePart(mode);
      if (modePart) suffixParts.push(modePart);
    }
    suffixParts.push(Date.now().toString(36));
    suffixParts.push(crypto.randomBytes(4).toString('hex'));
    const bodyParts = [prefix];
    if (sanitizedBase) bodyParts.push(sanitizedBase);
    bodyParts.push(...suffixParts);
    return `${bodyParts.filter(Boolean).join('-')}.pdf`;
  }
}

module.exports = { PadesService };
