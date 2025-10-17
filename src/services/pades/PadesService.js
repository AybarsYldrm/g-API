'use strict';

const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const path = require('path');

const { PAdESManager } = require('../../pades/pades_manager');
const { parsePositiveInt, parseBoolean } = require('./utils');

const DEFAULT_PLACEHOLDER = 120000;
const DEFAULT_DOC_TS_PLACEHOLDER = 64000;
const DEFAULT_UPLOAD_ACCEPT = ['application/pdf'];

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

class PadesFlowError extends Error {
  constructor(message, { statusCode = 400, code = 'PADES_ERROR', details = null, cause = null } = {}) {
    super(message);
    if (cause) this.cause = cause;
    this.statusCode = statusCode;
    this.code = code;
    if (details) this.details = details;
  }
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
    const directory = path.resolve(cfg.directory || path.join(process.cwd(), 'data', 'uploads', 'pades'));
    const accept = Array.isArray(cfg.accept) && cfg.accept.length ? cfg.accept.slice() : DEFAULT_UPLOAD_ACCEPT.slice();
    return {
      directory,
      baseDir: directory,
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

  buildSigningOptions(query = {}) {
    if (!query || typeof query !== 'object') return {};

    const options = {};

    if (query.fieldName !== undefined) options.fieldName = query.fieldName;

    const placeholderHexLen = parsePositiveInt(query.placeholderHexLen);
    if (placeholderHexLen) options.placeholderHexLen = placeholderHexLen;

    const docTimestampOverrides = {};
    const appendDocTs = parseBoolean(query.appendDocumentTimestamp);
    if (appendDocTs !== undefined) docTimestampOverrides.append = appendDocTs;
    if (query.documentTimestampField !== undefined) docTimestampOverrides.fieldName = query.documentTimestampField;
    const docTsPlaceholder = parsePositiveInt(query.documentTimestampPlaceholderHexLen);
    if (docTsPlaceholder) docTimestampOverrides.placeholderHexLen = docTsPlaceholder;
    if (Object.keys(docTimestampOverrides).length) options.documentTimestamp = docTimestampOverrides;

    const forceRenew = parseBoolean(query.forceRenewCertificate);
    if (forceRenew !== undefined) options.forceRenew = forceRenew;

    return options;
  }

  async processSigningRequest({ user, upload, query = {}, downloadService, downloadPath }) {
    if (!user || !user.id) {
      throw new PadesFlowError('Authenticated user required', { statusCode: 401, code: 'AUTH_REQUIRED' });
    }
    if (!upload || !upload.path) {
      throw new PadesFlowError('PDF file is required', { statusCode: 400, code: 'PDF_REQUIRED' });
    }
    if (!downloadService || typeof downloadService.createToken !== 'function' || !downloadService.rootDir) {
      throw new PadesFlowError('Download service unavailable', { statusCode: 503, code: 'DOWNLOAD_UNAVAILABLE' });
    }

    const pdfBuffer = await this.#loadPdfFromUpload(upload);
    this.#assertPdf(pdfBuffer);

    const signingOptions = this.buildSigningOptions(query);
    let signed;
    try {
      signed = await this.signForUser(user, pdfBuffer, signingOptions);
    } catch (err) {
      if (err?.code === 'KEY_MISSING') {
        throw new PadesFlowError(err.message || 'User private key is not available', {
          statusCode: 409,
          code: 'KEY_MISSING',
          cause: err
        });
      }
      throw err instanceof PadesFlowError
        ? err
        : new PadesFlowError(err.message || 'Unable to sign PDF', { statusCode: 500, code: err.code || 'SIGN_FAILED', cause: err });
    }

    const artifact = await this.#persistSignedArtifact(downloadService.rootDir, signed.pdf, {
      originalName: upload.originalName || upload.filename,
      user: signed.user || user,
      mode: signed.mode
    });

    try {
      const { token, downloadUrl, expiresAt } = this.#createDownloadToken(downloadService, artifact, downloadPath);

      return {
        success: true,
        mode: signed.mode,
        filename: artifact.filename,
        token,
        downloadUrl,
        expiresAt,
        documentTimestamp: signed.documentTimestamp,
        fieldName: signed.fieldName,
        placeholderHexLen: signed.placeholderHexLen
      };
    } catch (err) {
      await this.#removeFile(artifact.absolutePath);
      throw err instanceof PadesFlowError
        ? err
        : new PadesFlowError('Unable to create download token', { statusCode: 500, code: 'DOWNLOAD_TOKEN_FAILED', cause: err });
    }
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

  async #loadPdfFromUpload(upload) {
    let pdfBuffer;
    try {
      pdfBuffer = await fsp.readFile(upload.path);
    } catch (err) {
      throw new PadesFlowError('Uploaded file could not be read', {
        statusCode: 500,
        code: 'UPLOAD_READ_FAILED',
        cause: err
      });
    } finally {
      await this.#removeFile(upload.path);
    }

    if (!pdfBuffer || !pdfBuffer.length) {
      throw new PadesFlowError('Uploaded PDF is empty', { statusCode: 400, code: 'UPLOAD_EMPTY' });
    }

    return pdfBuffer;
  }

  #assertPdf(buffer) {
    const header = buffer.slice(0, 5).toString('ascii');
    if (!header.startsWith('%PDF')) {
      throw new PadesFlowError('Uploaded file is not a valid PDF', { statusCode: 400, code: 'INVALID_PDF' });
    }
  }

  async #persistSignedArtifact(downloadRoot, pdfBuffer, context) {
    let artifact;
    try {
      artifact = this.generateArtifactInfo(downloadRoot, context);
      await fsp.mkdir(artifact.directory, { recursive: true });
      await fsp.writeFile(artifact.absolutePath, pdfBuffer);
      return artifact;
    } catch (err) {
      if (artifact?.absolutePath) {
        await this.#removeFile(artifact.absolutePath);
      }
      throw new PadesFlowError('Unable to persist signed PDF', { statusCode: 500, code: 'PERSISTENCE_FAILED', cause: err });
    }
  }

  #createDownloadToken(downloadService, artifact, downloadPath = '/download') {
    const downloadCfg = this.getDownloadOptions();
    const relative = this.#relativeToDownloadRoot(downloadService.rootDir, artifact.absolutePath);
    const expiresIn = downloadCfg.expiresIn || downloadService.ttlSeconds || 15 * 60;
    let token;
    try {
      token = downloadService.createToken({
        relativePath: relative,
        expiresIn,
        filename: artifact.filename,
        contentType: 'application/pdf',
        disposition: downloadCfg.disposition
      });
    } catch (err) {
      throw new PadesFlowError('Unable to create download token', {
        statusCode: 500,
        code: 'DOWNLOAD_TOKEN_FAILED',
        cause: err
      });
    }

    const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    const downloadUrl = `${downloadPath}?token=${encodeURIComponent(token)}`;

    return { token, downloadUrl, expiresAt };
  }

  #relativeToDownloadRoot(rootDir, target) {
    const base = path.resolve(rootDir);
    const resolved = path.resolve(target);
    const relative = path.relative(base, resolved);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new PadesFlowError('Signed PDF path escaped download root', {
        statusCode: 500,
        code: 'INVALID_DOWNLOAD_PATH'
      });
    }
    return relative.split(path.sep).join('/');
  }

  async #removeFile(filePath) {
    if (!filePath) return;
    try {
      await fsp.unlink(filePath);
    } catch (err) {
      if (err?.code !== 'ENOENT') {
        console.warn('Failed to remove file', err);
      }
    }
  }
}

module.exports = { PadesService, PadesFlowError };
