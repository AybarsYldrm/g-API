'use strict';

const fsp = require('fs').promises;
const path = require('path');

function parseBoolean(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  return undefined;
}

function parsePositiveInt(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const num = Number(value);
  if (!Number.isFinite(num)) return undefined;
  const intVal = Math.trunc(num);
  return intVal > 0 ? intVal : undefined;
}

function toPosixRelative(base, target) {
  const relative = path.relative(base, target);
  return relative.split(path.sep).join('/');
}

async function removeIfExists(filePath) {
  if (!filePath) return;
  try {
    await fsp.unlink(filePath);
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      console.warn('Failed to remove temporary file', err);
    }
  }
}

module.exports = function registerPadesRoutes(http, { padesService, downloadService } = {}) {
  if (!http || !padesService) return;

  const uploadCfg = padesService.getUploadOptions();
  const downloadCfg = padesService.getDownloadOptions();

  http.addRoute('POST', '/api/pades/sign', async (req, res, send) => {
    if (!downloadService || typeof http.createDownloadToken !== 'function') {
      return send(503, { success: false, message: 'Download service unavailable' });
    }

    const files = Array.isArray(req.body?.files) ? req.body.files : [];
    if (!files.length) {
      return send(400, { success: false, message: 'PDF file is required' });
    }

    const file = files[0];
    let pdfBuffer;
    try {
      pdfBuffer = await fsp.readFile(file.path);
    } catch (err) {
      await removeIfExists(file.path);
      return send(500, { success: false, message: 'Uploaded file could not be read' });
    }

    try {
      await removeIfExists(file.path);
    } catch (err) {
      // logged inside helper
    }

    if (!pdfBuffer || !pdfBuffer.length) {
      return send(400, { success: false, message: 'Uploaded PDF is empty' });
    }

    const query = req.query || {};
    const signOptions = {};

    if (query.fieldName !== undefined) signOptions.fieldName = query.fieldName;
    const placeholderHexLen = parsePositiveInt(query.placeholderHexLen);
    if (placeholderHexLen) signOptions.placeholderHexLen = placeholderHexLen;

    const docTimestampOverrides = {};
    const appendDocTs = parseBoolean(query.appendDocumentTimestamp);
    if (appendDocTs !== undefined) docTimestampOverrides.append = appendDocTs;
    if (query.documentTimestampField !== undefined) docTimestampOverrides.fieldName = query.documentTimestampField;
    const docTsPlaceholder = parsePositiveInt(query.documentTimestampPlaceholderHexLen);
    if (docTsPlaceholder) docTimestampOverrides.placeholderHexLen = docTsPlaceholder;
    if (Object.keys(docTimestampOverrides).length) {
      signOptions.documentTimestamp = docTimestampOverrides;
    }

    const forceRenew = parseBoolean(query.forceRenewCertificate);
    if (forceRenew !== undefined) {
      signOptions.forceRenew = forceRenew;
    }

    let signed;
    try {
      signed = await padesService.signForUser(req.user, pdfBuffer, signOptions);
    } catch (err) {
      const status = err && err.code === 'KEY_MISSING' ? 409 : 500;
      const message = err && err.message ? err.message : 'Unable to sign PDF';
      return send(status, { success: false, message });
    }

    const { directory, filename, absolutePath } = padesService.generateArtifactInfo(downloadService.rootDir, {
      originalName: file.originalName || file.filename,
      user: signed.user || req.user,
      mode: signed.mode
    });

    try {
      await fsp.mkdir(directory, { recursive: true });
      await fsp.writeFile(absolutePath, signed.pdf);
    } catch (err) {
      return send(500, { success: false, message: 'Unable to persist signed PDF' });
    }

    const expiresIn = downloadCfg.expiresIn;
    let token;
    try {
      const relative = toPosixRelative(downloadService.rootDir, absolutePath);
      token = http.createDownloadToken(relative, {
        expiresIn,
        filename,
        contentType: 'application/pdf',
        disposition: downloadCfg.disposition
      });
    } catch (err) {
      await removeIfExists(absolutePath);
      return send(500, { success: false, message: 'Unable to create download token' });
    }

    const expiresAt = new Date(Date.now() + (expiresIn || downloadService.ttlSeconds || 0) * 1000).toISOString();
    const downloadUrl = `${http.downloadPath}?token=${encodeURIComponent(token)}`;

    return send(200, {
      success: true,
      mode: signed.mode,
      filename,
      token,
      downloadUrl,
      expiresAt,
      documentTimestamp: signed.documentTimestamp,
      fieldName: signed.fieldName,
      placeholderHexLen: signed.placeholderHexLen
    });
  }, {
    auth: true,
    upload: {
      folder: uploadCfg.folder,
      maxBytes: uploadCfg.maxBytes,
      accept: uploadCfg.accept,
      naming: uploadCfg.naming
    }
  });
};
