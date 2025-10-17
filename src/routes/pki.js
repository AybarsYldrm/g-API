'use strict';

const { PERMISSIONS } = require('../utils/permissions');

module.exports = function registerPkiRoutes(http, { pkiService } = {}) {
  if (!http || !pkiService) return;

  http.addRoute('GET', '/healthz', async (req, res) => {
    try {
      const status = await pkiService.health();
      http.sendJson(res, 200, status);
    } catch (err) {
      http.sendJson(res, 500, { ok: false, error: err.message || 'pki health error' });
    }
  });

  http.addRoute('GET', '/crl', async (req, res) => {
    try {
      const format = typeof req.query.format === 'string' && req.query.format.toLowerCase() === 'pem' ? 'pem' : 'der';
      const result = await pkiService.getCrl({ format });
      http.sendBuffer(res, 200, result.body, result.contentType, {
        'Cache-Control': result.cacheControl,
      });
    } catch (err) {
      http.sendJson(res, 500, { ok: false, error: err.message || 'Unable to provide CRL' });
    }
  });

  http.addRoute('GET', '/aia/ca.crt', async (req, res) => {
    try {
      const format = typeof req.query.format === 'string' && req.query.format.toLowerCase() === 'pem' ? 'pem' : 'der';
      const result = await pkiService.getRootCertificate({ format });
      http.sendBuffer(res, 200, result.body, result.contentType, {
        'Cache-Control': result.cacheControl,
        'Content-Disposition': result.disposition,
        ...(result.lastModified ? { 'Last-Modified': result.lastModified } : {}),
      });
    } catch (err) {
      http.sendJson(res, 500, { ok: false, error: err.message || 'Unable to provide CA certificate' });
    }
  });

  http.addRoute('GET', '/ocsp/:encoded', async (req, res) => {
    try {
      const raw = pkiService.decodeOcspPathComponent(req.params.encoded);
      const response = await pkiService.handleOcspRequest(raw);
      http.sendBuffer(res, 200, response.buffer, 'application/ocsp-response', {
        'Cache-Control': response.cacheControl,
      });
    } catch (err) {
      const errorResp = await pkiService.buildOcspError('malformedRequest');
      http.sendBuffer(res, 200, errorResp.buffer, 'application/ocsp-response', {
        'Cache-Control': errorResp.cacheControl,
      });
    }
  });

  http.addRoute('POST', '/ocsp', async (req, res) => {
    try {
      const body = Buffer.isBuffer(req.body) ? req.body : req.rawBodyBuffer;
      const response = await pkiService.handleOcspRequest(body);
      http.sendBuffer(res, 200, response.buffer, 'application/ocsp-response', {
        'Cache-Control': response.cacheControl,
      });
    } catch (err) {
      const errorResp = await pkiService.buildOcspError('malformedRequest');
      http.sendBuffer(res, 200, errorResp.buffer, 'application/ocsp-response', {
        'Cache-Control': errorResp.cacheControl,
      });
    }
  }, { rawBody: true, maxBodyLength: 64 * 1024 });

  http.addRoute('POST', '/pki/revoke', async (req, res) => {
    try {
      const email = typeof req.body?.email === 'string' ? req.body.email : '';
      const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
      if (!email.trim()) {
        return http.sendJson(res, 400, { success: false, message: 'email is required' });
      }

      const revoked = await pkiService.revokeByEmail(email, { reason });
      http.sendJson(res, 200, { success: true, revoked });
    } catch (err) {
      if (err && err.code === 'NOT_FOUND') {
        return http.sendJson(res, 404, { success: false, message: 'No certificate found for email' });
      }
      http.sendJson(res, 500, { success: false, message: err.message || 'Unable to revoke certificate' });
    }
  }, { auth: true, permissions: PERMISSIONS.MANAGE_TENANT });
};
