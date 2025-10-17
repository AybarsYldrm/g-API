
'use strict';

module.exports = function registerPadesRoutes(http, { padesService, downloadService } = {}) {
  if (!http || !padesService) return;

  const uploadCfg = padesService.getUploadOptions();

  http.addRoute('POST', '/api/pades/sign', async (req, res, send) => {
    const files = Array.isArray(req.body?.files) ? req.body.files : [];
    try {
      const result = await padesService.processSigningRequest({
        user: req.user,
        upload: files[0] || null,
        query: req.query || {},
        downloadService,
        downloadPath: http.downloadPath
      });

      return send(200, result);
    } catch (err) {
      const status = err?.statusCode || 500;
      const body = {
        success: false,
        message: err?.message || 'Unable to sign PDF'
      };
      if (err?.code) body.code = err.code;
      if (err?.details) body.details = err.details;
      return send(status, body);
    }
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
