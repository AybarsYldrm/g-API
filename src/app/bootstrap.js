'use strict';

const fs = require('fs');
const path = require('path');

const HttpService = require('../services/HttpService');
const { AuthService } = require('../services/AuthService');
const { NoSQL } = require('../db/noSQL');
const { parse, execute } = require('../graphql');
const createSchema = require('../graphql/schema');
const registerRestRoutes = require('../routes/rest');
const registerPkiRoutes = require('../routes/pki');
const registerPadesRoutes = require('../routes/pades');
const { SnowflakeIdFactory } = require('../utils/snowflake');
const { DownloadTokenService } = require('../services/download/DownloadTokenService');
const { SMTPService } = require('../services/email/SMTPService');
const { EmailNotificationService } = require('../services/email/EmailNotificationService');
const { CertificateAuthorityService } = require('../services/pki/CertificateAuthorityService');
const { WebPushService } = require('../services/webpush/WebPushService');
const { PERMISSIONS } = require('../utils/permissions');
const { PadesService } = require('../services/pades/PadesService');

async function createAppContext(config, options = {}) {
  const resolvedConfig = config || require('../../config');
  const {
    logger = console,
    skipEmail = false,
    skipPki = false,
    skipPades = false,
    skipWebPush = false,
    publicDir = path.join(__dirname, '../../public'),
  } = options;

  const dataDir = path.join(__dirname, '../../data');

  const idFactory = new SnowflakeIdFactory({ epoch: resolvedConfig.security.operationEpoch });
  const db = new NoSQL(undefined, { idFactory });
  await db.init();

  let smtpService = null;
  let notificationService = null;
  if (!skipEmail && resolvedConfig.email && resolvedConfig.email.username && resolvedConfig.email.password) {
    smtpService = new SMTPService({
      host: resolvedConfig.email.host,
      port: resolvedConfig.email.port,
      username: resolvedConfig.email.username,
      password: resolvedConfig.email.password,
      secure: resolvedConfig.email.secure,
      rejectUnauthorized: resolvedConfig.email.rejectUnauthorized,
      defaultFrom: resolvedConfig.email.defaultFrom,
      timeoutMs: resolvedConfig.email.timeoutMs,
    });

    notificationService = new EmailNotificationService({
      smtpService,
      defaultFrom: resolvedConfig.email.defaultFrom,
      appBaseUrl: resolvedConfig.email.appBaseUrl,
    });
  }

  let pkiService = null;
  if (!skipPki && resolvedConfig.pki && resolvedConfig.pki.enabled !== false) {
    const pkiDir = resolvedConfig.pki.baseDir
      ? path.resolve(resolvedConfig.pki.baseDir)
      : path.join(dataDir, 'pki');
    pkiService = new CertificateAuthorityService({
      baseDir: pkiDir,
      db,
      config: resolvedConfig.pki,
    });
    await pkiService.init();
  }

  let webPushService = null;
  if (!skipWebPush && resolvedConfig.webpush && resolvedConfig.webpush.enabled !== false) {
    const pushDir = resolvedConfig.webpush.dataDir
      ? path.resolve(resolvedConfig.webpush.dataDir)
      : path.join(dataDir, 'webpush');
    webPushService = new WebPushService({
      dataDir: pushDir,
      rateLimitWindowMs: resolvedConfig.webpush.rateLimitWindowMs,
      rateLimitMax: resolvedConfig.webpush.rateLimitMax,
      defaultTtl: resolvedConfig.webpush.defaultTtl,
      subject: resolvedConfig.webpush.subject,
    });
    await webPushService.init();
  }

  const authService = new AuthService({ db, config: resolvedConfig, notificationService, pkiService });

  const downloadService = new DownloadTokenService({
    rootDir: publicDir,
    secret: resolvedConfig.security.downloadTokens.secret,
    ttlSeconds: resolvedConfig.security.downloadTokens.ttlSeconds,
    idFactory,
  });

  const schema = createSchema({ db });

  const padesService = (!skipPades && resolvedConfig.pades && resolvedConfig.pades.enabled !== false && pkiService)
    ? new PadesService({ pkiService, config: resolvedConfig.pades })
    : null;

  return {
    logger,
    config: resolvedConfig,
    idFactory,
    db,
    smtpService,
    notificationService,
    pkiService,
    webPushService,
    authService,
    downloadService,
    schema,
    padesService,
    publicDir: path.resolve(publicDir),
  };
}

function createHttpService(context, options = {}) {
  if (!context) throw new Error('createHttpService requires an application context');
  const {
    publicDir = context.publicDir,
    maxRequestsPerMinute = 400,
    uploadDefaultLimit = 10 * 1024 * 1024,
    allowedOrigins = context.config.security.allowedOrigins,
    downloadPath = '/download',
    cspDirectives = {
      'connect-src': ["'self'"],
      'font-src': ["'self'", 'https://fonts.gstatic.com'],
      'img-src': ["'self'", 'data:'],
    },
  } = options;

  const resolvedAllowedOrigins = Array.isArray(allowedOrigins) && allowedOrigins.length
    ? allowedOrigins.slice()
    : ['https://fitfak.net', 'http://localhost'];

  return new HttpService(context.authService, {
    publicPath: publicDir,
    maxRequestsPerMinute,
    uploadDefaultLimit,
    allowedOrigins: resolvedAllowedOrigins,
    operationEpoch: context.config.security.operationEpoch,
    downloadService: context.downloadService,
    downloadPath,
    cspDirectives,
  });
}

function registerWebPushRoutes(http, webPushService) {
  const clientIp = (req) => {
    const header = typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'] : '';
    const forwarded = header.split(',')[0].trim();
    return forwarded || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
  };

  http.addRoute('GET', '/push/vapid', async (req, res) => {
    try {
      const key = await webPushService.getPublicKey();
      http.sendJson(res, 200, { success: true, publicKey: key });
    } catch (err) {
      http.sendJson(res, 500, { success: false, message: 'Unable to provide VAPID key' });
    }
  });

  http.addRoute('POST', '/push/subscribe', async (req, res) => {
    try {
      const ip = clientIp(req);
      if (!webPushService.checkRateLimit(ip)) {
        return http.sendJson(res, 429, { success: false, message: 'Rate limit exceeded' });
      }
      const result = await webPushService.subscribe(req.body || {});
      const status = result.created ? 201 : 200;
      http.sendJson(res, status, { success: true, created: result.created });
    } catch (err) {
      http.sendJson(res, 400, { success: false, message: err.message || 'Subscription failed' });
    }
  });

  http.addRoute('POST', '/push/unsubscribe', async (req, res) => {
    try {
      const endpoint = typeof req.body?.endpoint === 'string' ? req.body.endpoint.trim() : '';
      if (!endpoint) {
        return http.sendJson(res, 400, { success: false, message: 'endpoint is required' });
      }
      const removed = await webPushService.unsubscribe(endpoint);
      const status = removed ? 200 : 404;
      http.sendJson(res, status, { success: removed, removed });
    } catch (err) {
      http.sendJson(res, 500, { success: false, message: err.message || 'Unsubscribe failed' });
    }
  });

  http.addRoute('POST', '/push/send', async (req, res) => {
    try {
      const payload = req.body || {};
      if (!payload.title && !payload.body) {
        return http.sendJson(res, 400, { success: false, message: 'title or body is required' });
      }
      const message = {
        title: String(payload.title || 'Bildirim'),
        body: String(payload.body || ''),
      };
      if (payload.icon) message.icon = String(payload.icon);
      if (payload.data && typeof payload.data === 'object') message.data = payload.data;
      let ttl;
      if (payload.ttl !== undefined && payload.ttl !== null && payload.ttl !== '') {
        const parsedTtl = Number(payload.ttl);
        if (Number.isFinite(parsedTtl)) ttl = parsedTtl;
      }
      const subject = typeof payload.subject === 'string' ? payload.subject : undefined;
      const results = await webPushService.sendToAll(message, { ttl, subject });
      http.sendJson(res, 200, { success: true, results });
    } catch (err) {
      http.sendJson(res, 500, { success: false, message: err.message || 'Failed to deliver push notification' });
    }
  }, { auth: true, permissions: PERMISSIONS.MANAGE_ALL_EVENTS });
}

async function registerCoreRoutes(http, context, options = {}) {
  if (!http) throw new Error('registerCoreRoutes requires an HttpService instance');
  if (!context) throw new Error('registerCoreRoutes requires an application context');

  const {
    registerGraphQL = true,
    registerViews = true,
    enableWebPush = context.webPushService && options.enableWebPush !== false,
  } = options;

  registerRestRoutes(http, { db: context.db });
  registerPkiRoutes(http, { pkiService: context.pkiService });

  if (context.padesService) {
    registerPadesRoutes(http, { padesService: context.padesService, downloadService: context.downloadService });
  }

  if (enableWebPush && context.webPushService) {
    registerWebPushRoutes(http, context.webPushService);
  }

  http.addRoute('GET', '/login', (req, res) => {
    const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '/';
    context.authService.beginLogin(res, { returnTo });
  });

  http.addRoute('GET', '/callback', async (req, res) => {
    try {
      const result = await context.authService.handleCallback(req.query, res);
      if (res.headersSent) return;

      const wantsJson = (req.headers.accept || '').includes('application/json');
      if (wantsJson) {
        http.sendJson(res, 200, {
          success: true,
          redirectTo: result.redirectTo,
          tokens: result.tokens,
          profile: {
            externalId: result.profile.externalId,
            email: result.profile.email,
            name: result.profile.name,
            roles: result.profile.roles,
          },
        });
        return;
      }

      http.redirectHtml(res, result.redirectTo || '/');
    } catch (err) {
      context.logger.error?.('Callback error', err);
      if (!res.headersSent) {
        http.sendJson(res, 500, { success: false, message: err.message || 'Authentication failed' });
      }
    }
  });

  http.addRoute('GET', '/logout', async (req, res) => {
    try {
      const url = await context.authService.logout(res);
      if (!res.headersSent) {
        http.redirectHtml(res, url || '/');
      }
    } catch (err) {
      context.logger.error?.('Logout error', err);
      http.sendJson(res, 500, { success: false, message: 'Logout failed' });
    }
  });

  if (registerGraphQL) {
    http.addRoute('POST', '/graph', async (req, res, send) => {
      const body = req.body || {};
      if (!body.query) {
        return send(400, { errors: [{ message: 'query is required' }] });
      }

      let document;
      try {
        document = parse(body.query);
      } catch (err) {
        return send(400, { errors: [{ message: err.message }] });
      }

      let variables = body.variables || {};
      if (typeof variables === 'string') {
        try {
          variables = JSON.parse(variables);
        } catch (err) {
          return send(400, { errors: [{ message: 'variables must be valid JSON' }] });
        }
      }

      try {
        const contextValue = {
          db: context.db,
          req,
          authService: context.authService,
          user: req.user,
        };

        const result = await execute({
          schema: context.schema,
          document,
          variableValues: variables,
          contextValue,
        });

        const statusCode = result.errors && result.errors.length ? 200 : 200;
        return send(statusCode, result);
      } catch (err) {
        context.logger.error?.('GraphQL execution error', err);
        return send(500, { errors: [{ message: 'Internal Server Error' }] });
      }
    }, { auth: true, graph: true });
  }

  if (registerViews) {
    const viewsDir = path.join(context.publicDir, 'views');
    if (fs.existsSync(viewsDir)) {
      const files = fs.readdirSync(viewsDir);
      for (const file of files) {
        if (!file.toLowerCase().endsWith('.html')) continue;
        const absolute = path.join(viewsDir, file);

        if (file.toLowerCase() === 'index.html') {
          http.addRoute('GET', '/', (req, res) => {
            http.renderHtmlFile(res, 200, absolute);
          });
          http.addRoute('GET', '/index', (req, res) => {
            http.renderHtmlFile(res, 200, absolute);
          });
          continue;
        }

        const routeName = `/${file.replace(/\.html$/i, '')}`;
        http.addRoute('GET', routeName, (req, res) => {
          http.renderHtmlFile(res, 200, absolute);
        });
      }
    }
  }

  return http;
}

async function shutdownAppContext(context) {
  if (!context) return;
  const operations = [];

  if (context.webPushService && typeof context.webPushService.shutdown === 'function') {
    operations.push(context.webPushService.shutdown());
  }

  if (context.smtpService && typeof context.smtpService.close === 'function') {
    try {
      operations.push(context.smtpService.close());
    } catch (err) {
      context.logger.warn?.('Failed to close SMTP service cleanly', err);
    }
  }

  if (operations.length) {
    try {
      await Promise.allSettled(operations);
    } catch (err) {
      context.logger.warn?.('Error during shutdown', err);
    }
  }
}

module.exports = {
  createAppContext,
  createHttpService,
  registerCoreRoutes,
  shutdownAppContext,
};
