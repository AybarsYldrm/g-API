'use strict';

const path = require('path');
const fs = require('fs');

const HttpService = require('./src/services/HttpService');
const { AuthService } = require('./src/services/AuthService');
const { NoSQL } = require('./src/db/noSQL');
const { parse, execute } = require('./src/graphql');
const createSchema = require('./src/graphql/schema');
const registerRestRoutes = require('./src/routes/rest');
const { SnowflakeIdFactory } = require('./src/utils/snowflake');
const { DownloadTokenService } = require('./src/services/download/DownloadTokenService');
const { SMTPService } = require('./src/services/email/SMTPService');
const { EmailNotificationService } = require('./src/services/email/EmailNotificationService');
const { CertificateAuthorityService } = require('./src/services/pki/CertificateAuthorityService');
const registerPkiRoutes = require('./src/routes/pki');
const { WebPushService } = require('./src/services/webpush/WebPushService');
const { PERMISSIONS } = require('./src/utils/permissions');
const config = require('./config');

(async () => {
  const idFactory = new SnowflakeIdFactory({ epoch: config.security.operationEpoch });
  const db = new NoSQL(undefined, { idFactory });
  await db.init();

  let smtpService = null;
  if (config.email && config.email.username && config.email.password) {
    smtpService = new SMTPService({
      host: config.email.host,
      port: config.email.port,
      username: config.email.username,
      password: config.email.password,
      secure: config.email.secure,
      rejectUnauthorized: config.email.rejectUnauthorized,
      defaultFrom: config.email.defaultFrom,
      timeoutMs: config.email.timeoutMs,
    });
  }

  const notificationService = smtpService
    ? new EmailNotificationService({
        smtpService,
        defaultFrom: config.email.defaultFrom,
        appBaseUrl: config.email.appBaseUrl,
      })
    : null;

  let pkiService = null;
  if (config.pki && config.pki.enabled !== false) {
    const pkiDir = config.pki.baseDir ? path.resolve(config.pki.baseDir) : path.join(__dirname, 'data', 'pki');
    pkiService = new CertificateAuthorityService({
      baseDir: pkiDir,
      db,
      config: config.pki,
    });
    await pkiService.init();
  }

  let webPushService = null;
  if (config.webpush && config.webpush.enabled !== false) {
    const pushDir = config.webpush.dataDir || path.join(__dirname, 'data', 'webpush');
    webPushService = new WebPushService({
      dataDir: pushDir,
      rateLimitWindowMs: config.webpush.rateLimitWindowMs,
      rateLimitMax: config.webpush.rateLimitMax,
      defaultTtl: config.webpush.defaultTtl,
      subject: config.webpush.subject
    });
    await webPushService.init();
  }

  const authService = new AuthService({ db, config, notificationService, pkiService });

  const downloadService = new DownloadTokenService({
    rootDir: path.join(__dirname, 'public'),
    secret: config.security.downloadTokens.secret,
    ttlSeconds: config.security.downloadTokens.ttlSeconds,
    idFactory,
  });

  const http = new HttpService(authService, {
    publicPath: path.join(__dirname, 'public'),
    maxRequestsPerMinute: 400,
    uploadDefaultLimit: 10 * 1024 * 1024,
    allowedOrigins: ['https://fitfak.net', 'http://localhost'],
    operationEpoch: config.security.operationEpoch,
    downloadService,
    downloadPath: '/download',
    cspDirectives: {
      'connect-src': ["'self'"],
      'font-src': ["'self'", 'https://fonts.gstatic.com'],
      'img-src': ["'self'", 'data:']
    }
  });

  const schema = createSchema({ db });

  registerRestRoutes(http, { db });
  registerPkiRoutes(http, { pkiService });

  if (webPushService) {
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

  // Microsoft identity routes
  http.addRoute('GET', '/login', (req, res) => {
    const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '/';
    authService.beginLogin(res, { returnTo });
  });

  http.addRoute('GET', '/callback', async (req, res) => {
    try {
      const result = await authService.handleCallback(req.query, res);
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
      console.error('Callback error', err);
      if (!res.headersSent) {
        http.sendJson(res, 500, { success: false, message: err.message || 'Authentication failed' });
      }
    }
  });

  http.addRoute('GET', '/logout', async (req, res) => {
    try {
      const url = await authService.logout(res);
      if (!res.headersSent) {
        http.redirectHtml(res, url || '/');
      }
    } catch (err) {
      console.error('Logout error', err);
      http.sendJson(res, 500, { success: false, message: 'Logout failed' });
    }
  });

  // GraphQL endpoint respecting GraphQL HTTP spec
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
        db,
        req,
        authService,
        user: req.user,
      };

      const result = await execute({
        schema,
        document,
        variableValues: variables,
        contextValue
      });

      const statusCode = result.errors && result.errors.length ? 200 : 200;
      return send(statusCode, result);
    } catch (err) {
      console.error('GraphQL execution error', err);
      return send(500, { errors: [{ message: 'Internal Server Error' }] });
    }
  }, { auth: true, graph: true });

  // Auto-register HTML views from public/views
  const viewsDir = path.join(__dirname, 'public', 'views');
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

  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 80;
  http.listen(port, () => console.log(`Server listening on ${port}`));
})();
