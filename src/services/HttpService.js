'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

const { hasPermission, permissionMaskFrom, normalizePermissionMask } = require('../utils/permissions');
const { OperationIdFactory } = require('../utils/operationId');

class HttpService {
  constructor(authService = null, options = {}) {
    this.authService = authService;

    // routes + rate limiting
    this.routes = [];
    this.globalRateStore = new Map();
    this.maxRequestsPerMinute = options.maxRequestsPerMinute || 120;
    this.globalRateWindowMs = options.globalRateWindowMs || 60_000;
    this.customRateStores = new Map();

    // public / defaults
    this.publicPath = options.publicPath || path.join(process.cwd(), 'public');
    this.uploadDefaultLimit = options.uploadDefaultLimit || 5 * 1024 * 1024;
    this.uploadDefaultMaxKBps = options.uploadDefaultMaxKBps || null;
    const allowedOrigins = options.allowedOrigins || ['*'];
    this.allowedOrigins = Array.isArray(allowedOrigins)
      ? allowedOrigins.slice()
      : [allowedOrigins];

    // basic mime map
    this.mimeMap = Object.assign({
      '.js':'application/javascript; charset=utf-8',
      '.mjs':'application/javascript; charset=utf-8',
      '.css':'text/css; charset=utf-8',
      '.html':'text/html; charset=utf-8',
      '.json':'application/json; charset=utf-8',
      '.xml':'application/xml; charset=utf-8',
      '.txt':'text/plain; charset=utf-8',
      '.csv':'text/csv; charset=utf-8',
      '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif',
      '.ico':'image/x-icon', '.svg':'image/svg+xml', '.webp':'image/webp'
    }, options.extraMime || {});

    // security headers default
    this.securityHeaders = Object.assign({
      'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':'DENY',
      'Strict-Transport-Security':'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'geolocation=(), microphone=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'X-DNS-Prefetch-Control': 'off'
    }, options.securityHeaders || {});

    const defaultCsp = Object.assign({
      'default-src': ["'self'"],
      'base-uri': ["'self'"],
      'frame-ancestors': ["'none'"],
      'object-src': ["'none'"],
      'img-src': ["'self'", 'data:'],
      'script-src': ["'self'"],
      'style-src': ["'self'"]
    }, options.cspDirectives || {});

    this.cspDirectives = {};
    for (const [directive, value] of Object.entries(defaultCsp)) {
      this.cspDirectives[directive] = Array.isArray(value)
        ? value.slice()
        : String(value).split(/\s+/).filter(Boolean);
    }

    this.cspUseStrictDynamic = options.cspUseStrictDynamic === true;

    const operationEpoch = options.operationEpoch || (authService?.security?.operationEpoch ?? Date.UTC(2023, 0, 1));
    this.operationIdFactory = new OperationIdFactory({ epoch: operationEpoch });

    this.downloadService = options.downloadService || null;
    this.downloadPath = options.downloadPath || '/download';
  }

  registerDownloadService(service, options = {}) {
    this.downloadService = service || null;
    if (options.downloadPath) this.downloadPath = options.downloadPath;
    return this;
  }

  createDownloadToken(relativePath, options = {}) {
    if (!this.downloadService || typeof this.downloadService.createToken !== 'function') {
      throw new Error('DownloadTokenService is not configured');
    }
    if (!relativePath) throw new Error('relativePath is required');
    return this.downloadService.createToken(Object.assign({ relativePath }, options));
  }

  // ---------- internals ----------
  _getIp(req) {
    const xf = req.headers['x-forwarded-for'];
    return xf ? xf.split(',')[0].trim() : req.socket.remoteAddress;
  }

  _resolveCorsOrigin(req) {
    if (!this.allowedOrigins || !this.allowedOrigins.length) return null;
    if (this.allowedOrigins.includes('*')) return '*';

    const origin = req.headers?.origin;
    if (!origin) return null;

    for (const allowed of this.allowedOrigins) {
      if (allowed instanceof RegExp && allowed.test(origin)) return origin;
      if (typeof allowed === 'string' && allowed === origin) return origin;
    }

    return null;
  }

  _composeHeaders(res, base = {}, extra = {}) {
    const headers = Object.assign({}, this.securityHeaders, base, extra);
    let origin = res.__corsOrigin;
    if (origin === undefined) {
      origin = this.allowedOrigins.includes('*') ? '*' : null;
      res.__corsOrigin = origin;
    }

    if (origin) {
      headers['Access-Control-Allow-Origin'] = origin;
      if (origin !== '*') {
        headers['Access-Control-Allow-Credentials'] = headers['Access-Control-Allow-Credentials'] || 'true';
        headers['Vary'] = headers['Vary'] ? `${headers['Vary']}, Origin` : 'Origin';
      }
    }

    return headers;
  }

  _safeJoin(root, target) {
    const base = path.resolve(root);
    const resolved = path.resolve(base, target);
    const relative = path.relative(base, resolved);
    if (!relative || relative === '') return resolved;
    if (relative.startsWith('..') || path.isAbsolute(relative)) return null;
    return resolved;
  }

  _randomFilename(orig) {
    const ext = path.extname(orig) || '';
    return `${crypto.randomBytes(16).toString('hex')}${ext}`;
  }

  _sanitizeString(str) {
    if (typeof str !== 'string') return str;
    // remove <script> blocks, remove inline event handlers, escape tags
    let s = str.replace(/<\s*script[\s\S]*?>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
    s = s.replace(/ on\w+\s*=\s*(?:"[^"]*"|'[^']*')/gi, '');
    s = s.replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return s;
  }

  _sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(v => typeof v === 'string' ? this._sanitizeString(v) : this._sanitizeObject(v));
    const out = {};
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      out[k] = typeof v === 'string' ? this._sanitizeString(v) : this._sanitizeObject(v);
    }
    return out;
  }

  _buildCspHeader(nonce = null, overrides = {}) {
    const directives = {};
    for (const [directive, values] of Object.entries(this.cspDirectives)) {
      directives[directive] = values.slice();
    }

    if (overrides && typeof overrides === 'object') {
      for (const [directive, value] of Object.entries(overrides)) {
        if (value === null) {
          delete directives[directive];
          continue;
        }
        const arr = Array.isArray(value)
          ? value.slice()
          : String(value).split(/\s+/).filter(Boolean);
        directives[directive] = arr;
      }
    }

    if (nonce) {
      const scriptSources = new Set([`'nonce-${nonce}'`]);
      if (this.cspUseStrictDynamic) scriptSources.add("'strict-dynamic'");
      (directives['script-src'] || []).forEach(v => scriptSources.add(v));
      directives['script-src'] = Array.from(scriptSources);

      const styleSources = new Set([`'nonce-${nonce}'`]);
      (directives['style-src'] || []).forEach(v => styleSources.add(v));
      directives['style-src'] = Array.from(styleSources);
    }

    return Object.entries(directives)
      .map(([directive, values]) => `${directive} ${values.join(' ')}`.trim())
      .join('; ');
  }

  // ---------- send helpers ----------
  sendJson(res, statusCode, payload, extraHeaders = {}) {
    if (res.headersSent) return;
    const safe = (payload && typeof payload === 'object') ? this._sanitizeObject(payload) : payload;
    const normalized = safe === undefined ? null : safe;
    const body = JSON.stringify(normalized);
    const headers = this._composeHeaders(res, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Csrf-Token',
      'Content-Length': Buffer.byteLength(body)
    }, extraHeaders);
    res.writeHead(statusCode, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  sendGraph(res, statusCode, raw, extraHeaders = {}) {
    if (res.headersSent) return;
    const payload = this._withGraphExtensions(raw, res.operationId);
    const body = JSON.stringify(payload);
    const headers = this._composeHeaders(res, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body)
    }, extraHeaders);
    res.writeHead(statusCode, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  /**
   * sendHtml - CSP-aware HTML sender
   * nonce: base64 string (optional) - used in script/style tags
   */
  sendHtml(res, statusCode, html, nonce = null, extraHeaders = {}, cspOverrides = {}) {
    if (res.headersSent) return;

    const csp = this._buildCspHeader(nonce, cspOverrides);
    const body = html || '';
    const headers = this._composeHeaders(res, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': csp,
      'Content-Length': Buffer.byteLength(body)
    }, extraHeaders);

    res.writeHead(statusCode, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  sendBuffer(res, statusCode, payload, contentType = 'application/octet-stream', extraHeaders = {}) {
    if (res.headersSent) return;
    const body = Buffer.isBuffer(payload)
      ? payload
      : Buffer.from(payload || '');
    const baseHeaders = Object.assign({
      'Content-Type': contentType
    }, extraHeaders || {});
    if (!('Content-Length' in baseHeaders)) {
      baseHeaders['Content-Length'] = body.length;
    }
    const headers = this._composeHeaders(res, baseHeaders);
    res.writeHead(statusCode, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  renderHtmlFile(res, statusCode, filePath, options = {}) {
    const nonce = crypto.randomBytes(16).toString('base64');
    let html = fs.readFileSync(filePath, 'utf8');
    html = this._hoistInlineStylesAndStripEvents(html, nonce);
    html = this._addNonceToScriptAndStyleTags(html, nonce);
    this.sendHtml(res, statusCode, html, nonce, options.headers || {}, options.csp || {});
  }

  redirectHtml(res, location, status = 302) {
    if (res.headersSent) return;
    const body = `<html><body>Redirecting to <a href="${location}">${location}</a></body></html>`;
    const headers = this._composeHeaders(res, {
      Location: location,
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Length': Buffer.byteLength(body)
    });
    res.writeHead(status, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  // ---------- routing ----------
  addRoute(method, pathPattern, handler, options = {}) {
    const route = { method: method.toUpperCase(), path: pathPattern, handler, options };
    this.routes.push(route);
    if (options.rateLimit) {
      const key = `${route.method}:${route.path}`;
      if (!this.customRateStores.has(key)) this.customRateStores.set(key, new Map());
    }
  }

  findRoute(method, pathname) {
    method = method.toUpperCase();
    for (const r of this.routes) {
      if (r.method !== method) continue;
      if (r.path === pathname) return r;
      if (r.path.includes('/:') && this._matchDynamicRoute(r.path, pathname)) return r;
    }
    return null;
  }

  allowedMethods(pathname) {
    const methods = new Set();
    for (const r of this.routes) {
      if (r.path === pathname || (r.path.includes('/:') && this._matchDynamicRoute(r.path, pathname))) {
        methods.add(r.method);
      }
    }
    return methods;
  }

  _matchDynamicRoute(routePath, actualPath) {
    const rp = routePath.split('/');
    const ap = actualPath.split('/');
    if (rp.length !== ap.length) return false;
    for (let i=0;i<rp.length;i++){
      if (rp[i].startsWith(':')) continue;
      if (rp[i] !== ap[i]) return false;
    }
    return true;
  }

  extractParams(routePath, actualPath) {
    const params = {};
    const rp = routePath.split('/');
    const ap = actualPath.split('/');
    if (rp.length !== ap.length) return params;
    for (let i=0;i<rp.length;i++) {
      if (rp[i].startsWith(':')) params[rp[i].slice(1)] = decodeURIComponent(ap[i]);
    }
    return params;
  }

  // ---------- rate checks ----------
  _globalRateCheck(ip) {
    const now = Date.now();
    const entry = this.globalRateStore.get(ip) || { count: 0, ts: now };
    if (now - entry.ts > this.globalRateWindowMs) {
      this.globalRateStore.set(ip, { count: 1, ts: now });
      return false;
    }
    if (entry.count >= this.maxRequestsPerMinute) return true;
    entry.count++;
    this.globalRateStore.set(ip, entry);
    return false;
  }

  _customRateCheck(route, ip) {
    const cfg = route.options && route.options.rateLimit;
    if (!cfg) return false;
    const key = `${route.method}:${route.path}`;
    if (!this.customRateStores.has(key)) this.customRateStores.set(key, new Map());
    const store = this.customRateStores.get(key);
    const now = Date.now();
    const entry = store.get(ip) || { count: 0, ts: now };
    const windowMs = cfg.windowMs || 60_000;
    if (now - entry.ts > windowMs) { store.set(ip, { count: 1, ts: now }); return false; }
    if (entry.count >= (cfg.max || 10)) return true;
    entry.count++;
    store.set(ip, entry);
    return false;
  }

  // ---------- multipart streaming parser ----------
  _handleMultipartStream(req, res, routeOptions, cb) {
    const contentType = req.headers['content-type'] || '';
    const m = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!m) { res.writeHead(400); res.end('Missing boundary'); return; }
    const boundary = Buffer.from(`--${(m[1]||m[2]).trim()}`);

    const decoder = new StringDecoder('utf8');
    let buffer = Buffer.alloc(0);
    const fields = {};
    const files = [];

    const maxBytes = routeOptions?.upload?.maxBytes || this.uploadDefaultLimit;
    const maxKBps = routeOptions?.upload?.maxKBps || this.uploadDefaultMaxKBps || null;
    const accept = routeOptions?.upload?.accept || [];

    let folder = this.publicPath;
    if (routeOptions?.upload?.folder) folder = path.join(this.publicPath, routeOptions.upload.folder);
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });

    let totalBytes = 0, lastTick = Date.now(), bytesSinceLast = 0;
    let state = { headers:null, name:null, origFilename:null, filename:null, contentType:null, stream:null, tempPath:null };

    const pushCurrentFile = () => {
      if (state.filename) {
        files.push({
          fieldname: state.name,
          filename: state.filename,
          originalName: state.origFilename || null,
          path: state.tempPath,
          contentType: state.contentType || null
        });
      }
    };

    const endCurrentPart = () => {
      if (state.stream) {
        state.stream.end();
        pushCurrentFile();
      }
      state = { headers:null, name:null, origFilename:null, filename:null, contentType:null, stream:null, tempPath:null };
    };

    req.on('data', chunk => {
      totalBytes += chunk.length;
      bytesSinceLast += chunk.length;
      if (totalBytes > maxBytes) { this.sendJson(res, 413, { success: false, message: "Payload too large" }); req.destroy(); return; }

      const now = Date.now();
      if (now - lastTick >= 1000) {
        const kbps = (bytesSinceLast / 1024) / ((now - lastTick)/1000);
        if (maxKBps && kbps > maxKBps) { this.sendJson(res, 429, { success: false, message: "Upload rate limit exceeded" }); req.destroy(); return; }
        lastTick = now; bytesSinceLast = 0;
      }

      buffer = Buffer.concat([buffer, chunk]);

      while (true) {
        const idx = buffer.indexOf(boundary);
        if (idx === -1) break;

        const before = buffer.slice(0, idx);
        if (before.length && state.stream) {
          let toWrite = before;
          if (toWrite.length >= 2 && toWrite.slice(-2).toString()==='\r\n') toWrite = toWrite.slice(0,-2);
          state.stream.write(toWrite);
        }

        buffer = buffer.slice(idx + boundary.length);
        if (buffer.slice(0,2).toString() === '--') { endCurrentPart(); try{ cb({fields,files}); }catch(e){console.error(e);} return; }
        if (buffer.slice(0,2).toString() === '\r\n') buffer = buffer.slice(2);

        const headerEndIdx = buffer.indexOf('\r\n\r\n');
        if (headerEndIdx === -1) break;

        const headerPart = buffer.slice(0, headerEndIdx).toString('utf8');
        buffer = buffer.slice(headerEndIdx + 4);

        const headerLines = headerPart.split('\r\n').map(l=>l.trim()).filter(Boolean);
        const parsedHeaders = {};
        headerLines.forEach(l=>{ const i=l.indexOf(':'); if(i===-1) return; parsedHeaders[l.slice(0,i).toLowerCase()]=l.slice(i+1).trim(); });
        state.headers = parsedHeaders;

        const cd = parsedHeaders['content-disposition'] || '';
        state.name = cd.match(/name="([^"]+)"/i)?.[1] || null;
        const orig = cd.match(/filename="([^"]+)"/i)?.[1] || null;
        state.origFilename = orig ? path.basename(orig) : null;
        state.contentType = parsedHeaders['content-type'] || null;

        if (state.origFilename) {
          if (accept.length && !accept.includes(state.contentType)) { this.sendJson(res,415,{success:false,message:'Unsupported Media Type'}); req.destroy(); return; }

          let finalName = state.origFilename;
          if (routeOptions?.upload?.naming && typeof routeOptions.upload.naming === 'function') {
            try { finalName = routeOptions.upload.naming(state.origFilename, req); } catch(e) { finalName = this._randomFilename(state.origFilename); }
          } else {
            finalName = this._randomFilename(state.origFilename);
          }

          const tempPath = path.join(folder, finalName);

          if (fs.existsSync(tempPath)) {
            this.sendJson(res, 409, {
              success: false,
              message: 'File with the same name already exists',
              filename: finalName
            });
            req.destroy();
            return;
          }

          state.tempPath = tempPath;
          state.filename = finalName;
          state.stream = fs.createWriteStream(tempPath);
        }
      }
    });

    req.on('end', () => {
      // finalize: if still open, close and push
      if (state.stream) {
        try { state.stream.end(); } catch(e) {}
        pushCurrentFile();
      }
      try { cb({ fields, files }); } catch(e) { console.error(e); }
    });

    req.on('error', e => {
      console.error('upload stream error', e);
      try { res.writeHead(500); res.end('Upload error'); } catch(e) {}
    });
  }

  // wrapper: choose multipart parser or raw buffered upload
  _handleUpload(req, res, routeOptions, cb) {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart/form-data')) return this._handleMultipartStream(req, res, routeOptions, cb);

    // raw body upload (small)
    const maxBytes = (routeOptions && routeOptions.upload && routeOptions.upload.maxBytes) || this.uploadDefaultLimit;
    const maxKBps = (routeOptions && routeOptions.upload && routeOptions.upload.maxKBps) || this.uploadDefaultMaxKBps || null;
    let total = 0; let lastTick = Date.now(); let bytesSince = 0;
    const chunks = [];
    req.on('data', chunk => {
      total += chunk.length; bytesSince += chunk.length; chunks.push(chunk);
      if (total > maxBytes) { res.writeHead(413); res.end('Payload too large'); req.destroy(); return; }
      const now = Date.now();
      if (now - lastTick >= 1000) {
        const kbps = (bytesSince / 1024) / ((now - lastTick)/1000);
        if (maxKBps && kbps > maxKBps) { res.writeHead(429); res.end('Upload rate limit exceeded'); req.destroy(); return; }
        lastTick = now; bytesSince = 0;
      }
    });
    req.on('end', () => cb({ buffer: Buffer.concat(chunks), contentType }));
    req.on('error', e => { console.error('upload error', e); try { res.writeHead(500); res.end('Upload error'); } catch(e) {} });
  }

  // ---------- asset serving ----------
  _serveAsset(req, res, relPath) {
    const fp = this._safeJoin(this.publicPath, relPath);
    if (!fp) {
      return this._sendAssetError(res, 403, 'Forbidden');
    }

    let stat;
    try {
      stat = fs.statSync(fp);
    } catch (err) {
      const notFound = err && err.code === 'ENOENT';
      return this._sendAssetError(res, notFound ? 404 : 500, notFound ? 'Not Found' : 'Asset error');
    }

    if (!stat.isFile()) {
      return this._sendAssetError(res, 404, 'Not Found');
    }

    const mime = this.mimeMap[path.extname(fp).toLowerCase()] || 'application/octet-stream';
    const modifiedHex = Math.max(0, Math.trunc(stat.mtimeMs)).toString(16);
    const etag = `"${stat.size.toString(16)}-${modifiedHex}"`;
    const lastModified = stat.mtime.toUTCString();

    if (this._isFresh(req, etag, stat.mtimeMs)) {
      const headers = this._composeHeaders(res, {
        'ETag': etag,
        'Cache-Control': 'public, max-age=604800, immutable',
        'Last-Modified': lastModified
      });
      res.writeHead(304, headers);
      return res.end();
    }

    return this._streamFile(res, fp, {
      stat,
      mime,
      cacheControl: 'public, max-age=604800, immutable',
      etag,
      lastModified,
      rangeHeader: req.headers.range,
      headOnly: Boolean(res.__headRequest)
    });
  }

  _handleDownload(req, res) {
    if (!this.downloadService) {
      this._assignOperationId(req, res, 0);
      return this.sendJson(res, 404, { success: false, message: 'Download service unavailable' });
    }

    const method = req.method;
    if (method !== 'GET' && method !== 'HEAD') {
      this._assignOperationId(req, res, 0);
      const headers = this._composeHeaders(res, {
        Allow: 'GET, HEAD',
        'Content-Type': 'text/plain; charset=utf-8'
      });
      res.writeHead(405, headers);
      if (res.__headRequest) return res.end();
      return res.end('Method Not Allowed');
    }

    const token = typeof req.query.token === 'string' ? req.query.token : null;
    if (!token) {
      this._assignOperationId(req, res, 0);
      return this.sendJson(res, 400, { success: false, message: 'token query parameter is required' });
    }

    let details;
    try {
      details = this.downloadService.resolve(token);
    } catch (err) {
      console.error('download resolve error', err);
      this._assignOperationId(req, res, 0);
      return this.sendJson(res, 401, { success: false, message: 'Invalid or expired download token' });
    }

    this._assignOperationId(req, res, details.operationCode || 0);

    const extension = path.extname(details.absolutePath || '').toLowerCase();
    const mime = details.contentType
      || this.mimeMap[extension]
      || 'application/octet-stream';

    const safeFilename = (details.filename || path.basename(details.absolutePath))
      .replace(/[\r\n]/g, '')
      .replace(/[\x00-\x1F\x7F]/g, '_');
    const encodedFilename = encodeURIComponent(details.filename || safeFilename);
    const dispositionType = (details.disposition || 'attachment').toLowerCase();
    const contentDisposition = `${dispositionType}; filename="${safeFilename}"; filename*=UTF-8''${encodedFilename}`;

    let revoked = false;
    const revoke = () => {
      if (revoked) return;
      revoked = true;
      try {
        if (typeof this.downloadService.revoke === 'function') {
          this.downloadService.revoke(details.id);
        }
      } catch (err) {
        console.warn('download token revoke failed', err);
      }
    };

    res.once('close', revoke);
    res.once('finish', revoke);

    const lastModified = details.mtimeMs ? new Date(details.mtimeMs).toUTCString() : null;

    return this._streamFile(res, details.absolutePath, {
      mime,
      cacheControl: 'private, max-age=0, no-store',
      etag: null,
      lastModified,
      rangeHeader: req.headers.range,
      headOnly: method === 'HEAD',
      disposition: contentDisposition
    });
  }

  _isFresh(req, etag, mtimeMs) {
    const headers = req.headers || {};
    const inm = headers['if-none-match'];
    if (etag && typeof inm === 'string') {
      const candidates = inm.split(',').map(v => v.trim()).filter(Boolean);
      if (candidates.includes('*') || candidates.includes(etag)) return true;
    }

    const ims = headers['if-modified-since'];
    if (ims) {
      const since = Date.parse(ims);
      if (!Number.isNaN(since) && Math.floor(mtimeMs / 1000) <= Math.floor(since / 1000)) {
        return true;
      }
    }
    return false;
  }

  _sendAssetError(res, statusCode, message) {
    if (res.headersSent) return;
    const body = message || 'Error';
    const headers = this._composeHeaders(res, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': Buffer.byteLength(body)
    });
    res.writeHead(statusCode, headers);
    if (res.__headRequest) return res.end();
    res.end(body);
  }

  _streamFile(res, filePath, { stat = null, mime = 'application/octet-stream', cacheControl = 'no-store', etag = null, lastModified = null, rangeHeader = null, headOnly = false, disposition = null } = {}) {
    let fileStat = stat;
    try {
      if (!fileStat) fileStat = fs.statSync(filePath);
    } catch (err) {
      console.error('stream stat error', err);
      return this._sendAssetError(res, 404, 'File not found');
    }

    const size = fileStat.size;
    let start = 0;
    let end = size - 1;
    let statusCode = 200;

    if (rangeHeader && typeof rangeHeader === 'string') {
      const match = /^bytes=(\d*)-(\d*)$/i.exec(rangeHeader.trim());
      if (match) {
        const startStr = match[1];
        const endStr = match[2];
        if (startStr === '' && endStr === '') {
          return this._sendRangeNotSatisfiable(res, size);
        }
        start = startStr ? Math.min(size - 1, parseInt(startStr, 10)) : start;
        end = endStr ? Math.min(size - 1, parseInt(endStr, 10)) : end;
        if (startStr === '' && endStr) {
          const suffixLength = Math.min(size, parseInt(endStr, 10));
          start = Math.max(0, size - suffixLength);
          end = size > 0 ? size - 1 : 0;
        }
        if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) {
          return this._sendRangeNotSatisfiable(res, size);
        }
        statusCode = 206;
      } else {
        return this._sendRangeNotSatisfiable(res, size);
      }
    }

    if (size === 0) {
      start = 0;
      end = -1;
    }

    const length = Math.max(0, end - start + 1);
    const headers = {
      'Content-Type': mime,
      'Content-Length': length,
      'Last-Modified': lastModified || fileStat.mtime.toUTCString(),
      'Cache-Control': cacheControl,
      'Accept-Ranges': 'bytes'
    };
    if (etag) headers['ETag'] = etag;
    if (disposition) headers['Content-Disposition'] = disposition;
    if (statusCode === 206) {
      headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
    }

    const composed = this._composeHeaders(res, headers);
    res.writeHead(statusCode, composed);
    if (headOnly || length === 0) return res.end();

    const stream = fs.createReadStream(filePath, { start, end: start + length - 1 });
    stream.on('error', (e) => {
      console.error('file stream error', e);
      if (!res.headersSent) {
        this._sendAssetError(res, 500, 'File stream error');
      } else {
        try { res.destroy(e); } catch (errDestroy) { /* ignore */ }
      }
    });
    stream.pipe(res);
  }

  _sendRangeNotSatisfiable(res, size) {
    const headers = this._composeHeaders(res, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Range': `bytes */${size}`,
      'Content-Length': Buffer.byteLength('Requested Range Not Satisfiable')
    });
    res.writeHead(416, headers);
    if (res.__headRequest) return res.end();
    return res.end('Requested Range Not Satisfiable');
  }

  // ---------- body collector ----------
  _collectBody(req, res, maxLen=10_000_000) {
    return new Promise((resolve, reject) => {
      const decoder = new StringDecoder('utf8');
      let raw = '';
      req.on('data', chunk => { raw += decoder.write(chunk); if (raw.length > maxLen) { req.destroy(); reject({ code:413, message:'Payload too large' }); } });
      req.on('end', () => {
        raw += decoder.end();
        resolve({ raw });
      });
      req.on('error', e => reject({ code:400, message:'Request stream error', details:e?.message }));
    });
  }

  _collectRawBody(req, res, maxLen=10_000_000) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      req.on('data', chunk => {
        total += chunk.length;
        if (total > maxLen) {
          req.destroy();
          reject({ code: 413, message: 'Payload too large' });
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve({ buffer: Buffer.concat(chunks) }));
      req.on('error', e => reject({ code: 400, message: 'Request stream error', details: e?.message }));
    });
  }

  _collectRawBody(req, res, maxLen=10_000_000) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      req.on('data', chunk => {
        total += chunk.length;
        if (total > maxLen) {
          req.destroy();
          reject({ code: 413, message: 'Payload too large' });
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve({ buffer: Buffer.concat(chunks) }));
      req.on('error', e => reject({ code: 400, message: 'Request stream error', details: e?.message }));
    });
  }

  _getCookie(req, name) {
    const cookie = req.headers.cookie || '';
    const parts = cookie.split(';').map(c => c.trim()).filter(Boolean);
    for (const p of parts) {
      const idx = p.indexOf('=');
      if (idx === -1) continue;
      const k = p.slice(0, idx); const v = p.slice(idx+1);
      if (k === name) return decodeURIComponent(v);
    }
    return null;
  }

  // ---------- helpers for index.html CSP / hoist ----------
  /**
   * convert inline style attributes into class names and build a style block (returns new html)
   * - scans for style="..." on elements and replaces with class="is-<hash>"
   * - collects `.is-<hash> { ... }` rules and injects <style nonce="..."> into <head>
   *
   * NOTE: this is a heuristic helper. It strips inline event handlers (onclick=...) for safety.
   */
  _hoistInlineStylesAndStripEvents(html, nonce) {
    const styleMap = Object.create(null);

    html = html.replace(/(<[a-zA-Z0-9\-]+)([^>]*?)\sstyle\s*=\s*(['"])(.*?)\3([^>]*?)(\/?)>/gi,
      (match, startTag, beforeAttrs, q, styleStr, afterAttrs, endSlash) => {

        const styleNormalized = styleStr.trim();
        if (!styleNormalized) return match;

        const hash = crypto.createHash('sha1').update(styleNormalized).digest('hex').slice(0,8);
        const cls = `is-${hash}`;
        styleMap[cls] = styleNormalized;

        // remove any inline event handlers in the remaining attrs
        let combined = (beforeAttrs + ' ' + afterAttrs).trim();
        combined = combined.replace(/\s*on\w+\s*=\s*(['"])[\s\S]*?\1/gi, '');

        const classMatch = combined.match(/class\s*=\s*(['"])(.*?)\1/i);
        let newAttrs;
        if (classMatch) {
          const existing = classMatch[2];
          newAttrs = combined.replace(classMatch[0], `class="${existing} ${cls}"`);
        } else {
          newAttrs = `${combined} class="${cls}"`.trim();
        }

        return `${startTag} ${newAttrs}${endSlash}>`;
      });

    const keys = Object.keys(styleMap);
    if (keys.length) {
      let styleBlock = `<style nonce="${nonce}">\n`;
      for (const k of keys) styleBlock += `.${k} { ${styleMap[k]} }\n`;
      styleBlock += `</style>\n`;

      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1>\n${styleBlock}`);
      } else {
        html = styleBlock + html;
      }
    }
    return html;
  }

  _addNonceToScriptAndStyleTags(html, nonce) {
    html = html.replace(/<script\b([^>]*)>/gi, (match, attrs) => {
      if (/nonce\s*=\s*['"]?[\w+/=.-]+['"]?/i.test(attrs)) return `<script${attrs}>`;
      return `<script nonce="${nonce}"${attrs}>`;
    });
    html = html.replace(/<style\b([^>]*)>/gi, (match, attrs) => {
      if (/nonce\s*=\s*['"]?[\w+/=.-]+['"]?/i.test(attrs)) return `<style${attrs}>`;
      return `<style nonce="${nonce}"${attrs}>`;
    });
    return html;
  }

  // ---------- main request handler ----------
  async handleRequest(req, res) {
    try {
      const corsOrigin = this._resolveCorsOrigin(req);
      res.__corsOrigin = corsOrigin;
      req.__corsOrigin = corsOrigin;

      req.method = (req.method || 'GET').toUpperCase();
      const isHeadRequest = req.method === 'HEAD';
      res.__headRequest = isHeadRequest;

      if (req.method === 'OPTIONS') {
        const headers = this._composeHeaders(res, {
          'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Csrf-Token',
          'Access-Control-Max-Age': '600',
          'Allow': 'OPTIONS, GET, HEAD, POST, PUT, DELETE'
        });
        res.writeHead(204, headers);
        return res.end();
      }

      const ip = this._getIp(req);
      if (this._globalRateCheck(ip)) return this.sendJson(res, 429, { success:false, message:'Too many requests' });

      const parsed = url.parse(req.url || '', true);
      const pathname = decodeURIComponent(parsed.pathname || '/');
      req.query = parsed.query || {};
      req.pathname = pathname;

      if (this.downloadService && pathname === this.downloadPath) {
        return this._handleDownload(req, res);
      }

      // static assets
      if (pathname.startsWith('/assets/')) {
        const rel = pathname.replace(/^\/assets\//,'');
        this._assignOperationId(req, res, 0);
        return this._serveAsset(req, res, path.join('assets', rel));
      }

      let route = this.findRoute(req.method, pathname);
      if (!route && isHeadRequest) {
        route = this.findRoute('GET', pathname);
      }

      if (!route) {
        const allowed = this.allowedMethods(pathname);
        if (allowed.size) {
          const allowSet = new Set(allowed);
          if (allowSet.has('GET')) allowSet.add('HEAD');
          allowSet.add('OPTIONS');
          const allowHeader = Array.from(allowSet).sort().join(', ');
          this._assignOperationId(req, res, 0);
          const headers = this._composeHeaders(res, {
            'Content-Type': 'text/plain; charset=utf-8',
            Allow: allowHeader
          });
          res.writeHead(405, headers);
          if (res.__headRequest) return res.end();
          return res.end('Method Not Allowed');
        }

        if (req.method === 'GET' || isHeadRequest) {
          const indexFile = this._safeJoin(this.publicPath, 'index.html');
          if (indexFile && fs.existsSync(indexFile)) {
            this._assignOperationId(req, res, 0);
            return this.renderHtmlFile(res, 200, indexFile);
          }
        }

        this._assignOperationId(req, res, 0);
        return this.sendJson(res, 404, { success:false, message:'Not found' });
      }

      if (this._customRateCheck(route, ip)) return this.sendJson(res, 429, { success:false, message:'Too many requests for this endpoint' });

      // -------- auth (route-level) --------
      let user = null;
      if (route.options && route.options.auth) {
        if (!this.authService || typeof this.authService.authenticateRequest !== 'function') {
          return this.sendJson(res, 500, { success:false, message:'AuthService missing authenticateRequest' });
        }
        try {
          const authResult = await this.authService.authenticateRequest(req, route.options);
          user = (authResult && authResult.user) || authResult || null;
          if (authResult && authResult.token) req.authToken = authResult.token;
        } catch (err) {
          const status = err && err.statusCode ? err.statusCode : 401;
          const message = err && err.message ? err.message : 'Unauthorized';
          if (route.options && route.options.redirect && (req.headers.accept || '').includes('text/html')) {
            return this.redirectHtml(res, route.options.redirect);
          }
          if (route.options && route.options.graph) {
            const opId = this._assignOperationId(req, res, 0);
            return this.sendGraph(res, 200, { data: null, errors: [{ message, extensions: { code: status === 401 ? 'UNAUTHENTICATED' : 'FORBIDDEN', httpStatus: status, operationId: opId } }] });
          }
          this._assignOperationId(req, res, 0);
          return this.sendJson(res, status, { success:false, message });
        }
        if (route.options.roles) {
          const allowed = Array.isArray(route.options.roles) ? route.options.roles : [route.options.roles];
          const hasRole = user && (allowed.includes(user.role) || (Array.isArray(user.roles) && user.roles.some(r => allowed.includes(r))));
          if (!hasRole) {
            const opId = this._assignOperationId(req, res, user?.permissions || 0);
            const body = route.options.graph
              ? { data: null, errors: [{ message: 'Forbidden', extensions: { code: 'FORBIDDEN', httpStatus: 403, operationId: opId } }] }
              : { success:false, message:'Forbidden' };
            if (route.options.graph) return this.sendGraph(res, 200, body);
            return this.sendJson(res, 403, body);
          }
        }
        if (route.options && route.options.permissions !== undefined) {
          const requiredMask = permissionMaskFrom(route.options.permissions);
          if (!hasPermission(user, requiredMask)) {
            const opId = this._assignOperationId(req, res, user?.permissions || 0);
            const body = route.options.graph
              ? { data: null, errors: [{ message: 'Forbidden', extensions: { code: 'FORBIDDEN', httpStatus: 403, operationId: opId } }] }
              : { success:false, message:'Forbidden' };
            if (route.options.graph) return this.sendGraph(res, 200, body);
            return this.sendJson(res, 403, body);
          }
        }
      }

      if (route.path.includes('/:')) req.params = this.extractParams(route.path, pathname);
      req.user = user;

      this._assignOperationId(req, res, user?.permissions || 0);

      // small helper send() for handlers
      const send = (status, payload, headers) => {
        if (route.options && route.options.graph) return this.sendGraph(res, status, payload, headers);
        return this.sendJson(res, status, payload, headers);
      };

      // ---------- upload handling ----------
      if (route.options && (route.options.multipart || (req.headers['content-type']||'').includes('multipart/form-data') || route.options.upload)) {
        return this._handleUpload(req, res, route.options, async (uploadResult) => {
          req.body = uploadResult;
          // validate files if accept list provided
          if (uploadResult.files && uploadResult.files.length) {
            for (const f of uploadResult.files) {
              const ext = path.extname(f.filename).toLowerCase();
              const detected = f.contentType || this.mimeMap[ext] || 'application/octet-stream';
              if (route.options.upload && route.options.upload.accept && route.options.upload.accept.length) {
                if (!route.options.upload.accept.includes(detected)) {
                  try { fs.unlinkSync(f.path); } catch(e) {}
                  return this.sendJson(res, 415, { success:false, message:'Unsupported Media Type' });
                }
              }
            }
          }

          // allow handler to use send helper or return value
          let handled = false;
          const wrappedSend = (status, payload, headers) => { handled = true; return send(status, payload, headers); };

          const maybe = route.handler.length >= 3 ? await route.handler(req, res, wrappedSend) : await route.handler(req, res, wrappedSend);
          if (handled) return;
          if (maybe === true || (maybe && maybe.redirect === true)) {
            const loc = (maybe && maybe.location) || (route.options && route.options.redirect) || '/';
            if ((req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, loc);
            return this.sendJson(res, 204, { success:true, redirect: loc });
          }
          if (route.options && route.options.graph) return this.sendGraph(res, 200, maybe);
          return this.sendJson(res, 200, maybe);
        });
      }

      // ---------- normal (non-upload) body handling ----------
      const maxBodyLength = (route.options && route.options.maxBodyLength) || 10_000_000;
      let collected;
      try {
        if (route.options && route.options.rawBody) {
          collected = await this._collectRawBody(req, res, maxBodyLength);
        } else {
          collected = await this._collectBody(req, res, maxBodyLength);
        }
      } catch (err) {
        const status = err && err.code === 413 ? 413 : 400;
        const message = err && err.message ? err.message : 'Request body error';
        return this.sendJson(res, status, { success: false, message });
      }

      if (route.options && route.options.rawBody) {
        req.rawBody = collected.buffer;
        req.rawBodyBuffer = collected.buffer;
        req.body = collected.buffer;
      } else {
        req.rawBody = collected.raw || '';

        if (route.options && route.options.graph) {
          // GraphQL-special parsing: attempt to parse JSON; fallback to treating raw as { query: raw }
          const contentType = String(req.headers['content-type'] || '').toLowerCase();
          if (contentType.includes('application/graphql') || contentType === 'graphql') {
            // some clients send raw GraphQL string; try to parse JSON first (legacy compat)
            try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch { req.body = { query: collected.raw }; }
          } else if (contentType.includes('application/json')) {
            try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch {
              return this.sendJson(res, 400, { error: 'Invalid JSON' });
            }
          } else {
            // best-effort
            try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch {
              req.body = { query: collected.raw };
            }
          }
        } else {
          try {
            req.body = collected.raw ? JSON.parse(collected.raw) : {};
          } catch {
            try { req.body = Object.fromEntries(new URLSearchParams(collected.raw)); } catch { req.body = collected.raw || {}; }
          }
          if (req.body && typeof req.body === 'object') req.body = this._sanitizeObject(req.body);
        }
      }

      // ---------- call handler ----------
      let handled = false;
      const wrappedSend = (status, payload, headers) => { handled = true; return send(status, payload, headers); };

      const maybe = route.handler.length >= 3 ? await route.handler(req, res, wrappedSend) : await route.handler(req, res, wrappedSend);
      if (handled) return;

      if (maybe === true || (maybe && maybe.redirect === true)) {
        const loc = (maybe && maybe.location) || (route.options && route.options.redirect) || '/';
        if ((req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, loc);
        return this.sendJson(res, 204, { success:true, redirect: loc });
      }

      if (route.options && route.options.graph) return this.sendGraph(res, 200, maybe);
      return this.sendJson(res, 200, maybe);

    } catch (err) {
      console.error('Request handling error', err);
      if (!req.operationId) this._assignOperationId(req, res, 0);
      if (!res.headersSent) {
        const headers = this._composeHeaders(res, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.writeHead(500, headers);
      }
      try { res.end('Internal Server Error'); } catch(e) {}
    }
  }

  listen(port = 3000, cb) {
    const srv = http.createServer((req, res) => this.handleRequest(req, res));
    srv.listen(port, cb || (() => console.log(`HttpService listening on ${port}`)));
    return srv;
  }
}

module.exports = HttpService;

HttpService.prototype._assignOperationId = function assignOperationId(req, res, permissionMask) {
  if (req.operationId) return req.operationId;
  const mask = normalizePermissionMask(permissionMask);
  const opId = this.operationIdFactory.generate(mask);
  req.operationId = opId;
  if (!res.headersSent) {
    try { res.setHeader('X-Operation-Id', opId); } catch (err) { /* ignore */ }
  }
  res.operationId = opId;
  return opId;
};

HttpService.prototype._withGraphExtensions = function withGraphExtensions(payload, opId) {
  if (!opId || !payload || typeof payload !== 'object') return payload;
  const base = Array.isArray(payload) ? payload.slice() : Object.assign({}, payload);
  const currentExtensions = payload.extensions && typeof payload.extensions === 'object'
    ? Object.assign({}, payload.extensions)
    : {};
  if (!currentExtensions.operationId) currentExtensions.operationId = opId;
  base.extensions = currentExtensions;
  return base;
};
