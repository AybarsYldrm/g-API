'use strict';

const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');
const querystring = require('querystring');

const { normalizePermissionMask, permissionMaskFrom } = require('../utils/permissions');
const { JwksClient } = require('./auth/JwksClient');
const { TokenValidator } = require('./auth/TokenValidator');

class AuthService {
  constructor({ db, config, jwksClient = null, tokenValidator = null, notificationService = null, pkiService = null } = {}) {
    if (!db) throw new Error('AuthService requires db');
    if (!config || !config.microsoft) throw new Error('AuthService requires microsoft config');

    this.db = db;
    this.config = config;
    this.microsoft = Object.assign(
      {
        scope: 'openid profile email offline_access',
      },
      config.microsoft,
    );

    this.microsoft.expectedIssuers = this._normalizeIssuers(
      this.microsoft.expectedIssuers?.length
        ? this.microsoft.expectedIssuers
        : this.microsoft.expectedIssuer,
    );

    this.security = Object.assign(
      {
        authCookieName: 'auth_token',
        authCookieSecure: process.env.NODE_ENV === 'production',
        authCookieSameSite: 'Lax',
        persistIdToken: true,
        rolePermissionMap: config.security?.rolePermissionMap || {},
        defaultPermissionMask: config.security?.defaultPermissionMask || 0,
      },
      config.security || {},
    );

    this.pendingStates = new Map();
    this.notifications = notificationService;
    this.pki = pkiService || null;

    this.jwksClient = jwksClient
      || new JwksClient({
        authority: this.microsoft.authority,
        expectedIssuers: this.microsoft.expectedIssuers,
        cacheTtlMs: this.microsoft.jwksCacheTtlMs || 60 * 60 * 1000,
      });

    this.tokenValidator = tokenValidator
      || new TokenValidator({
        jwksClient: this.jwksClient,
        defaultAudience: this.microsoft.clientId,
        defaultIssuers: this.microsoft.expectedIssuers,
        clockToleranceSec: this.microsoft.clockToleranceSec || 120,
      });

    this.tokenExtractors = this._buildTokenExtractors();
  }

  // ---------- Authorization request helpers ----------
  createAuthorizationRequest({ returnTo = '/', scope = null } = {}) {
    const state = this._createState(returnTo);

    const params = {
      client_id: this.microsoft.clientId,
      response_type: 'code',
      response_mode: 'query',
      redirect_uri: this.microsoft.redirectUri,
      scope: scope || this.microsoft.scope,
      state: state.serialized,
      nonce: state.nonce,
    };

    const location = `${this.microsoft.authority}/oauth2/v2.0/authorize?${querystring.stringify(params)}`;
    return { location, state, nonce: state.nonce };
  }

  beginLogin(res, { returnTo = '/', scope = null } = {}) {
    const { location } = this.createAuthorizationRequest({ returnTo, scope });
    res.writeHead(302, { Location: location });
    res.end();
    return { location };
  }

  async handleCallback(query, res = null) {
    const stateEntry = this._validateState(query?.state);
    if (!stateEntry) throw new Error('State validation failed');
    if (!query?.code) throw new Error('Authorization code missing');

    const tokenResponse = await this._tokenRequest(query.code);
    if (!tokenResponse || !tokenResponse.id_token) {
      throw new Error('Microsoft token exchange failed');
    }

    const { payload } = await this.tokenValidator.verify(tokenResponse.id_token, {
      nonce: stateEntry.nonce,
    });

    const profile = this._buildProfile(payload, tokenResponse);
    const user = await this._syncUser(profile);

    if (this.security.persistIdToken !== false && res) {
      this._setAuthCookie(res, tokenResponse.id_token, payload.exp);
    }

    return {
      user,
      profile,
      tokens: {
        idToken: tokenResponse.id_token,
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        expiresIn: tokenResponse.expires_in,
      },
      redirectTo: stateEntry.returnTo || '/',
    };
  }

  async logout(res) {
    if (this.security.persistIdToken !== false && res) {
      this._clearAuthCookie(res);
    }

    const postUri = this.microsoft.postLogoutRedirectUri
      || (this.microsoft.redirectUri
        ? (() => {
            const u = new URL(this.microsoft.redirectUri);
            u.pathname = '/';
            u.search = '';
            u.hash = '';
            return u.toString();
          })()
        : '/');

    const qs = querystring.stringify({ post_logout_redirect_uri: postUri });
    const url = `${this.microsoft.authority}/oauth2/v2.0/logout?${qs}`;
    return url;
  }

  async authenticateRequest(req, options = {}) {
    const token = this._extractTokenFromRequest(req);
    if (!token) {
      throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
    }

    let payload;
    try {
      ({ payload } = await this.tokenValidator.verify(token));
    } catch (err) {
      throw Object.assign(new Error('Invalid token'), { statusCode: 401 });
    }

    const profile = this._buildProfile(payload, {
      expires_in: payload.exp ? payload.exp - Math.floor(Date.now() / 1000) : undefined,
    });

    const user = await this._ensureUser(profile);
    if (options && options.expectPermissions) {
      const requiredMask = permissionMaskFrom(options.expectPermissions);
      if (!user || (user.permissions & requiredMask) !== requiredMask) {
        throw Object.assign(new Error('Forbidden'), { statusCode: 403 });
      }
    }

    return { user, token, claims: payload };
  }

  async refreshJwks(issuerHint = null) {
    return this.jwksClient.refresh(issuerHint);
  }

  // ---------- Internal helpers ----------
  _buildTokenExtractors() {
    const extractors = [];

    extractors.push((req) => {
      const auth = req.headers?.authorization || req.headers?.Authorization;
      if (auth && typeof auth === 'string' && auth.startsWith('Bearer ')) {
        return auth.slice(7).trim();
      }
      return null;
    });

    if (this.security.persistIdToken !== false) {
      extractors.push((req) => {
        const cookies = this._parseCookies(req);
        return cookies[this.security.authCookieName];
      });
    }

    const customExtractors = Array.isArray(this.security.tokenExtractors)
      ? this.security.tokenExtractors
      : [];
    for (const extractor of customExtractors) {
      if (typeof extractor === 'function') {
        extractors.push((req) => {
          try { return extractor(req); } catch (err) { return null; }
        });
      }
    }

    return extractors;
  }

  _createState(returnTo = '/') {
    const stateId = crypto.randomBytes(16).toString('hex');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(16).toString('base64url');
    const serialized = `${stateId}.${verifier}`;

    this.pendingStates.set(stateId, { returnTo, verifier, nonce, createdAt: Date.now() });

    return { stateId, verifier, nonce, serialized };
  }

  _validateState(stateParam) {
    if (!stateParam || typeof stateParam !== 'string') return null;
    const [stateId, verifier] = stateParam.split('.');
    const entry = this.pendingStates.get(stateId);
    if (!entry) return null;
    this.pendingStates.delete(stateId);
    if (!verifier || entry.verifier !== verifier) return null;
    if (Date.now() - entry.createdAt > 5 * 60 * 1000) return null;
    return entry;
  }

  async _tokenRequest(code) {
    const body = querystring.stringify({
      client_id: this.microsoft.clientId,
      scope: this.microsoft.scope,
      code,
      redirect_uri: this.microsoft.redirectUri,
      grant_type: 'authorization_code',
      client_secret: this.microsoft.clientSecret,
    });

    const url = new URL(`${this.microsoft.authority}/oauth2/v2.0/token`);

    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          method: 'POST',
          hostname: url.hostname,
          path: url.pathname,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data || '{}');
              if (res.statusCode >= 400 || parsed.error) {
                const msg = parsed.error_description || parsed.error || 'Microsoft token exchange failed';
                return reject(new Error(msg));
              }
              resolve(parsed);
            } catch (err) {
              reject(err);
            }
          });
        },
      );

      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  _extractTokenFromRequest(req) {
    for (const extractor of this.tokenExtractors) {
      try {
        const token = extractor(req);
        if (token) return token;
      } catch (err) {
        continue;
      }
    }
    return null;
  }

  _parseCookies(req) {
    const header = req?.headers?.cookie;
    if (!header) return {};
    return header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .reduce((acc, part) => {
        const idx = part.indexOf('=');
        if (idx === -1) return acc;
        const key = part.slice(0, idx);
        const value = decodeURIComponent(part.slice(idx + 1));
        acc[key] = value;
        return acc;
      }, {});
  }

  _setAuthCookie(res, token, expUnix = null) {
    const attrs = [`${this.security.authCookieName}=${encodeURIComponent(token)}`];
    attrs.push('Path=/');
    attrs.push('HttpOnly');
    attrs.push(`SameSite=${this.security.authCookieSameSite || 'Lax'}`);
    if (this.security.authCookieSecure) attrs.push('Secure');
    if (this.security.authCookieDomain) attrs.push(`Domain=${this.security.authCookieDomain}`);
    if (expUnix && Number.isFinite(expUnix)) {
      const maxAge = Math.max(0, Math.floor(expUnix - Date.now() / 1000));
      attrs.push(`Max-Age=${maxAge}`);
    }
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  _clearAuthCookie(res) {
    const attrs = [
      `${this.security.authCookieName}=`,
      'Path=/',
      'HttpOnly',
      `SameSite=${this.security.authCookieSameSite || 'Lax'}`,
      'Max-Age=0',
    ];
    if (this.security.authCookieSecure) attrs.push('Secure');
    if (this.security.authCookieDomain) attrs.push(`Domain=${this.security.authCookieDomain}`);
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  _normalizeIssuers(input) {
    const arr = Array.isArray(input) ? input : (input ? [input] : []);
    if (!arr.length && this.microsoft?.expectedIssuer) return [this.microsoft.expectedIssuer];
    return arr.map((entry) => (entry instanceof RegExp || typeof entry === 'function' ? entry : String(entry)));
  }

  _resolvePermissions(roles = []) {
    const map = this.security.rolePermissionMap || {};
    const defaultMask = typeof this.security.defaultPermissionMask === 'number'
      ? this.security.defaultPermissionMask
      : 0;
    let mask = defaultMask;
    for (const role of roles) {
      if (!role) continue;
      const key = String(role).toLowerCase();
      if (map[key] !== undefined) mask |= map[key];
    }
    return normalizePermissionMask(mask);
  }

  async _ensureUser(profile) {
    const existing = await this.db.findOne('users', { externalId: profile.externalId });
    if (existing) {
      return Object.assign({}, existing, {
        permissions: profile.permissions,
        role: profile.roles && profile.roles.length ? profile.roles[0] : existing.role,
        roles: profile.roles && profile.roles.length ? profile.roles.slice() : existing.roles,
      });
    }
    return this._syncUser(profile);
  }

  async _syncUser(profile) {
    const existing = await this.db.findOne('users', { externalId: profile.externalId });
    const nowIso = new Date().toISOString();
    const basePatch = {
      email: profile.email,
      name: profile.name,
      role: profile.roles && profile.roles.length ? profile.roles[0] : 'member',
      roles: profile.roles,
      permissions: profile.permissions,
      tenantId: profile.tenantId,
      lastLoginAt: nowIso,
    };

    if (existing) {
      const patch = Object.assign({}, basePatch, {
        loginCount: typeof existing.loginCount === 'number' ? existing.loginCount + 1 : 1,
      });
      const updated = await this.db.update('users', existing.id, patch);
      const stamped = await this._maybeSendWelcome(updated, false);
      const certed = await this._issueCertificateIfNeeded(stamped || updated, false);
      return certed || stamped || updated;
    }

    const created = await this.db.insert('users', Object.assign({
      externalId: profile.externalId,
      role: 'member',
      permissions: profile.permissions,
      tenantId: profile.tenantId,
      firstLoginAt: nowIso,
      lastLoginAt: nowIso,
      loginCount: 1,
      welcomeEmailSentAt: null,
      pki: null,
    }, basePatch));
    const stamped = await this._maybeSendWelcome(created, true);
    const certed = await this._issueCertificateIfNeeded(stamped || created, true);
    return certed || stamped || created;
  }

  _buildProfile(idPayload, tokenResponse = {}) {
    const roles = Array.isArray(idPayload.roles) ? idPayload.roles : (idPayload.role ? [idPayload.role] : []);
    return {
      externalId: idPayload.oid || idPayload.sub,
      tenantId: idPayload.tid,
      email: idPayload.preferred_username || idPayload.email,
      name: idPayload.name || `${idPayload.given_name || ''} ${idPayload.family_name || ''}`.trim(),
      roles,
      permissions: this._resolvePermissions(roles),
      locale: idPayload.locale,
      issuedAt: idPayload.iat,
      expiresAt: idPayload.exp,
      raw: idPayload,
      sessionExpiresIn: tokenResponse.expires_in,
    };
  }

  async _maybeSendWelcome(user, isNew) {
    if (!user || !this.notifications || typeof this.notifications.sendWelcome !== 'function') return null;
    if (user.welcomeEmailSentAt) return null;
    try {
      await this.notifications.sendWelcome(user, { isNew });
      const stamped = await this.db.update('users', user.id, { welcomeEmailSentAt: new Date().toISOString() });
      return stamped;
    } catch (err) {
      console.error('Welcome email dispatch failed', err);
      return null;
    }
  }

  async _issueCertificateIfNeeded(user, force) {
    if (!this.pki || !user) return null;
    try {
      const result = await this.pki.ensureUserCertificate(user, { force });
      if (result && result.user) return result.user;
      if (result && result.certificate) {
        const refreshed = await this.db.findOne('users', { id: user.id });
        return refreshed || user;
      }
    } catch (err) {
      console.error('Certificate provisioning failed', err);
    }
    return null;
  }
}

module.exports = { AuthService };
