'use strict';

const https = require('https');
const { URL } = require('url');

class JwksClient {
  constructor(options = {}) {
    const {
      authority,
      expectedIssuers = [],
      cacheTtlMs = 60 * 60 * 1000,
      httpAgent = null,
    } = options;

    if (!authority) throw new Error('JwksClient requires an authority');

    this.authority = authority.replace(/\/$/, '');
    this.expectedIssuers = Array.isArray(expectedIssuers) ? expectedIssuers.slice() : [expectedIssuers];
    this.cacheTtlMs = cacheTtlMs;
    this.httpAgent = httpAgent || undefined;

    this._jwksCache = null;
    this._jwksFetchedAt = 0;
    this._pendingFetch = null;
  }

  async getSigningKey(header, payload) {
    if (!header || typeof header !== 'object') throw new Error('JWT header is required');
    if (!payload || typeof payload !== 'object') throw new Error('JWT payload is required');

    const kid = header.kid || null;
    const hint = payload.iss || null;

    let jwk = this._findKeyFromCache(kid, header, hint);
    if (jwk) return jwk;

    await this._refreshJwks(hint);
    jwk = this._findKeyFromCache(kid, header, hint);
    if (jwk) return jwk;

    // fallback: refresh using base authority if issuer-specific fetch failed
    if (hint) {
      await this._refreshJwks(null);
      jwk = this._findKeyFromCache(kid, header, hint);
      if (jwk) return jwk;
    }

    throw new Error('Matching JWK not found');
  }

  async preload() {
    await this._refreshJwks(null);
  }

  async refresh(issuerHint = null) {
    return this._refreshJwks(issuerHint);
  }

  _findKeyFromCache(kid, header, issuerHint) {
    if (!this._jwksCache || !Array.isArray(this._jwksCache.keys)) return null;
    const { keys } = this._jwksCache;

    if (kid) {
      const direct = keys.find((key) => key.kid === kid);
      if (direct) return direct;
    }

    const thumbprint = header && (header.x5t || header['x5t#S256']);
    if (thumbprint) {
      const thumbKey = keys.find((key) => key.x5t === thumbprint || key['x5t#S256'] === thumbprint);
      if (thumbKey) return thumbKey;
    }

    if (issuerHint) {
      const issuerKey = keys.find((key) => key.issuer === issuerHint);
      if (issuerKey) return issuerKey;
    }

    return null;
  }

  async _refreshJwks(issuerHint) {
    const now = Date.now();
    if (this._jwksCache && now - this._jwksFetchedAt < this.cacheTtlMs && !issuerHint) {
      return this._jwksCache;
    }

    if (this._pendingFetch) {
      return this._pendingFetch;
    }

    this._pendingFetch = this._loadJwks(issuerHint)
      .then((jwks) => {
        this._jwksCache = jwks;
        this._jwksFetchedAt = Date.now();
        return jwks;
      })
      .finally(() => {
        this._pendingFetch = null;
      });

    return this._pendingFetch;
  }

  async _loadJwks(issuerHint) {
    const authority = this._resolveAuthorityFromIssuer(issuerHint) || this.authority;
    const openIdConfig = await this._discoverOpenIdConfiguration(authority);
    if (!openIdConfig || !openIdConfig.jwks_uri) {
      throw new Error('OpenID configuration did not include jwks_uri');
    }

    const jwks = await this._httpsGetJson(openIdConfig.jwks_uri);
    if (!jwks || !Array.isArray(jwks.keys)) {
      throw new Error('Invalid JWKS payload received');
    }

    return { keys: jwks.keys };
  }

  _resolveAuthorityFromIssuer(issuer) {
    if (!issuer) return this.authority;
    try {
      const url = new URL(issuer);
      const host = url.host;
      const segments = url.pathname.split('/').filter(Boolean);

      if (host.includes('b2clogin.com')) {
        if (segments.length >= 2) {
          return `https://${host}/${segments[0]}/${segments[1]}`;
        }
        return `https://${host}`;
      }

      if (host.includes('sts.windows.net') && segments.length >= 1) {
        return `https://login.microsoftonline.com/${segments[0]}`;
      }

      if (host.includes('login.microsoftonline.com')) {
        const tenant = segments[0] || 'common';
        return `https://login.microsoftonline.com/${tenant}`;
      }
    } catch (err) {
      return this.authority;
    }
    return this.authority;
  }

  async _discoverOpenIdConfiguration(authority) {
    const base = authority.replace(/\/$/, '');
    const v2 = `${base}/v2.0/.well-known/openid-configuration`;
    const v1 = `${base}/.well-known/openid-configuration`;

    try {
      return await this._httpsGetJson(v2);
    } catch (err) {
      return this._httpsGetJson(v1);
    }
  }

  async _httpsGetJson(targetUrl) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(targetUrl);
      const options = {
        method: 'GET',
        hostname: parsed.hostname,
        path: parsed.pathname + (parsed.search || ''),
        headers: { 'Accept': 'application/json' },
        agent: this.httpAgent,
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body || '{}'));
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }
}

module.exports = { JwksClient };
