'use strict';

const crypto = require('crypto');

class TokenValidator {
  constructor(options = {}) {
    const {
      jwksClient,
      clockToleranceSec = 120,
      defaultAudience = null,
      defaultIssuers = [],
    } = options;

    if (!jwksClient) throw new Error('TokenValidator requires a JWKS client');

    this.jwksClient = jwksClient;
    this.clockToleranceSec = clockToleranceSec;
    this.defaultAudience = defaultAudience;
    this.defaultIssuers = Array.isArray(defaultIssuers) ? defaultIssuers.slice() : [defaultIssuers];
  }

  async verify(token, expectations = {}) {
    if (!token || typeof token !== 'string') throw new Error('Token is required');
    const { header, payload, segments } = this._decode(token);

    const jwk = await this.jwksClient.getSigningKey(header, payload);
    this._verifySignature(header, segments, jwk);
    this._assertClaims(payload, expectations);

    return { header, payload };
  }

  _decode(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT structure');
    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    const header = JSON.parse(this._base64UrlDecode(encodedHeader).toString('utf8'));
    const payload = JSON.parse(this._base64UrlDecode(encodedPayload).toString('utf8'));
    const signature = this._base64UrlDecode(encodedSignature);

    return {
      header,
      payload,
      signature,
      segments: { header: encodedHeader, payload: encodedPayload, signature: encodedSignature },
    };
  }

  _base64UrlDecode(input) {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4;
    const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;
    return Buffer.from(padded, 'base64');
  }

  _verifySignature(header, segments, jwk) {
    const { alg } = header;
    const publicKey = this._jwkToKeyObject(jwk);
    const data = `${segments.header}.${segments.payload}`;
    const signature = this._base64UrlDecode(segments.signature);

    const verifier = crypto.createVerify(this._mapAlgorithm(alg));
    verifier.update(data);
    verifier.end();

    const options = alg.startsWith('PS')
      ? { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
      : publicKey;

    const valid = verifier.verify(options, signature);
    if (!valid) throw new Error('Invalid token signature');
  }

  _mapAlgorithm(alg) {
    switch (alg) {
      case 'RS256':
      case 'PS256':
        return 'RSA-SHA256';
      case 'RS384':
      case 'PS384':
        return 'RSA-SHA384';
      case 'RS512':
      case 'PS512':
        return 'RSA-SHA512';
      default:
        throw new Error(`Unsupported signing algorithm: ${alg}`);
    }
  }

  _jwkToKeyObject(jwk) {
    if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
      throw new Error('Invalid RSA JWK');
    }
    return crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
  }

  _assertClaims(payload, expectations) {
    const now = Math.floor(Date.now() / 1000);
    const tolerance = Number.isFinite(expectations.clockToleranceSec) ? expectations.clockToleranceSec : this.clockToleranceSec;

    if (payload.exp && now > payload.exp + tolerance) {
      throw new Error('Token expired');
    }

    if (payload.nbf && now + tolerance < payload.nbf) {
      throw new Error('Token not yet valid');
    }

    const expectedAudience = expectations.audience || this.defaultAudience;
    if (expectedAudience) {
      const expectedList = Array.isArray(expectedAudience) ? expectedAudience : [expectedAudience];
      const actualAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!actualAud.some((aud) => expectedList.includes(aud))) {
        throw new Error('Audience mismatch');
      }
    }

    const expectedIssuers = expectations.issuers || this.defaultIssuers;
    if (expectedIssuers && expectedIssuers.length) {
      const actual = String(payload.iss || '').trim();
      const matches = expectedIssuers.some((issuer) => this._issuerMatches(issuer, actual, payload));
      if (!matches) {
        throw new Error('Issuer mismatch');
      }
    }

    if (expectations.nonce && payload.nonce && expectations.nonce !== payload.nonce) {
      throw new Error('Nonce mismatch');
    }
  }

  _issuerMatches(expected, actual, payload) {
    if (!expected) return true;
    if (expected instanceof RegExp) return expected.test(actual);
    if (typeof expected === 'function') {
      try { return !!expected(actual, payload); } catch (err) { return false; }
    }

    const normalizedActual = String(actual || '').trim().replace(/\/$/, '');
    if (!normalizedActual) return false;

    const tenantId = payload?.tid || payload?.tenantId || payload?.tenant || payload?.['http://schemas.microsoft.com/identity/claims/tenantid'];
    const normalizedExpected = String(expected).trim();

    const candidates = new Set();
    const placeholdersReplaced = tenantId
      ? normalizedExpected
          .replace(/{tenantId}/gi, tenantId)
          .replace(/{tenant}/gi, tenantId)
          .replace(/{tid}/gi, tenantId)
      : normalizedExpected;

    const normalized = String(placeholdersReplaced).trim().replace(/\/$/, '');
    candidates.add(normalizedExpected.replace(/\/$/, ''));
    candidates.add(normalized);

    if (normalizedExpected.includes('/common') && tenantId) {
      const swapped = normalizedExpected.replace(/\/common/gi, `/${tenantId}`);
      candidates.add(swapped.replace(/\/$/, ''));
    }

    for (const candidate of Array.from(candidates)) {
      if (!candidate) continue;

      if (this._issuerCandidateMatchesActual(candidate, normalizedActual)) {
        return true;
      }
    }

    return false;
  }

  _issuerCandidateMatchesActual(candidate, actual) {
    const normalizedCandidate = String(candidate).trim().replace(/\/$/, '');
    if (!normalizedCandidate) return false;

    if (normalizedCandidate === actual) return true;

    if (normalizedCandidate.endsWith('*')) {
      const prefix = normalizedCandidate.slice(0, -1);
      if (actual.startsWith(prefix)) return true;
    }

    const variants = new Set([normalizedCandidate]);
    if (/login\.microsoftonline\.com/i.test(normalizedCandidate)) {
      variants.add(normalizedCandidate.replace(/login\.microsoftonline\.com/gi, 'sts.windows.net'));
    }
    if (/sts\.windows\.net/i.test(normalizedCandidate)) {
      variants.add(normalizedCandidate.replace(/sts\.windows\.net/gi, 'login.microsoftonline.com'));
    }

    for (const variant of variants) {
      const trimmed = variant.replace(/\/$/, '');
      if (trimmed === actual) return true;
      if (trimmed.endsWith('/v2.0') && actual === trimmed.slice(0, -5)) return true;
      if (!trimmed.endsWith('/v2.0') && `${trimmed}/v2.0` === actual) return true;
    }

    return false;
  }
}

module.exports = { TokenValidator };
