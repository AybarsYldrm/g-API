'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SnowflakeIdFactory } = require('../../utils/snowflake');

class DownloadTokenService {
  constructor({ rootDir, secret, ttlSeconds = 300, idFactory = null } = {}) {
    if (!rootDir) throw new Error('DownloadTokenService requires rootDir');
    this.rootDir = rootDir;
    this.secret = this.#normalizeSecret(secret);
    this.ttlSeconds = Math.max(1, Number(ttlSeconds) || 300);
    this.idFactory = idFactory || new SnowflakeIdFactory();
    this.active = new Map(); // id -> metadata
  }

  createToken({ relativePath, expiresIn = this.ttlSeconds, filename = null, contentType = null, disposition = 'attachment', operationCode = 0 } = {}) {
    if (!relativePath) throw new Error('relativePath is required');
    const sanitized = this.#safeJoin(relativePath);
    if (!sanitized) throw new Error('Invalid relativePath');

    const stat = fs.statSync(sanitized);
    if (!stat.isFile()) throw new Error('Download target must be a file');

    const id = this.idFactory.generate(operationCode);
    const expiresAt = Math.floor(Date.now() / 1000) + Math.max(1, Number(expiresIn) || this.ttlSeconds);

    const payload = {
      id,
      p: relativePath,
      e: expiresAt,
      f: filename || path.basename(sanitized),
      c: contentType || null,
      d: disposition || 'attachment'
    };

    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signature = crypto.createHmac('sha256', this.secret).update(encoded).digest('base64url');
    const token = `${encoded}.${signature}`;

    this.active.set(id, {
      id,
      absolutePath: sanitized,
      relativePath,
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      filename: payload.f,
      contentType: payload.c,
      disposition: payload.d,
      expiresAt,
      operationCode
    });

    return token;
  }

  resolve(token) {
    if (!token || typeof token !== 'string') throw new Error('Token required');
    const parts = token.split('.');
    if (parts.length !== 2) throw new Error('Malformed token');

    const [encoded, signature] = parts;
    const expectedSig = crypto.createHmac('sha256', this.secret).update(encoded).digest('base64url');
    let providedBuf;
    let expectedBuf;
    try {
      providedBuf = Buffer.from(signature, 'base64url');
      expectedBuf = Buffer.from(expectedSig, 'base64url');
    } catch (err) {
      throw new Error('Invalid token signature');
    }
    if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
      throw new Error('Invalid token signature');
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    } catch (err) {
      throw new Error('Invalid token payload');
    }

    if (!payload || !payload.id || !payload.p) throw new Error('Incomplete token payload');

    if (Math.floor(Date.now() / 1000) > Number(payload.e || 0)) {
      this.active.delete(payload.id);
      throw new Error('Token expired');
    }

    const record = this.active.get(payload.id);
    const absolutePath = record ? record.absolutePath : this.#safeJoin(payload.p);
    if (!absolutePath) throw new Error('Token path resolution failed');

    const stat = fs.statSync(absolutePath);
    if (!stat.isFile()) throw new Error('Download target missing');

    return {
      id: payload.id,
      absolutePath,
      relativePath: payload.p,
      filename: payload.f || path.basename(absolutePath),
      contentType: payload.c,
      disposition: payload.d || 'attachment',
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      expiresAt: payload.e,
      operationCode: record ? record.operationCode : 0
    };
  }

  revoke(idOrToken) {
    if (!idOrToken) return false;
    let id = idOrToken;
    if (typeof idOrToken === 'string' && idOrToken.includes('.')) {
      try {
        const [encoded] = idOrToken.split('.');
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        id = payload.id;
      } catch (err) {
        return false;
      }
    }
    return this.active.delete(id);
  }

  #normalizeSecret(secret) {
    if (Buffer.isBuffer(secret)) return secret;
    if (typeof secret === 'string' && secret.length) return Buffer.from(secret, 'utf8');
    return crypto.createHash('sha256').update('graph-api-download-secret').digest();
  }

  #safeJoin(target) {
    const base = path.resolve(this.rootDir);
    const resolved = path.resolve(base, target);
    const relative = path.relative(base, resolved);
    if (!relative || relative === '' || relative === path.basename(resolved)) {
      return resolved;
    }
    if (relative.startsWith('..') || path.isAbsolute(relative)) return null;
    return resolved;
  }
}

module.exports = { DownloadTokenService };
