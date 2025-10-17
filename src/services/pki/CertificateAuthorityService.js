'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const { CertificateAuthoritySystem } = require('./CertificateAuthoritySystem');

class CertificateAuthorityService {
  constructor({ baseDir, db, config = {} } = {}) {
    if (!baseDir) throw new Error('CertificateAuthorityService requires baseDir');
    if (!db) throw new Error('CertificateAuthorityService requires db');

    this.baseDir = baseDir;
    this.db = db;
    this.config = config || {};

    this.rootSubject = Object.assign({
      C: 'TR',
      ST: 'Sivas',
      L: 'Merkez',
      O: 'Fitfak',
      OU: 'Fitfak Root CA',
      CN: 'Fitfak Root Certificate Authority'
    }, config.rootSubject || {});

    this.subjectDefaults = config.subjectDefaults && typeof config.subjectDefaults === 'object'
      ? Object.assign({}, config.subjectDefaults)
      : {};

    this.rootValidityDays = config.rootValidityDays || 900;
    this.rootKeyFormat = config.rootEcPrivateKeyFormat === 'sec1' ? 'sec1' : 'pkcs8';
    this.leafValidityDays = config.leafValidityDays || 180;
    this.leafKeyFormat = config.leafEcPrivateKeyFormat === 'sec1' ? 'sec1' : 'pkcs8';
    this.autoRenewThresholdDays = config.autoRenewThresholdDays ?? 30;

    const eku = Array.isArray(config.leafExtendedKeyUsages) ? config.leafExtendedKeyUsages : null;
    this.leafExtendedKeyUsages = eku && eku.length ? eku : ['clientAuth', 'emailProtection'];

    this.services = Object.assign({
      ocspUrl: 'https://fitfak.net/ocsp',
      crlUrl: 'https://fitfak.net/crl',
      caIssuersUrl: 'https://fitfak.net/aia/ca.crt'
    }, config.services || {});

    this.ocspNextUpdateSeconds = config.ocspNextUpdateSeconds || 12 * 3600;
    this.crlNextUpdateSeconds = config.crlNextUpdateSeconds || 7 * 24 * 3600;

    this.ca = new CertificateAuthoritySystem(baseDir, { subjectDefaults: this.subjectDefaults });
    this.usersFile = path.join(baseDir, 'users.json');
    this.ca.setUsersFile(this.usersFile);

    this._lockPromise = null;
    this._initialized = false;
  }

  async init() {
    await fsp.mkdir(this.baseDir, { recursive: true });
    if (!fs.existsSync(this.usersFile)) {
      await fsp.writeFile(this.usersFile, '[]\n', 'utf8');
    }

    await this.#withLock(async () => {
      this.ca.ensureRoot(this.rootSubject, {
        days: this.rootValidityDays,
        ecPrivateKeyFormat: this.rootKeyFormat,
        services: this.services
      });

      this.ca.configureServices({
        ocspUrl: this.services.ocspUrl,
        crlUrl: this.services.crlUrl,
        caIssuersUrl: this.services.caIssuersUrl,
        ocspNextUpdateSeconds: this.ocspNextUpdateSeconds,
        crlNextUpdateSeconds: this.crlNextUpdateSeconds,
        autoRenewThresholdDays: this.autoRenewThresholdDays
      });

      await this.#exportUsersSnapshot();
      await this.#importUsersSnapshot();
    });

    this._initialized = true;
  }

  async ensureReady() {
    if (this._initialized) return;
    await this.init();
  }

  async ensureUserCertificate(user, { force = false } = {}) {
    if (!user || !user.id) return null;
    await this.ensureReady();

    return this.#withLock(async () => {
      await this.#exportUsersSnapshot();

      const current = await this.db.findOne('users', { id: user.id }) || user;
      if (!force && !this.#shouldRenew(current)) {
        await this.#importUsersSnapshot();
        return {
          certificate: current?.pki?.certificate || null,
          user: current
        };
      }

      const caInput = this.#toCaUserInput(current);
      this.ca.issueForUser(caInput, {
        days: this.leafValidityDays,
        ecPrivateKeyFormat: this.leafKeyFormat,
        reuseThresholdDays: this.autoRenewThresholdDays,
        eku: this.leafExtendedKeyUsages
      });

      await this.#importUsersSnapshot();
      const updated = await this.db.findOne('users', { id: current.id }) || current;
      return {
        certificate: updated?.pki?.certificate || null,
        user: updated
      };
    });
  }

  async getUserSigningMaterial(userOrId, { forceRenew = false } = {}) {
    if (!userOrId) throw new Error('User reference is required');

    await this.ensureReady();

    const baseUser = await this.#resolveUser(userOrId);
    if (!baseUser) throw new Error('User not found');

    const ensured = await this.ensureUserCertificate(baseUser, { force: forceRenew });
    const currentUser = ensured?.user
      || (await this.db.findOne('users', { id: baseUser.id }))
      || baseUser;

    const userId = currentUser && currentUser.id ? String(currentUser.id) : String(baseUser.id);
    const userDir = path.join(this.baseDir, 'users', userId);
    const keyPath = path.join(userDir, 'keys', 'key.pem');
    const certPath = path.join(userDir, 'certs', 'cert.pem');

    let keyPem;
    let certPem;
    try {
      keyPem = fs.readFileSync(keyPath, 'utf8');
    } catch (err) {
      const error = new Error('User private key is not available');
      error.code = 'KEY_MISSING';
      throw error;
    }

    try {
      certPem = fs.readFileSync(certPath, 'utf8');
    } catch (err) {
      const error = new Error('User certificate is not available');
      error.code = 'CERT_MISSING';
      throw error;
    }

    const chainPems = [];
    if (this.ca?.paths?.cert && fs.existsSync(this.ca.paths.cert)) {
      try {
        chainPems.push(fs.readFileSync(this.ca.paths.cert, 'utf8'));
      } catch (err) {
        console.warn('Unable to read CA certificate for chain', err);
      }
    }

    return {
      user: currentUser,
      keyPem,
      certPem,
      chainPems,
      certificate: currentUser?.pki?.certificate || null
    };
  }

  async getRootCertificate({ format = 'der' } = {}) {
    await this.ensureReady();
    return this.#withLock(async () => {
      const pem = fs.readFileSync(this.ca.paths.cert, 'utf8');
      const stat = fs.statSync(this.ca.paths.cert);
      const normalized = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
      const der = Buffer.from(normalized, 'base64');
      const body = format === 'pem' ? Buffer.from(pem.endsWith('\n') ? pem : `${pem}\n`, 'utf8') : der;
      const contentType = format === 'pem'
        ? 'application/x-pem-file; charset=us-ascii'
        : 'application/pkix-cert';
      const disposition = format === 'pem'
        ? 'inline; filename="ca.pem"'
        : 'inline; filename="ca.crt"';
      return {
        body,
        contentType,
        cacheControl: this.#cacheControl('aia'),
        disposition,
        lastModified: stat.mtime.toUTCString()
      };
    });
  }

  async getCrl({ format = 'der' } = {}) {
    await this.ensureReady();
    return this.#withLock(async () => {
      await this.#exportUsersSnapshot();
      const latest = this.ca.latestCRL();
      const ensured = latest || this.ca.generateCRL({
        thisUpdate: new Date(),
        nextUpdate: new Date(Date.now() + this.crlNextUpdateSeconds * 1000)
      });
      const der = ensured.crlDer || (latest && latest.der);
      const pem = ensured.crlPem || (latest && latest.pem);
      const body = format === 'pem'
        ? Buffer.from((pem || '').endsWith('\n') ? (pem || '') : `${pem}\n`, 'utf8')
        : Buffer.from(der || []);
      return {
        body,
        contentType: 'application/pkix-crl',
        cacheControl: this.#cacheControl('crl')
      };
    });
  }

  async handleOcspRequest(rawBody) {
    await this.ensureReady();
    return this.#withLock(async () => {
      await this.#exportUsersSnapshot();
      try {
        const decoded = this.#decodeOcspBody(rawBody);
        const result = this.ca.buildOCSPResponse(decoded);
        const buffer = Buffer.isBuffer(result.der) ? result.der : Buffer.from(result.der);
        return {
          buffer,
          cacheControl: this.#cacheControl('ocsp'),
          status: result.status || 'successful',
          ok: !!result.ok
        };
      } finally {
        await this.#importUsersSnapshot();
      }
    });
  }

  async buildOcspError(status) {
    await this.ensureReady();
    const response = this.ca.buildOCSPErrorResponse(status || 'malformedRequest');
    const buffer = Buffer.isBuffer(response.der) ? response.der : Buffer.from(response.der);
    return {
      buffer,
      cacheControl: this.#cacheControl('ocsp'),
      status: response.status || status || 'malformedRequest',
      ok: false
    };
  }

  async revokeByEmail(email, { reason = 'unspecified', revokedAt = null } = {}) {
    if (!email || typeof email !== 'string') {
      throw new Error('email is required for certificate revocation');
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail) {
      throw new Error('email is required for certificate revocation');
    }

    const normalizedReason = typeof reason === 'string' && reason.trim()
      ? reason.trim()
      : 'unspecified';

    await this.ensureReady();
    return this.#withLock(async () => {
      await this.#exportUsersSnapshot();
      let revoked;
      try {
        revoked = this.ca.revokeByEmail(normalizedEmail, {
          reason: normalizedReason,
          revokedAt
        });
      } finally {
        await this.#importUsersSnapshot();
      }

      if (!Array.isArray(revoked) || revoked.length === 0) {
        const err = new Error('No active certificate found for the provided email');
        err.code = 'NOT_FOUND';
        throw err;
      }

      return revoked.map(entry => this.#prune({
        serial: entry.serialHex || null,
        email: entry.email || normalizedEmail,
        userId: entry.userId || null,
        revokedAt: entry.revokedAt || null,
        reason: entry.reason || normalizedReason,
        reasonCode: entry.reasonCode ?? null
      }));
    });
  }

  decodeOcspPathComponent(encoded) {
    if (!encoded) throw new Error('OCSP path segment empty');
    const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4;
    const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;
    return Buffer.from(padded, 'base64');
  }

  async health() {
    await this.ensureReady();
    const config = this.ca.getConfig();
    return {
      ok: true,
      generatedAt: new Date().toISOString(),
      rootExists: this.ca.rootExists(),
      services: {
        ocsp: config.services?.ocspUrl || null,
        crl: config.services?.crlUrl || null,
        caIssuers: config.services?.caIssuersUrl || null
      }
    };
  }

  #shouldRenew(user) {
    const cert = user?.pki?.certificate;
    if (!cert || !cert.serial) return true;
    if (cert.revokedAt) return true;
    if (cert.notAfter) {
      const expiry = Date.parse(cert.notAfter);
      if (!Number.isNaN(expiry)) {
        const remaining = expiry - Date.now();
        if (remaining <= (this.autoRenewThresholdDays || 0) * 86400e3) {
          return true;
        }
      }
    }
    return false;
  }

  async #resolveUser(userOrId) {
    if (!userOrId) return null;
    if (typeof userOrId === 'object' && userOrId.id) {
      return userOrId;
    }
    const id = typeof userOrId === 'string' || typeof userOrId === 'number'
      ? String(userOrId)
      : null;
    if (!id) return null;
    return this.db.findOne('users', { id });
  }

  async #exportUsersSnapshot() {
    const users = await this.db.find('users');
    const payload = users.map(user => this.#serializeForCa(user));
    await fsp.writeFile(this.usersFile, JSON.stringify(payload, null, 2));
    this.ca.setUsersFile(this.usersFile);
  }

  async #importUsersSnapshot() {
    let raw;
    try {
      raw = await fsp.readFile(this.usersFile, 'utf8');
    } catch {
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }
    if (!Array.isArray(parsed)) return;

    for (const entry of parsed) {
      if (!entry || !entry.id) continue;
      const existing = await this.db.findOne('users', { id: entry.id });
      if (!existing) continue;
      const nextPki = this.#buildPki(entry);
      if (this.#stableStringify(existing.pki || null) !== this.#stableStringify(nextPki)) {
        await this.db.update('users', existing.id, { pki: nextPki });
      }
    }
  }

  #serializeForCa(user) {
    const pki = this.#normalizePki(user?.pki);
    const subject = pki.subject && typeof pki.subject === 'object'
      ? Object.assign({}, pki.subject)
      : {};
    const record = {
      id: String(user.id),
      email: user.email || null,
      name: user.name || null,
      surname: user.surname || null,
      C: subject.C || null,
      ST: subject.ST || null,
      L: subject.L || null,
      O: subject.O || null,
      OU: subject.OU || null,
      CN: subject.CN || null,
      certificate: pki.certificate || null,
      revocations: pki.revocations || []
    };
    return this.#prune(record);
  }

  #buildPki(entry) {
    const certificate = entry.certificate && typeof entry.certificate === 'object'
      ? Object.assign({}, entry.certificate)
      : null;
    if (certificate && certificate.serial) {
      certificate.serial = this.#sanitizeHex(certificate.serial);
    }
    const revocations = Array.isArray(entry.revocations)
      ? entry.revocations
        .map(item => {
          if (!item || typeof item !== 'object') return null;
          const serial = this.#sanitizeHex(item.serial);
          if (!serial) return null;
          return this.#prune({
            serial,
            revokedAt: this.#normalizeDate(item.revokedAt),
            reason: item.reason || null
          });
        })
        .filter(Boolean)
      : [];

    return this.#prune({
      certificate: certificate ? this.#prune(certificate) : null,
      revocations,
      subject: null
    });
  }

  #normalizePki(value) {
    if (!value || typeof value !== 'object') {
      return { certificate: null, revocations: [], subject: null };
    }
    const certificate = value.certificate && typeof value.certificate === 'object'
      ? Object.assign({}, value.certificate)
      : null;
    if (certificate && certificate.serial) {
      certificate.serial = this.#sanitizeHex(certificate.serial);
    }
    const revocations = Array.isArray(value.revocations)
      ? value.revocations.filter(Boolean).map(item => Object.assign({}, item))
      : [];
    return {
      certificate: certificate ? this.#prune(certificate) : null,
      revocations,
      subject: null
    };
  }

  #toCaUserInput(user) {
    const pki = this.#normalizePki(user.pki);
    const subject = pki.subject && typeof pki.subject === 'object'
      ? Object.assign({}, pki.subject)
      : {};
    const input = {
      id: String(user.id),
      email: user.email || null,
      name: user.name || null,
      surname: user.surname || null,
      C: subject.C || null,
      ST: subject.ST || null,
      L: subject.L || null,
      O: subject.O || null,
      OU: subject.OU || null,
      CN: subject.CN || null
    };
    return this.#prune(input);
  }

  #decodeOcspBody(body) {
    if (!body) throw new Error('Boş OCSP isteği');
    const buffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
    let binaryScore = 0;
    for (const byte of buffer) {
      if (byte === 9 || byte === 10 || byte === 13) continue;
      if (byte < 32 || byte > 126) {
        binaryScore++;
        if (binaryScore > 4) break;
      }
    }
    if (binaryScore > 4) return buffer;
    const text = buffer.toString('utf8').trim();
    if (!text) throw new Error('OCSP isteği çözülemedi');
    const sanitized = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = sanitized.length % 4;
    const padded = pad ? sanitized + '='.repeat(4 - pad) : sanitized;
    return Buffer.from(padded, 'base64');
  }

  #cacheControl(type) {
    if (type === 'crl') {
      return `public, max-age=${this.crlNextUpdateSeconds}, must-revalidate`;
    }
    if (type === 'ocsp') {
      return `public, max-age=${this.ocspNextUpdateSeconds}`;
    }
    if (type === 'aia') {
      return 'public, max-age=604800, immutable';
    }
    return 'no-cache';
  }

  #sanitizeHex(value) {
    if (value === null || value === undefined) return null;
    let hex = String(value).trim().toLowerCase().replace(/[^0-9a-f]/g, '');
    if (!hex) return null;
    hex = hex.replace(/^0+(?=[0-9a-f])/, '');
    return hex || '0';
  }

  #normalizeDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? null : date.toISOString();
  }

  #prune(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const out = {};
    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined || value === '') continue;
      if (Array.isArray(value)) {
        const filtered = value.map(item => this.#prune(item)).filter(item => item !== null && item !== undefined);
        if (filtered.length) out[key] = filtered;
        continue;
      }
      out[key] = value;
    }
    return out;
  }

  #stableStringify(value) {
    const seen = new WeakSet();
    const replacer = (_key, val) => {
      if (val && typeof val === 'object') {
        if (seen.has(val)) return undefined;
        seen.add(val);
        if (Array.isArray(val)) {
          return val.map(item => replacer('', item));
        }
        return Object.keys(val)
          .sort()
          .reduce((acc, key) => {
            acc[key] = replacer('', val[key]);
            return acc;
          }, {});
      }
      return val;
    };
    return JSON.stringify(replacer('', value));
  }

  async #withLock(fn) {
    while (this._lockPromise) {
      try {
        await this._lockPromise;
      } catch {
        // ignore
      }
    }
    let release;
    this._lockPromise = new Promise(resolve => {
      release = resolve;
    });
    try {
      return await fn();
    } finally {
      release();
      this._lockPromise = null;
    }
  }
}

module.exports = { CertificateAuthorityService };
