'use strict';

const fsp = require('fs').promises;
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

class WebPushService {
  constructor(options = {}) {
    this.dataDir = options.dataDir || path.join(process.cwd(), 'data', 'webpush');
    this.vapidPrivatePath = path.join(this.dataDir, 'vapid_priv.pem');
    this.vapidPublicJwkPath = path.join(this.dataDir, 'vapid_pub.jwk.json');
    this.subscriptionsPath = path.join(this.dataDir, 'subscriptions.json');

    this.rateLimitWindowMs = Number.isFinite(options.rateLimitWindowMs)
      ? options.rateLimitWindowMs
      : 60 * 1000;
    this.rateLimitMax = Number.isFinite(options.rateLimitMax)
      ? options.rateLimitMax
      : 30;
    this.defaultTtl = Number.isFinite(options.defaultTtl)
      ? options.defaultTtl
      : 2419200;
    this.subject = typeof options.subject === 'string' && options.subject.trim()
      ? options.subject.trim()
      : 'mailto:network@fitfak.net';

    this.subscriptions = [];
    this.rateMap = new Map();
    this.vapid = null;
  }

  async init() {
    await fsp.mkdir(this.dataDir, { recursive: true });
    await this.#ensureVapid();
    await this.#loadSubscriptions();
  }

  async #ensureVapid() {
    if (this.vapid) return this.vapid;
    try {
      const [privPem, pubRaw] = await Promise.all([
        fsp.readFile(this.vapidPrivatePath, 'utf8'),
        fsp.readFile(this.vapidPublicJwkPath, 'utf8')
      ]);
      const publicKeyJwk = JSON.parse(pubRaw);
      this.vapid = { privateKeyPem: privPem, publicKeyJwk };
      return this.vapid;
    } catch (err) {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
      const publicKeyJwk = publicKey.export({ format: 'jwk' });
      await Promise.all([
        this.#writeAtomic(this.vapidPrivatePath, privateKeyPem),
        this.#writeAtomic(this.vapidPublicJwkPath, JSON.stringify(publicKeyJwk, null, 2))
      ]);
      this.vapid = { privateKeyPem, publicKeyJwk };
      return this.vapid;
    }
  }

  async #loadSubscriptions() {
    try {
      const raw = await fsp.readFile(this.subscriptionsPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this.subscriptions = parsed.filter((entry) => this.#isValidSubscription(entry));
      }
    } catch (err) {
      this.subscriptions = [];
    }
  }

  async #writeAtomic(filePath, payload) {
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmpPath, payload, typeof payload === 'string' ? 'utf8' : undefined);
    await fsp.rename(tmpPath, filePath);
  }

  async #saveSubscriptions() {
    await this.#writeAtomic(this.subscriptionsPath, JSON.stringify(this.subscriptions, null, 2));
  }

  #isValidSubscription(value) {
    if (!value || typeof value !== 'object') return false;
    if (typeof value.endpoint !== 'string' || !value.endpoint.trim()) return false;
    if (!value.keys || typeof value.keys !== 'object') return false;
    const { p256dh, auth } = value.keys;
    if (typeof p256dh !== 'string' || typeof auth !== 'string') return false;
    return true;
  }

  base64url(buffer) {
    return Buffer.from(buffer).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  base64urlToBuffer(str) {
    const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4;
    const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;
    return Buffer.from(padded, 'base64');
  }

  #parseKeyFlex(str) {
    if (typeof str !== 'string') throw new Error('subscription key must be a string');
    const trimmed = str.trim();
    if (!trimmed) throw new Error('subscription key cannot be empty');
    if (/[\-_]/.test(trimmed)) {
      return this.base64urlToBuffer(trimmed);
    }
    return Buffer.from(trimmed, 'base64');
  }

  #ensureUncompressedPoint(buffer) {
    const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
    if (buf.length === 65 && buf[0] === 0x04) return buf;
    if (buf.length === 64) return Buffer.concat([Buffer.from([0x04]), buf]);
    throw new Error(`public key is not a valid P-256 point (len=${buf.length})`);
  }

  #hmacSha256(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest();
  }

  #hkdfExtract(salt, ikm) {
    return this.#hmacSha256(salt, ikm);
  }

  #hkdfExpand(prk, info) {
    return this.#hmacSha256(prk, Buffer.concat([info, Buffer.from([0x01])]));
  }

  async getPublicKey() {
    const vapid = await this.#ensureVapid();
    const publicKeyUint8 = this.#jwkToPublicKeyBytes(vapid.publicKeyJwk);
    return this.base64url(publicKeyUint8);
  }

  #jwkToPublicKeyBytes(jwk) {
    const x = this.base64urlToBuffer(jwk.x);
    const y = this.base64urlToBuffer(jwk.y);
    return this.#ensureUncompressedPoint(Buffer.concat([Buffer.from([0x04]), x, y]));
  }

  checkRateLimit(ip) {
    if (!ip) return true;
    const now = Date.now();
    const entry = this.rateMap.get(ip) || { windowStart: now, count: 0 };
    if (now - entry.windowStart > this.rateLimitWindowMs) {
      entry.windowStart = now;
      entry.count = 0;
    }
    entry.count += 1;
    this.rateMap.set(ip, entry);
    return entry.count <= this.rateLimitMax;
  }

  async subscribe(subscription) {
    if (!this.#isValidSubscription(subscription)) {
      throw new Error('Invalid subscription payload');
    }
    const exists = this.subscriptions.find((item) => item.endpoint === subscription.endpoint);
    if (exists) {
      return { created: false };
    }
    this.subscriptions.push({
      endpoint: subscription.endpoint,
      keys: {
        p256dh: subscription.keys.p256dh,
        auth: subscription.keys.auth
      }
    });
    await this.#saveSubscriptions();
    return { created: true };
  }

  async unsubscribe(endpoint) {
    if (typeof endpoint !== 'string') return false;
    const before = this.subscriptions.length;
    this.subscriptions = this.subscriptions.filter((item) => item.endpoint !== endpoint);
    if (this.subscriptions.length !== before) {
      await this.#saveSubscriptions();
      return true;
    }
    return false;
  }

  async sendToAll(message = {}, options = {}) {
    const vapid = await this.#ensureVapid();
    const payloadBuffer = Buffer.from(JSON.stringify(message), 'utf8');
    const ttl = Number.isFinite(options.ttl) ? options.ttl : this.defaultTtl;
    const subject = typeof options.subject === 'string' && options.subject.trim()
      ? options.subject.trim()
      : this.subject;

    const results = [];
    let mutated = false;

    for (let i = this.subscriptions.length - 1; i >= 0; i -= 1) {
      const sub = this.subscriptions[i];
      try {
        const response = await this.#sendNotification(sub, payloadBuffer, { ttl, subject, vapid });
        results.push(Object.assign({ endpoint: sub.endpoint }, response));
        if (response.statusCode === 404 || response.statusCode === 410) {
          this.subscriptions.splice(i, 1);
          mutated = true;
        }
      } catch (err) {
        results.push({ endpoint: sub.endpoint, error: err.message || String(err) });
      }
    }

    if (mutated) {
      await this.#saveSubscriptions();
    }

    return results;
  }

  async #sendNotification(subscription, payloadBuffer, { ttl, subject, vapid }) {
    const endpointUrl = new URL(subscription.endpoint);
    const isHttps = endpointUrl.protocol === 'https:';
    const transport = isHttps ? https : http;
    const port = endpointUrl.port
      ? parseInt(endpointUrl.port, 10)
      : (isHttps ? 443 : 80);

    const salt = crypto.randomBytes(16);
    const ecdh = crypto.createECDH('prime256v1');
    const asPublic = this.#ensureUncompressedPoint(ecdh.generateKeys());
    const uaPublic = this.#ensureUncompressedPoint(this.#parseKeyFlex(subscription.keys.p256dh));
    const authSecret = this.#parseKeyFlex(subscription.keys.auth);

    const sharedSecret = ecdh.computeSecret(uaPublic);
    const prkKey = this.#hkdfExtract(authSecret, sharedSecret);

    const keyInfo = Buffer.concat([
      Buffer.from('WebPush: info', 'ascii'),
      Buffer.from([0x00]),
      uaPublic,
      asPublic
    ]);
    const ikm = this.#hkdfExpand(prkKey, keyInfo);

    const prk = this.#hkdfExtract(salt, ikm);
    const cekInfo = Buffer.concat([Buffer.from('Content-Encoding: aes128gcm', 'ascii'), Buffer.from([0x00])]);
    const nonceInfo = Buffer.concat([Buffer.from('Content-Encoding: nonce', 'ascii'), Buffer.from([0x00])]);

    const cekFull = this.#hkdfExpand(prk, cekInfo);
    const cek = cekFull.slice(0, 16);
    const nonceFull = this.#hkdfExpand(prk, nonceInfo);
    const nonce = nonceFull.slice(0, 12);

    const paddedPlaintext = Buffer.concat([payloadBuffer, Buffer.from([0x02])]);
    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const encrypted = Buffer.concat([cipher.update(paddedPlaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const cipherBody = Buffer.concat([encrypted, authTag]);

    const rs = 4096;
    const rsBuf = Buffer.alloc(4);
    rsBuf.writeUInt32BE(rs, 0);
    const idLen = Buffer.from([asPublic.length]);
    const headerBlock = Buffer.concat([salt, rsBuf, idLen, asPublic]);
    const body = Buffer.concat([headerBlock, cipherBody]);

    const audience = `${endpointUrl.protocol}//${endpointUrl.host}`;
    const { jwt, publicKeyJwk } = this.#createVapidJwt(audience, subject, ttl, vapid);
    const vapidPubBytes = this.#jwkToPublicKeyBytes(publicKeyJwk);

    const baseHeaders = {
      'Content-Encoding': 'aes128gcm',
      'Content-Length': String(body.length),
      TTL: String(ttl),
      Encryption: `salt=${this.base64url(salt)}`,
      'Crypto-Key': `dh=${this.base64url(asPublic)}; p256ecdsa=${this.base64url(vapidPubBytes)}`
    };

    const authHeaders = [
      Object.assign({ Authorization: `WebPush ${jwt}` }, baseHeaders),
      Object.assign({ Authorization: `vapid t=${jwt}, k=${this.base64url(vapidPubBytes)}` }, baseHeaders)
    ];

    const pathWithQuery = `${endpointUrl.pathname || ''}${endpointUrl.search || ''}` || '/';

    const attempts = [];

    for (const headers of authHeaders) {
      const requestOptions = {
        method: 'POST',
        hostname: endpointUrl.hostname,
        port,
        path: pathWithQuery,
        headers
      };

      try {
        const response = await new Promise((resolve, reject) => {
          const req = transport.request(requestOptions, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
              resolve({
                statusCode: res.statusCode || 0,
                body: Buffer.concat(chunks).toString('utf8'),
                headers: res.headers,
                usedAuth: headers.Authorization
              });
            });
          });
          req.on('error', reject);
          req.write(body);
          req.end();
        });

        attempts.push(response);
        if (response.statusCode >= 200 && response.statusCode < 300) {
          return Object.assign(response, { attempts });
        }
        if (response.statusCode === 401 || response.statusCode === 403) {
          continue;
        }
        return Object.assign(response, { attempts });
      } catch (err) {
        return { error: err.message || String(err), attempts, usedAuth: headers.Authorization };
      }
    }

    return { statusCode: 401, body: 'authorization rejected', attempts };
  }

  #createVapidJwt(audience, subject, ttl, vapid) {
    const { privateKeyPem, publicKeyJwk } = vapid;
    const header = { alg: 'ES256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = { aud: audience, exp: now + ttl, sub: subject };
    const encoder = (value) => this.base64url(Buffer.from(JSON.stringify(value)));
    const signingInput = `${encoder(header)}.${encoder(payload)}`;
    const signature = crypto.createSign('SHA256')
      .update(signingInput)
      .sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' });
    const jwt = `${signingInput}.${this.base64url(signature)}`;
    return { jwt, publicKeyJwk };
  }
}

module.exports = { WebPushService };
