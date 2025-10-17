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

    this.db = options.db || null;
    this.collection = options.collection || 'webpushSubscriptions';

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
    this.subscriptionIndex = new Map();
    this.rateMap = new Map();
    this.vapid = null;
  }

  async init() {
    await fsp.mkdir(this.dataDir, { recursive: true });
    await this.#ensureVapid();
    if (this.db) await this.#loadSubscriptionsFromDb();
    else await this.#loadSubscriptionsFromFile();
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

  async #loadSubscriptionsFromFile() {
    try {
      const raw = await fsp.readFile(this.subscriptionsPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this.subscriptions = parsed
          .filter((entry) => this.#isValidStoredSubscription(entry))
          .map((entry) => ({
            id: entry.id || null,
            ownerId: entry.ownerId,
            endpoint: entry.endpoint,
            keys: entry.keys,
            userAgent: entry.userAgent || null,
            createdAt: entry.createdAt || null,
            updatedAt: entry.updatedAt || null,
            lastSentAt: entry.lastSentAt || null,
          }));
      } else {
        this.subscriptions = [];
      }
    } catch (err) {
      this.subscriptions = [];
    }
    this.#rebuildIndex();
  }

  async #loadSubscriptionsFromDb() {
    try {
      const docs = await this.db.find(this.collection, {});
      this.subscriptions = docs.map((doc) => this.#fromDbDoc(doc));
    } catch (err) {
      console.warn('Failed to load web push subscriptions from database', err);
      this.subscriptions = [];
    }
    this.#rebuildIndex();
  }

  async #writeAtomic(filePath, payload) {
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmpPath, payload, typeof payload === 'string' ? 'utf8' : undefined);
    await fsp.rename(tmpPath, filePath);
  }

  async #saveSubscriptions() {
    if (this.db) return;
    const payload = this.subscriptions.map((entry) => ({
      id: entry.id || null,
      ownerId: entry.ownerId,
      endpoint: entry.endpoint,
      keys: entry.keys,
      userAgent: entry.userAgent || null,
      createdAt: entry.createdAt || null,
      updatedAt: entry.updatedAt || null,
      lastSentAt: entry.lastSentAt || null,
    }));
    await this.#writeAtomic(this.subscriptionsPath, JSON.stringify(payload, null, 2));
  }

  #indexKey(ownerId, endpoint) {
    return `${ownerId}::${endpoint}`;
  }

  #rebuildIndex() {
    this.subscriptionIndex.clear();
    for (const entry of this.subscriptions) {
      if (!entry.ownerId || !entry.endpoint) continue;
      this.subscriptionIndex.set(this.#indexKey(entry.ownerId, entry.endpoint), entry);
    }
  }

  #fromDbDoc(doc) {
    return {
      id: doc.id,
      ownerId: doc.ownerId,
      endpoint: doc.endpoint,
      keys: doc.keys || {},
      userAgent: doc.userAgent || null,
      createdAt: doc.createdAt || null,
      updatedAt: doc.updatedAt || null,
      lastSentAt: doc.lastSentAt || null,
    };
  }

  #publicSubscription(entry) {
    return {
      id: entry.id || null,
      ownerId: entry.ownerId,
      endpoint: entry.endpoint,
      userAgent: entry.userAgent || null,
      createdAt: entry.createdAt || null,
      updatedAt: entry.updatedAt || null,
      lastSentAt: entry.lastSentAt || null,
    };
  }

  #isValidSubscriptionPayload(value) {
    if (!value || typeof value !== 'object') return false;
    if (typeof value.endpoint !== 'string' || !value.endpoint.trim()) return false;
    if (!value.keys || typeof value.keys !== 'object') return false;
    const { p256dh, auth } = value.keys;
    if (typeof p256dh !== 'string' || !p256dh.trim()) return false;
    if (typeof auth !== 'string' || !auth.trim()) return false;
    return true;
  }

  #isValidStoredSubscription(value) {
    if (!this.#isValidSubscriptionPayload(value)) return false;
    return typeof value.ownerId === 'string' && value.ownerId.trim().length > 0;
  }

  #normalizeSubscriptionPayload(subscription) {
    if (!this.#isValidSubscriptionPayload(subscription)) {
      throw new Error('Invalid subscription payload');
    }
    return {
      endpoint: subscription.endpoint.trim(),
      keys: {
        p256dh: subscription.keys.p256dh.trim(),
        auth: subscription.keys.auth.trim(),
      }
    };
  }

  async #upsertSubscription(entry) {
    if (!this.db) {
      await this.#saveSubscriptions();
      return entry;
    }

    if (entry.id) {
      const updated = await this.db.update(this.collection, entry.id, {
        ownerId: entry.ownerId,
        endpoint: entry.endpoint,
        keys: entry.keys,
        userAgent: entry.userAgent || null,
        lastSentAt: entry.lastSentAt || null,
      });
      if (updated) {
        entry.updatedAt = updated.updatedAt || entry.updatedAt;
        entry.createdAt = updated.createdAt || entry.createdAt;
        entry.lastSentAt = updated.lastSentAt || entry.lastSentAt;
      }
      return entry;
    }

    const inserted = await this.db.insert(this.collection, {
      ownerId: entry.ownerId,
      endpoint: entry.endpoint,
      keys: entry.keys,
      userAgent: entry.userAgent || null,
      lastSentAt: entry.lastSentAt || null,
    });
    entry.id = inserted.id;
    entry.createdAt = inserted.createdAt || entry.createdAt;
    entry.updatedAt = inserted.updatedAt || entry.updatedAt;
    entry.lastSentAt = inserted.lastSentAt || entry.lastSentAt;
    return entry;
  }

  async #removeFromStore(entry, { persist = true } = {}) {
    if (!entry) return;
    if (this.db) {
      if (entry.id) {
        try { await this.db.remove(this.collection, entry.id); } catch (err) { console.warn('Failed to remove subscription', err); }
      }
      return;
    }
    if (persist) await this.#saveSubscriptions();
  }

  #isValidSubscription(value) {
    return this.#isValidSubscriptionPayload(value);
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

  async subscribeForUser(user, subscription, { userAgent } = {}) {
    if (!user || !user.id) throw new Error('ownerId is required for subscription');
    if (this.db) {
      await this.#loadSubscriptionsFromDb();
    }
    const normalized = this.#normalizeSubscriptionPayload(subscription);
    const ownerId = String(user.id);
    const key = this.#indexKey(ownerId, normalized.endpoint);
    let entry = this.subscriptionIndex.get(key);
    const nowIso = new Date().toISOString();

    if (entry) {
      entry.keys = normalized.keys;
      entry.userAgent = userAgent || entry.userAgent || null;
      entry.updatedAt = nowIso;
      await this.#upsertSubscription(entry);
      return { created: false, subscription: this.#publicSubscription(entry) };
    }

    entry = {
      id: null,
      ownerId,
      endpoint: normalized.endpoint,
      keys: normalized.keys,
      userAgent: userAgent || null,
      createdAt: nowIso,
      updatedAt: nowIso,
      lastSentAt: null,
    };
    this.subscriptions.push(entry);
    this.subscriptionIndex.set(key, entry);
    await this.#upsertSubscription(entry);
    return { created: true, subscription: this.#publicSubscription(entry) };
  }

  async subscribe(subscription, context = {}) {
    const ownerId = context.ownerId || context.userId;
    if (!ownerId) throw new Error('ownerId is required for subscription');
    return this.subscribeForUser({ id: ownerId }, subscription, { userAgent: context.userAgent || null });
  }

  async unsubscribe(ownerId, identifier) {
    if (identifier === undefined) {
      identifier = ownerId;
      ownerId = null;
    }
    if (!ownerId) throw new Error('ownerId is required to unsubscribe');
    if (this.db) {
      await this.#loadSubscriptionsFromDb();
    }
    if (typeof identifier !== 'string' || !identifier.trim()) return false;
    const token = identifier.trim();
    const index = this.subscriptions.findIndex((sub) => sub.ownerId === ownerId && (sub.id === token || sub.endpoint === token));
    if (index === -1) return false;
    const [removed] = this.subscriptions.splice(index, 1);
    this.subscriptionIndex.delete(this.#indexKey(removed.ownerId, removed.endpoint));
    await this.#removeFromStore(removed);
    return true;
  }

  async listByOwner(ownerId) {
    if (!ownerId) return [];
    if (this.db) {
      const docs = await this.db.find(this.collection, { ownerId });
      return docs.map((doc) => this.#publicSubscription(this.#fromDbDoc(doc)));
    }
    return this.subscriptions
      .filter((sub) => sub.ownerId === ownerId)
      .map((sub) => this.#publicSubscription(sub));
  }

  async sendToAll(message = {}, options = {}) {
    if (this.db) {
      await this.#loadSubscriptionsFromDb();
    }

    const vapid = await this.#ensureVapid();
    const payloadBuffer = Buffer.from(JSON.stringify(message), 'utf8');
    const ttl = Number.isFinite(options.ttl) ? options.ttl : this.defaultTtl;
    const subject = typeof options.subject === 'string' && options.subject.trim()
      ? options.subject.trim()
      : this.subject;

    const results = [];
    const removed = [];
    const updatedLastSent = [];
    let filePersistNeeded = false;

    for (let i = this.subscriptions.length - 1; i >= 0; i -= 1) {
      const sub = this.subscriptions[i];
      try {
        const response = await this.#sendNotification(sub, payloadBuffer, { ttl, subject, vapid });
        results.push(Object.assign({ endpoint: sub.endpoint }, response));
        if (response.statusCode >= 200 && response.statusCode < 300) {
          const sentAt = new Date().toISOString();
          sub.lastSentAt = sentAt;
          updatedLastSent.push(sub);
        } else if (response.statusCode === 404 || response.statusCode === 410) {
          const [removedSub] = this.subscriptions.splice(i, 1);
          if (removedSub) {
            this.subscriptionIndex.delete(this.#indexKey(removedSub.ownerId, removedSub.endpoint));
            removed.push(removedSub);
            if (!this.db) filePersistNeeded = true;
          }
        }
      } catch (err) {
        results.push({ endpoint: sub.endpoint, error: err.message || String(err) });
      }
    }

    if (removed.length) {
      if (this.db) {
        await Promise.all(removed.map((entry) => this.#removeFromStore(entry)));
      }
    }

    if (updatedLastSent.length) {
      if (this.db) {
        await Promise.all(updatedLastSent.map((entry) => this.db.update(this.collection, entry.id, { lastSentAt: entry.lastSentAt })));
      } else {
        filePersistNeeded = true;
      }
    }

    if (filePersistNeeded && !this.db) {
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
