'use strict';

const crypto = require('crypto');

class SessionService {
  constructor({ ttlSeconds = 3600, cleanupIntervalMs = 10 * 60 * 1000 } = {}) {
    this.ttlSeconds = ttlSeconds;
    this.sessions = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs).unref();
  }

  createSession(payload) {
    const sid = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + this.ttlSeconds * 1000;
    this.sessions.set(sid, { ...payload, createdAt: Date.now(), expiresAt });
    return { id: sid, expiresAt };
  }

  getSession(id) {
    if (!id) return null;
    const entry = this.sessions.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.sessions.delete(id);
      return null;
    }
    return entry;
  }

  touchSession(id, extendSeconds) {
    const entry = this.sessions.get(id);
    if (!entry) return false;
    const ttl = typeof extendSeconds === 'number' ? extendSeconds : this.ttlSeconds;
    entry.expiresAt = Date.now() + ttl * 1000;
    entry.lastTouchedAt = Date.now();
    this.sessions.set(id, entry);
    return true;
  }

  deleteSession(id) {
    if (!id) return false;
    return this.sessions.delete(id);
  }

  cleanup() {
    const now = Date.now();
    for (const [sid, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(sid);
      }
    }
  }
}

module.exports = { SessionService };
