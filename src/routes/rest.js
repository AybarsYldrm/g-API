'use strict';

const { sanitizeUser, ensureOwnership } = require('../utils/security');

module.exports = function registerRestRoutes(http, { db }) {
  http.addRoute('GET', '/api/health', (req, res, send) => {
    return send(200, { status: 'ok', timestamp: new Date().toISOString() });
  });

  http.addRoute('GET', '/api/me', async (req, res, send) => {
    return send(200, { user: sanitizeUser(req.user) });
  }, { auth: true });

  http.addRoute('GET', '/api/events', async (req, res, send) => {
    const events = await db.find('events', { ownerId: req.user.id });
    return send(200, { events });
  }, { auth: true });

  http.addRoute('GET', '/api/events/:id', async (req, res, send) => {
    const event = await db.findOne('events', { id: req.params.id });
    if (!event) return send(404, { success: false, message: 'Event not found' });
    try {
      ensureOwnership(req.user, event.ownerId);
    } catch (err) {
      return send(err.statusCode || 403, { success: false, message: err.message });
    }
    return send(200, { event });
  }, { auth: true });

  http.addRoute('POST', '/api/events', async (req, res, send) => {
    const input = req.body || {};
    if (!input.title) return send(400, { success: false, message: 'title is required' });
    if (!input.startsAt || !input.endsAt) {
      return send(400, { success: false, message: 'startsAt and endsAt are required' });
    }
    if (input.tags && !Array.isArray(input.tags)) {
      return send(400, { success: false, message: 'tags must be an array' });
    }
    const created = await db.insert('events', {
      title: input.title,
      startsAt: input.startsAt,
      endsAt: input.endsAt,
      location: input.location || null,
      tags: input.tags || [],
      ownerId: req.user.id
    });
    return send(201, { event: created });
  }, { auth: true });

  http.addRoute('PUT', '/api/events/:id', async (req, res, send) => {
    const existing = await db.findOne('events', { id: req.params.id });
    if (!existing) return send(404, { success: false, message: 'Event not found' });
    try {
      ensureOwnership(req.user, existing.ownerId);
    } catch (err) {
      return send(err.statusCode || 403, { success: false, message: err.message });
    }

    const input = req.body || {};
    if (input.tags !== undefined && !Array.isArray(input.tags)) {
      return send(400, { success: false, message: 'tags must be an array' });
    }

    const patch = {};
    if (input.title !== undefined) patch.title = input.title;
    if (input.startsAt !== undefined) patch.startsAt = input.startsAt;
    if (input.endsAt !== undefined) patch.endsAt = input.endsAt;
    if (input.location !== undefined) patch.location = input.location;
    if (input.tags !== undefined) patch.tags = input.tags;

    const updated = await db.update('events', existing.id, patch);
    return send(200, { event: updated });
  }, { auth: true });

  http.addRoute('DELETE', '/api/events/:id', async (req, res, send) => {
    const existing = await db.findOne('events', { id: req.params.id });
    if (!existing) return send(404, { success: false, message: 'Event not found' });
    try {
      ensureOwnership(req.user, existing.ownerId);
    } catch (err) {
      return send(err.statusCode || 403, { success: false, message: err.message });
    }
    await db.remove('events', existing.id);
    return send(200, { success: true });
  }, { auth: true });
};
