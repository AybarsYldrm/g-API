'use strict';

const { sanitizeUser, ensureOwnership } = require('../utils/security');

const asEvent = (event) => ({ ...event, __type: 'Event' });

module.exports = ({ db }) => ({
  Query: {
    me: {
      auth: true,
      resolve: async (_, __, ctx) => sanitizeUser(ctx.user)
    },
    myEvents: {
      auth: true,
      resolve: async (_, __, ctx) => {
        const events = await db.find('events', { ownerId: ctx.user.id });
        return events.map(asEvent);
      }
    },
    event: {
      auth: true,
      resolve: async (_, args, ctx) => {
        if (!args || !args.id) throw new Error('id is required');
        const event = await db.findOne('events', { id: args.id });
        if (!event) return null;
        ensureOwnership(ctx.user, event.ownerId);
        return asEvent(event);
      }
    }
  },
  Mutation: {
    createEvent: {
      auth: true,
      resolve: async (_, args, ctx) => {
        const input = args && args.input;
        if (!input) throw new Error('input is required');
        if (!input.title) throw new Error('title is required');
        if (!input.startsAt || !input.endsAt) throw new Error('startsAt and endsAt are required');
        if (input.tags !== undefined && !Array.isArray(input.tags)) {
          throw new Error('tags must be an array');
        }

        const doc = await db.insert('events', {
          title: input.title,
          startsAt: input.startsAt,
          endsAt: input.endsAt,
          location: input.location || null,
          tags: Array.isArray(input.tags) ? input.tags : [],
          ownerId: ctx.user.id
        });
        return asEvent(doc);
      }
    },
    updateEvent: {
      auth: true,
      resolve: async (_, args, ctx) => {
        if (!args || !args.id) throw new Error('id is required');
        const input = args.input || {};
        const existing = await db.findOne('events', { id: args.id });
        if (!existing) throw new Error('Event not found');
        ensureOwnership(ctx.user, existing.ownerId);
        const patch = {};
        if (input.title !== undefined) patch.title = input.title;
        if (input.startsAt !== undefined) patch.startsAt = input.startsAt;
        if (input.endsAt !== undefined) patch.endsAt = input.endsAt;
        if (input.location !== undefined) patch.location = input.location;
        if (input.tags !== undefined) {
          if (!Array.isArray(input.tags)) throw new Error('tags must be an array');
          patch.tags = input.tags;
        }
        const updated = await db.update('events', existing.id, patch);
        return asEvent(updated);
      }
    },
    deleteEvent: {
      auth: true,
      resolve: async (_, args, ctx) => {
        if (!args || !args.id) throw new Error('id is required');
        const existing = await db.findOne('events', { id: args.id });
        if (!existing) throw new Error('Event not found');
        ensureOwnership(ctx.user, existing.ownerId);
        await db.remove('events', existing.id);
        return { success: true };
      }
    }
  },
  types: {
    Event: {
      owner: {
        auth: true,
        resolve: async (event, _, ctx) => {
          const user = await db.findOne('users', { id: event.ownerId });
          ensureOwnership(ctx.user, event.ownerId);
          return sanitizeUser(user);
        }
      }
    }
  }
});
