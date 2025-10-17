'use strict';

const assert = require('assert');
const path = require('path');

const config = require('../config');
const { createAppContext, createHttpService, registerCoreRoutes, shutdownAppContext } = require('../src/app/bootstrap');

module.exports = async function runAppSmoke() {
  const context = await createAppContext(config, {
    logger: console,
    publicDir: path.join(__dirname, '..', 'public'),
    skipEmail: true,
    skipWebPush: true,
  });

  const http = createHttpService(context, {
    publicDir: context.publicDir,
    maxRequestsPerMinute: 100,
  });

  await registerCoreRoutes(http, context, {
    registerViews: false,
    enableWebPush: false,
  });

  assert.ok(Array.isArray(http.routes) && http.routes.length > 0, 'Expected HTTP routes to be registered');

  await shutdownAppContext(context);
};
