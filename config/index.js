'use strict';

const microsoft = require('./microsoft');
const security = require('./security');
const email = require('./email');
const pki = require('./pki');
const webpush = require('./webpush');

module.exports = {
  microsoft,
  security,
  email,
  pki,
  webpush
};
