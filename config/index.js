'use strict';

const microsoft = require('./microsoft');
const security = require('./security');
const email = require('./email');
const pki = require('./pki');
const webpush = require('./webpush');
const pades = require('./pades');

module.exports = {
  microsoft,
  security,
  email,
  pki,
  webpush,
  pades
};
