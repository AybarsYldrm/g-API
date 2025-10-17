#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const runAppSmoke = require('../tests/app-smoke');

const requiredFiles = [
  path.join(__dirname, '..', 'server.js'),
  path.join(__dirname, '..', 'public', 'views', 'index.html'),
  path.join(__dirname, '..', 'public', 'views', 'dashboard.html')
];

(async () => {
  try {
    for (const file of requiredFiles) {
      if (!fs.existsSync(file)) {
        throw new Error(`Missing required file: ${file}`);
      }
    }

    if (typeof runAppSmoke === 'function') {
      await runAppSmoke();
    }

    console.log('Static checks passed.');
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
})();
