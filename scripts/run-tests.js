#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const requiredFiles = [
  path.join(__dirname, '..', 'server.js'),
  path.join(__dirname, '..', 'public', 'views', 'index.html'),
  path.join(__dirname, '..', 'public', 'views', 'dashboard.html')
];

for (const file of requiredFiles) {
  if (!fs.existsSync(file)) {
    console.error(`Missing required file: ${file}`);
    process.exit(1);
  }
}

console.log('Static checks passed.');
