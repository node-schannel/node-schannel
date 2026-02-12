'use strict';

const path = require('path');

let native;
try {
  native = require('./build/Release/schannels.node');
} catch (e) {
  try {
    native = require('./build/Debug/schannels.node');
  } catch (e2) {
    throw new Error(
      'node-schannels: Failed to load native addon. ' +
      'Ensure you have run "npm install" or "node-gyp rebuild". ' +
      'This module only works on Windows.\n' +
      'Original error: ' + e.message
    );
  }
}

const { SchannelSocket, listCertificates } = native;

module.exports = { SchannelSocket, listCertificates };
