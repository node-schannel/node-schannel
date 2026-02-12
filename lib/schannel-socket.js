'use strict';

const native = require('../index');

/**
 * @typedef {Object} ConnectOptions
 * @property {string} host - Hostname or IP to connect to
 * @property {number} port - TCP port
 * @property {string} [certSubject] - Find client cert by subject (substring match)
 * @property {string} [certThumbprint] - Find client cert by SHA-1 thumbprint (hex)
 * @property {string} [storeName='MY'] - Certificate store name
 * @property {string} [storeLocation='CurrentUser'] - 'CurrentUser' or 'LocalMachine'
 * @property {string} [serverName] - SNI / cert validation target (defaults to host)
 */

/**
 * @typedef {Object} ConnectionInfo
 * @property {string} protocol - Negotiated TLS version
 * @property {string} cipher - Negotiated cipher
 * @property {string} serverCertSubject - Server certificate subject
 * @property {boolean} mutualAuth - Whether mTLS was negotiated
 */

/**
 * @typedef {Object} CertInfo
 * @property {string} subject
 * @property {string} issuer
 * @property {string} thumbprint
 * @property {boolean} hasPrivateKey
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {string} friendlyName
 */

class SchannelSocketWrapper {
  constructor() {
    this._native = new native.SchannelSocket();
  }

  /**
   * @param {ConnectOptions} options
   * @returns {Promise<ConnectionInfo>}
   */
  async connect(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('connect() requires an options object');
    }
    if (!options.host || typeof options.host !== 'string') {
      throw new TypeError("'host' must be a non-empty string");
    }
    if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
      throw new TypeError("'port' must be an integer between 1 and 65535");
    }

    const opts = {
      host: options.host,
      port: options.port,
      serverName: options.serverName || '',
      certSubject: options.certSubject || '',
      certThumbprint: options.certThumbprint || '',
      storeName: options.storeName || 'MY',
      storeLocation: options.storeLocation || 'CurrentUser',
    };

    return this._native.connect(opts);
  }

  /**
   * @param {Buffer} buffer
   * @returns {Promise<number>}
   */
  async write(buffer) {
    if (!Buffer.isBuffer(buffer)) {
      if (typeof buffer === 'string') {
        buffer = Buffer.from(buffer);
      } else {
        throw new TypeError('write() requires a Buffer or string argument');
      }
    }
    return this._native.write(buffer);
  }

  /**
   * @returns {Promise<Buffer|null>}
   */
  async read() {
    return this._native.read();
  }

  /**
   * @returns {Promise<void>}
   */
  async close() {
    return this._native.close();
  }

  /**
   * @returns {boolean}
   */
  get connected() {
    return this._native.connected;
  }

  /**
   * Read all remaining data until connection closes.
   * @returns {Promise<Buffer>}
   */
  async readAll() {
    const chunks = [];
    let chunk;
    while ((chunk = await this.read()) !== null) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
}

/**
 * @param {Object} [options]
 * @param {string} [options.storeName='MY']
 * @param {string} [options.storeLocation='CurrentUser']
 * @returns {Promise<CertInfo[]>}
 */
async function listCertificates(options) {
  const opts = {
    storeName: (options && options.storeName) || 'MY',
    storeLocation: (options && options.storeLocation) || 'CurrentUser',
  };
  return native.listCertificates(opts);
}

module.exports = {
  SchannelSocket: SchannelSocketWrapper,
  listCertificates,
};
