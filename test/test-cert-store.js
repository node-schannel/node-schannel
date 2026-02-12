const { describe, it } = require('node:test');
const assert = require('node:assert');
const { listCertificates } = require('../lib/schannel-socket');

describe('listCertificates', () => {
  it('should return an array from CurrentUser MY store', async () => {
    const certs = await listCertificates();
    assert.ok(Array.isArray(certs), 'Expected an array');
    console.log(`Found ${certs.length} certificate(s) in CurrentUser\\MY`);
  });

  it('should return objects with expected fields', async () => {
    const certs = await listCertificates();
    if (certs.length === 0) {
      console.log('  (no certs to validate — skipping field check)');
      return;
    }
    const cert = certs[0];
    assert.ok(typeof cert.subject === 'string', 'subject should be a string');
    assert.ok(typeof cert.issuer === 'string', 'issuer should be a string');
    assert.ok(typeof cert.thumbprint === 'string', 'thumbprint should be a string');
    assert.ok(typeof cert.hasPrivateKey === 'boolean', 'hasPrivateKey should be boolean');
    assert.ok(cert.notBefore instanceof Date, 'notBefore should be a Date');
    assert.ok(cert.notAfter instanceof Date, 'notAfter should be a Date');
    assert.ok(typeof cert.friendlyName === 'string', 'friendlyName should be a string');
    console.log(`  First cert: ${cert.subject} [${cert.thumbprint.substring(0, 8)}...]`);
  });

  it('should accept custom store names', async () => {
    const certs = await listCertificates({ storeName: 'Root', storeLocation: 'CurrentUser' });
    assert.ok(Array.isArray(certs));
    console.log(`Found ${certs.length} certificate(s) in CurrentUser\\Root`);
  });

  it('should return empty array for nonexistent store', async () => {
    const certs = await listCertificates({ storeName: 'NonexistentStore12345' });
    assert.ok(Array.isArray(certs));
    assert.strictEqual(certs.length, 0);
  });
});
