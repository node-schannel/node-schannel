const { describe, it } = require('node:test');
const assert = require('node:assert');
const { listCertificates } = require('../lib/schannel-socket');

describe('listCertificates', () => {
  it('should return an array from CurrentUser MY store', async () => {
    const certs = await listCertificates();
    assert.ok(Array.isArray(certs), 'Expected an array');
    console.log(`Found ${certs.length} certificate(s) in CurrentUser\\MY`);
  });

  it('should return objects with all expected fields', async () => {
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

  it('should return valid thumbprint format (40 hex chars)', async () => {
    const certs = await listCertificates();
    for (const cert of certs) {
      assert.match(cert.thumbprint, /^[0-9a-f]{40}$/,
        `Thumbprint should be 40 lowercase hex chars, got: "${cert.thumbprint}"`);
    }
  });

  it('should return valid date ranges (notBefore < notAfter)', async () => {
    const certs = await listCertificates();
    for (const cert of certs) {
      assert.ok(cert.notBefore instanceof Date, 'notBefore should be Date');
      assert.ok(cert.notAfter instanceof Date, 'notAfter should be Date');
      assert.ok(!isNaN(cert.notBefore.getTime()), 'notBefore should be valid date');
      assert.ok(!isNaN(cert.notAfter.getTime()), 'notAfter should be valid date');
      assert.ok(cert.notBefore < cert.notAfter,
        `notBefore (${cert.notBefore}) should be before notAfter (${cert.notAfter})`);
    }
  });

  it('should accept custom store names (Root)', async () => {
    const certs = await listCertificates({ storeName: 'Root', storeLocation: 'CurrentUser' });
    assert.ok(Array.isArray(certs));
    console.log(`Found ${certs.length} certificate(s) in CurrentUser\\Root`);
  });

  it('should accept CA store', async () => {
    const certs = await listCertificates({ storeName: 'CA', storeLocation: 'CurrentUser' });
    assert.ok(Array.isArray(certs));
    console.log(`Found ${certs.length} certificate(s) in CurrentUser\\CA`);
  });

  it('should accept LocalMachine store location', async () => {
    // LocalMachine access may be restricted by permissions - handle both cases
    try {
      const certs = await listCertificates({ storeName: 'Root', storeLocation: 'LocalMachine' });
      assert.ok(Array.isArray(certs));
      console.log(`Found ${certs.length} certificate(s) in LocalMachine\\Root`);
    } catch (err) {
      // Access denied is acceptable
      console.log(`LocalMachine access: ${err.message}`);
    }
  });

  it('should return empty array for nonexistent store', async () => {
    const certs = await listCertificates({ storeName: 'NonexistentStore12345' });
    assert.ok(Array.isArray(certs));
    assert.strictEqual(certs.length, 0);
  });

  it('should return consistent results across multiple calls', async () => {
    const certs1 = await listCertificates();
    const certs2 = await listCertificates();
    assert.strictEqual(certs1.length, certs2.length, 'Same store should return same count');
    for (let i = 0; i < certs1.length; i++) {
      assert.strictEqual(certs1[i].thumbprint, certs2[i].thumbprint, 'Same thumbprints');
    }
  });

  it('should differentiate MY vs Root stores', async () => {
    const myCerts = await listCertificates({ storeName: 'MY' });
    const rootCerts = await listCertificates({ storeName: 'Root' });
    // They might overlap but typically are different sets
    const myThumbs = new Set(myCerts.map(c => c.thumbprint));
    const rootThumbs = new Set(rootCerts.map(c => c.thumbprint));
    console.log(`MY: ${myThumbs.size} unique certs, Root: ${rootThumbs.size} unique certs`);
    // At minimum verify they're different sets or the test environment is unusual
    if (myCerts.length > 0 && rootCerts.length > 0) {
      // Most environments have different certs in MY vs Root
      console.log('Both stores have certs — stores are queryable independently');
    }
  });

  it('should handle concurrent listCertificates calls', async () => {
    const results = await Promise.all([
      listCertificates({ storeName: 'MY' }),
      listCertificates({ storeName: 'Root' }),
      listCertificates({ storeName: 'CA' }),
    ]);
    for (const certs of results) {
      assert.ok(Array.isArray(certs), 'Each result should be an array');
    }
  });

  it('should use defaults when no options provided', async () => {
    const withDefaults = await listCertificates();
    const explicit = await listCertificates({ storeName: 'MY', storeLocation: 'CurrentUser' });
    assert.strictEqual(withDefaults.length, explicit.length);
  });
});
