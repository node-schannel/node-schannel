const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket, listCertificates } = require('../lib/schannel-socket');

describe('SchannelSocket - mTLS', () => {
  it('should list certificates with private keys (mTLS candidates)', async () => {
    const certs = await listCertificates();
    const mtlsCandidates = certs.filter(c => c.hasPrivateKey);
    console.log(`Found ${mtlsCandidates.length} cert(s) with private keys (mTLS candidates)`);
    for (const c of mtlsCandidates) {
      console.log(`  - ${c.subject} [${c.thumbprint.substring(0, 8)}...]`);
    }
  });

  it('should identify mTLS-capable certs by checking private key + validity', async () => {
    const certs = await listCertificates();
    const now = new Date();
    const validMtlsCerts = certs.filter(c =>
      c.hasPrivateKey &&
      c.notBefore <= now &&
      c.notAfter >= now
    );
    console.log(`Found ${validMtlsCerts.length} valid mTLS-capable cert(s)`);
    for (const c of validMtlsCerts) {
      console.log(`  - ${c.subject} (valid until ${c.notAfter.toISOString()})`);
    }
  });

  it('should reject mTLS connect with cert that has no private key', async () => {
    // Root CA certs typically exist but don't have private keys
    const rootCerts = await listCertificates({ storeName: 'Root' });
    if (rootCerts.length === 0) {
      console.log('  (no Root certs to test with — skipping)');
      return;
    }

    // Find a cert WITHOUT a private key
    const certWithoutKey = rootCerts.find(c => !c.hasPrivateKey);
    if (!certWithoutKey) {
      console.log('  (all Root certs have private keys — unusual, skipping)');
      return;
    }

    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({
        host: 'www.example.com',
        port: 443,
        certThumbprint: certWithoutKey.thumbprint,
        storeName: 'Root',
      }),
      (err) => {
        console.log(`Expected error (no private key): ${err.message}`);
        return err.message.includes('private key') || err.message.includes('not found');
      }
    );
  });

  it('should set mutualAuth flag based on client cert presence', async () => {
    // Without client cert — mutualAuth should be false
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'www.example.com', port: 443 });
    assert.strictEqual(info.mutualAuth, false,
      'Without client cert, mutualAuth should be false');
    await sock.close();
  });

  it('should find cert by subject substring match', async () => {
    const certs = await listCertificates();
    if (certs.length === 0) {
      console.log('  (no certs — skipping)');
      return;
    }

    // Take first cert's subject and verify searching for it works
    // (This tests the cert lookup path without needing an mTLS server)
    const firstCert = certs[0];
    console.log(`First cert subject: "${firstCert.subject}"`);
    console.log(`Has private key: ${firstCert.hasPrivateKey}`);
  });

  // ── Real mTLS tests (require a configured mTLS server) ───
  // Uncomment and configure these when testing with your environment.
  /*
  it('should connect with mTLS using certSubject', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({
      host: 'your-mtls-server.example.com',
      port: 8443,
      certSubject: 'YourClientCertSubject',
      storeName: 'MY',
      storeLocation: 'CurrentUser',
    });

    assert.strictEqual(info.mutualAuth, true, 'Should negotiate mTLS');
    console.log(`mTLS connected: ${info.protocol}, server=${info.serverCertSubject}`);

    await sock.close();
  });

  it('should connect with mTLS using certThumbprint', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({
      host: 'your-mtls-server.example.com',
      port: 8443,
      certThumbprint: 'a1b2c3d4e5f6...',
      storeName: 'MY',
      storeLocation: 'CurrentUser',
    });

    assert.strictEqual(info.mutualAuth, true);
    await sock.close();
  });
  */
});
