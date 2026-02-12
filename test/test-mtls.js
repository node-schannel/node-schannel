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

  // This test requires a real mTLS server and a client cert installed.
  // Uncomment and configure when testing with your environment.
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
