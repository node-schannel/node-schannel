const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

describe('SchannelSocket - TLS Validation', () => {
  it('should reject self-signed certificate', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'self-signed.badssl.com', port: 443 }),
      (err) => {
        // Schannel should reject untrusted root / self-signed cert
        console.log(`Self-signed cert error: ${err.message}`);
        return err.message.length > 0;
      }
    );
  });

  it('should reject expired certificate', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'expired.badssl.com', port: 443 }),
      (err) => {
        console.log(`Expired cert error: ${err.message}`);
        return err.message.length > 0;
      }
    );
  });

  it('should reject wrong-host certificate', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'wrong.host.badssl.com', port: 443 }),
      (err) => {
        console.log(`Wrong host cert error: ${err.message}`);
        return err.message.length > 0;
      }
    );
  });

  it('should reject untrusted root certificate', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'untrusted-root.badssl.com', port: 443 }),
      (err) => {
        console.log(`Untrusted root error: ${err.message}`);
        return err.message.length > 0;
      }
    );
  });

  it('should accept valid certificate from well-known CA', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'sha256.badssl.com', port: 443 });

    assert.ok(info.protocol, 'Should negotiate protocol');
    assert.ok(info.serverCertSubject.includes('badssl'), 'Should have badssl in subject');

    console.log(`Valid cert: ${info.serverCertSubject}, ${info.protocol}`);
    await sock.close();
  });

  it('should connect to TLS 1.2-only server', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'tls-v1-2.badssl.com', port: 1012 });

    assert.strictEqual(info.protocol, 'TLS 1.2', 'Should negotiate TLS 1.2');
    console.log(`TLS 1.2 only: ${info.protocol}, ${info.cipher}`);
    await sock.close();
  });

  it('should validate that server cert subject is populated', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'www.example.com', port: 443 });

    assert.ok(info.serverCertSubject, 'serverCertSubject should not be empty');
    assert.ok(info.serverCertSubject.length > 0, 'serverCertSubject should have content');
    console.log(`Server cert subject: ${info.serverCertSubject}`);

    await sock.close();
  });

  it('should show mutualAuth=false when no client cert used', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'www.example.com', port: 443 });

    assert.strictEqual(info.mutualAuth, false,
      'mutualAuth should be false without client cert');

    await sock.close();
  });
});
