const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

describe('SchannelSocket - Error handling', () => {
  // ── Pre-connection errors ────────────────────────────────

  it('should reject write on disconnected socket', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.write(Buffer.from('hello')),
      /not connected/
    );
  });

  it('should reject read on disconnected socket', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.read(),
      /not connected/
    );
  });

  it('should allow close on never-connected socket (no-op)', async () => {
    const sock = new SchannelSocket();
    await sock.close(); // should not throw
  });

  it('should allow double close (idempotent)', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    await sock.close();
    await sock.close(); // second close should be a no-op
  });

  // ── Input validation (JS layer) ─────────────────────────

  it('should reject connect with missing host', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ port: 443 }),
      /host/
    );
  });

  it('should reject connect with non-string host', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 123, port: 443 }),
      /host.*string/i
    );
  });

  it('should reject connect with empty host', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: '', port: 443 }),
      /host/
    );
  });

  it('should reject connect with invalid port (too high)', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com', port: 99999 }),
      /port/
    );
  });

  it('should reject connect with invalid port (zero)', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com', port: 0 }),
      /port/
    );
  });

  it('should reject connect with negative port', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com', port: -1 }),
      /port/
    );
  });

  it('should reject connect with float port', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com', port: 443.5 }),
      /port/
    );
  });

  it('should reject connect with missing port', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com' }),
      /port/
    );
  });

  it('should reject connect with no arguments', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect(),
      /options/i
    );
  });

  it('should reject connect with null argument', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect(null),
      /options/i
    );
  });

  it('should reject write with non-buffer/non-string argument', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    await assert.rejects(
      () => sock.write(12345),
      /Buffer|string/
    );

    await sock.close();
  });

  // ── Certificate errors ──────────────────────────────────

  it('should reject connect with nonexistent certificate thumbprint', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({
        host: 'www.example.com',
        port: 443,
        certThumbprint: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
      }),
      /not found/i
    );
  });

  it('should reject connect with nonexistent certificate subject', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({
        host: 'www.example.com',
        port: 443,
        certSubject: 'NoSuchCertificateSubject_XYZ_12345'
      }),
      /not found/i
    );
  });

  // ── Post-close errors ───────────────────────────────────

  it('should reject write after close', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    await sock.close();

    await assert.rejects(
      () => sock.write(Buffer.from('hello')),
      /not connected/
    );
  });

  it('should reject read after close', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    await sock.close();

    await assert.rejects(
      () => sock.read(),
      /not connected/
    );
  });

  // ── TLS-level errors ───────────────────────────────────

  it('should reject connection with mismatched serverName (wrong SNI)', async () => {
    const sock = new SchannelSocket();
    // Connect to example.com but claim a different serverName — cert validation should fail
    await assert.rejects(
      () => sock.connect({
        host: 'www.example.com',
        port: 443,
        serverName: 'wrong.hostname.invalid'
      }),
      (err) => {
        assert.ok(err.message.length > 0);
        console.log(`Expected SNI mismatch error: ${err.message}`);
        return true;
      }
    );
  });
});
