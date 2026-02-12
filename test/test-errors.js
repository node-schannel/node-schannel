const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

describe('SchannelSocket - Error handling', () => {
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

  it('should reject connect with missing host', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ port: 443 }),
      /host/
    );
  });

  it('should reject connect with invalid port', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'example.com', port: 99999 }),
      /port/
    );
  });

  it('should reject connect with nonexistent certificate', async () => {
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
});
