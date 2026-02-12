const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

describe('SchannelSocket - TLS connect', () => {
  it('should connect to a public HTTPS server', async () => {
    const sock = new SchannelSocket();
    assert.strictEqual(sock.connected, false);

    const info = await sock.connect({ host: 'www.example.com', port: 443 });

    assert.strictEqual(sock.connected, true);
    assert.ok(info.protocol, 'protocol should be set');
    assert.ok(info.cipher, 'cipher should be set');
    assert.ok(info.serverCertSubject, 'serverCertSubject should be set');
    assert.strictEqual(info.mutualAuth, false, 'no client cert = no mTLS');

    console.log(`Connected: ${info.protocol}, cipher=${info.cipher}, server=${info.serverCertSubject}`);

    await sock.close();
    assert.strictEqual(sock.connected, false);
  });

  it('should send an HTTP request and receive a response', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    const request =
      'GET / HTTP/1.1\r\n' +
      'Host: www.example.com\r\n' +
      'Connection: close\r\n' +
      '\r\n';
    await sock.write(Buffer.from(request));

    const response = await sock.readAll();
    const text = response.toString();

    assert.ok(text.startsWith('HTTP/1.1'), 'Should start with HTTP response');
    assert.ok(text.includes('Example Domain'), 'Should contain expected content');

    console.log(`Received ${response.length} bytes`);
    console.log(`Status line: ${text.split('\r\n')[0]}`);

    await sock.close();
  });

  it('should reject connection to invalid host', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: 'this-host-does-not-exist.invalid', port: 443 }),
      (err) => {
        assert.ok(err.message.length > 0, 'Error should have a message');
        console.log(`Expected error: ${err.message}`);
        return true;
      }
    );
  });

  it('should reject double connect', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    await assert.rejects(
      () => sock.connect({ host: 'www.example.com', port: 443 }),
      /already connected/
    );

    await sock.close();
  });
});
