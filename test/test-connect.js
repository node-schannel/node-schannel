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

  it('should negotiate TLS 1.2 or higher', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'www.example.com', port: 443 });

    const acceptableProtocols = ['TLS 1.2', 'TLS 1.3'];
    assert.ok(acceptableProtocols.includes(info.protocol),
      `Expected TLS 1.2+, got: ${info.protocol}`);

    console.log(`Protocol: ${info.protocol}`);
    await sock.close();
  });

  it('should negotiate a strong cipher', async () => {
    const sock = new SchannelSocket();
    const info = await sock.connect({ host: 'www.example.com', port: 443 });

    const strongCiphers = ['AES-128', 'AES-256'];
    assert.ok(strongCiphers.includes(info.cipher),
      `Expected AES cipher, got: ${info.cipher}`);

    console.log(`Cipher: ${info.cipher}`);
    await sock.close();
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

  it('should accept string argument to write()', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    // The JS wrapper should auto-convert string to Buffer
    const request =
      'GET / HTTP/1.1\r\n' +
      'Host: www.example.com\r\n' +
      'Connection: close\r\n' +
      '\r\n';
    const bytesWritten = await sock.write(request);
    assert.ok(bytesWritten > 0, 'Should return bytes written');

    const response = await sock.readAll();
    assert.ok(response.length > 0, 'Should receive response');

    await sock.close();
  });

  it('should support serverName option for SNI', async () => {
    const sock = new SchannelSocket();
    // Connect with explicit serverName matching the host
    const info = await sock.connect({
      host: 'www.example.com',
      port: 443,
      serverName: 'www.example.com',
    });

    assert.ok(info.serverCertSubject, 'Should have server cert subject');
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

  it('should reject connection to closed port', async () => {
    const sock = new SchannelSocket();
    await assert.rejects(
      () => sock.connect({ host: '127.0.0.1', port: 1 }),
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

  it('should support connecting to different hosts sequentially (after close)', async () => {
    const sock = new SchannelSocket();

    // First connection
    const info1 = await sock.connect({ host: 'www.example.com', port: 443 });
    assert.ok(info1.protocol);
    await sock.close();

    // The socket object can't be reused after close, create new one
    const sock2 = new SchannelSocket();
    const info2 = await sock2.connect({ host: 'www.google.com', port: 443 });
    assert.ok(info2.protocol);
    await sock2.close();
  });

  it('should handle multiple independent socket connections concurrently', async () => {
    const sockets = [];
    const hosts = ['www.example.com', 'www.google.com'];

    try {
      const connectPromises = hosts.map(host => {
        const sock = new SchannelSocket();
        sockets.push(sock);
        return sock.connect({ host, port: 443 });
      });

      const infos = await Promise.all(connectPromises);
      for (const info of infos) {
        assert.ok(info.protocol, 'Each should negotiate a protocol');
      }
    } finally {
      await Promise.all(sockets.map(s => s.close()));
    }
  });

  it('should report correct connected state through lifecycle', async () => {
    const sock = new SchannelSocket();

    assert.strictEqual(sock.connected, false, 'Before connect');

    await sock.connect({ host: 'www.example.com', port: 443 });
    assert.strictEqual(sock.connected, true, 'After connect');

    await sock.close();
    assert.strictEqual(sock.connected, false, 'After close');
  });
});
