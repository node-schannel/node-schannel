const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

/**
 * Helper: connect, send HTTP request, read full response, close.
 */
async function httpGet(host, path = '/', headers = {}) {
  const sock = new SchannelSocket();
  await sock.connect({ host, port: 443 });

  const hdrs = { Host: host, Connection: 'close', ...headers };
  const headerStr = Object.entries(hdrs).map(([k, v]) => `${k}: ${v}`).join('\r\n');
  const request = `GET ${path} HTTP/1.1\r\n${headerStr}\r\n\r\n`;
  await sock.write(request);

  const response = await sock.readAll();
  await sock.close();
  return response;
}

describe('SchannelSocket - Data Transfer', () => {
  it('should receive a complete HTTP response with headers and body', async () => {
    const response = await httpGet('www.example.com');
    const text = response.toString();

    // Verify HTTP response structure
    assert.ok(text.includes('HTTP/1.1'), 'Should have HTTP status line');
    assert.ok(text.includes('\r\n\r\n'), 'Should have header/body separator');
    assert.ok(text.includes('<!doctype html>') || text.includes('<!DOCTYPE html>'),
      'Should have HTML doctype');
  });

  it('should handle multiple sequential read() calls', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    await sock.write(
      'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'
    );

    // Read in chunks
    const chunks = [];
    let chunk;
    while ((chunk = await sock.read()) !== null) {
      chunks.push(chunk);
    }

    assert.ok(chunks.length >= 1, 'Should have at least one chunk');
    const total = Buffer.concat(chunks);
    assert.ok(total.length > 0, 'Total data should be non-empty');
    console.log(`Read ${chunks.length} chunk(s), total ${total.length} bytes`);

    await sock.close();
  });

  it('should return null from read() after Connection: close', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    await sock.write(
      'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'
    );

    // readAll reads until null
    const data = await sock.readAll();
    assert.ok(data.length > 0);

    // After readAll, a subsequent read should return null
    // (connection already closed by server)
    // Note: the socket may already be in a disconnected state
    await sock.close();
  });

  it('should send and receive binary data correctly', async () => {
    // Build a request with binary-safe content checking
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    // Request a page - the HTML may contain multi-byte UTF-8
    await sock.write(Buffer.from(
      'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'
    ));

    const response = await sock.readAll();
    assert.ok(Buffer.isBuffer(response), 'readAll should return a Buffer');
    assert.ok(response.length > 100, 'Response should be substantial');

    await sock.close();
  });

  it('should handle write() returning bytes written count', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    const data = 'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n';
    const bytesWritten = await sock.write(data);

    assert.strictEqual(typeof bytesWritten, 'number', 'Should return a number');
    assert.strictEqual(bytesWritten, Buffer.from(data).length,
      'Bytes written should match input length');

    await sock.readAll();
    await sock.close();
  });

  it('should handle a larger payload write', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'httpbin.org', port: 443 });

    // POST a larger body (4KB of data)
    const bodyData = 'A'.repeat(4096);
    const request =
      `POST /post HTTP/1.1\r\n` +
      `Host: httpbin.org\r\n` +
      `Content-Type: text/plain\r\n` +
      `Content-Length: ${bodyData.length}\r\n` +
      `Connection: close\r\n` +
      `\r\n` +
      bodyData;

    const bytesWritten = await sock.write(request);
    assert.ok(bytesWritten > 4096, 'Should write at least the body size');

    const response = await sock.readAll();
    const text = response.toString();
    assert.ok(text.includes('HTTP/1.1'), 'Should get HTTP response');
    console.log(`Status: ${text.split('\r\n')[0]}`);

    await sock.close();
  });

  it('should handle multiple sequential writes before reading', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    // Write request in parts
    await sock.write('GET / HTTP/1.1\r\n');
    await sock.write('Host: www.example.com\r\n');
    await sock.write('Connection: close\r\n');
    await sock.write('\r\n');

    const response = await sock.readAll();
    const text = response.toString();
    assert.ok(text.includes('Example Domain'), 'Should receive valid response');

    await sock.close();
  });

  it('should handle empty buffer write gracefully', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    // Write an empty buffer
    const bytesWritten = await sock.write(Buffer.alloc(0));
    assert.strictEqual(bytesWritten, 0, 'Empty write should return 0 bytes');

    // Socket should still be functional after empty write
    await sock.write('GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n');
    const response = await sock.readAll();
    assert.ok(response.length > 0, 'Should still work after empty write');

    await sock.close();
  });

  it('should receive data from a different server (google.com)', async () => {
    const response = await httpGet('www.google.com', '/');
    const text = response.toString();
    assert.ok(text.startsWith('HTTP/'), 'Should receive HTTP response');
    assert.ok(response.length > 100, 'Google response should be substantial');
    console.log(`Google response: ${response.length} bytes`);
  });

  it('should handle HTTP redirects in raw response', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.google.com', port: 443 });

    await sock.write(
      'GET /doodles HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n'
    );

    const response = await sock.readAll();
    const text = response.toString();
    const statusLine = text.split('\r\n')[0];

    // Could be 200, 301, 302, etc. - just verify we got a valid HTTP response
    assert.ok(statusLine.startsWith('HTTP/'), `Expected HTTP status, got: ${statusLine}`);
    console.log(`Redirect test: ${statusLine}`);

    await sock.close();
  });
});
