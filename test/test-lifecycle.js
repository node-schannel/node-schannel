const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SchannelSocket } = require('../lib/schannel-socket');

describe('SchannelSocket - Lifecycle & Resource Management', () => {
  it('should clean up resources after successful close', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    assert.strictEqual(sock.connected, true);

    await sock.close();
    assert.strictEqual(sock.connected, false);

    // After close, read/write should fail cleanly
    await assert.rejects(() => sock.write(Buffer.from('x')), /not connected/);
    await assert.rejects(() => sock.read(), /not connected/);
  });

  it('should clean up resources after failed connect', async () => {
    const sock = new SchannelSocket();

    await assert.rejects(
      () => sock.connect({ host: 'this-host-does-not-exist.invalid', port: 443 })
    );

    // Socket should not be connected
    assert.strictEqual(sock.connected, false);

    // Close should be safe even after failed connect
    await sock.close();
  });

  it('should handle rapid create-connect-close cycles', async () => {
    for (let i = 0; i < 5; i++) {
      const sock = new SchannelSocket();
      await sock.connect({ host: 'www.example.com', port: 443 });
      assert.strictEqual(sock.connected, true);
      await sock.close();
      assert.strictEqual(sock.connected, false);
    }
    console.log('5 rapid connect/close cycles completed');
  });

  it('should allow GC-eligible sockets without leaking (non-closed)', async () => {
    // Create sockets and let them go out of scope without closing
    // This tests that the destructor properly cleans up
    for (let i = 0; i < 3; i++) {
      const sock = new SchannelSocket();
      await sock.connect({ host: 'www.example.com', port: 443 });
      // Intentionally NOT closing — destructor should handle cleanup
    }
    // Force GC if exposed (V8 --expose-gc flag)
    if (global.gc) {
      global.gc();
      console.log('GC triggered — sockets should be cleaned up');
    } else {
      console.log('GC not exposed — skipping explicit GC test');
    }
  });

  it('should handle close during idle connection', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });

    // Wait a moment, then close without any read/write
    await new Promise(resolve => setTimeout(resolve, 100));

    await sock.close();
    assert.strictEqual(sock.connected, false);
  });

  it('should handle close right after connect', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    // Immediately close without any I/O
    await sock.close();
    assert.strictEqual(sock.connected, false);
  });

  it('should handle sequential operations with error recovery', async () => {
    // First: fail a connect
    const sock1 = new SchannelSocket();
    await assert.rejects(
      () => sock1.connect({ host: 'nonexistent.invalid', port: 443 })
    );
    await sock1.close();

    // Then: succeed with a new socket
    const sock2 = new SchannelSocket();
    const info = await sock2.connect({ host: 'www.example.com', port: 443 });
    assert.ok(info.protocol);
    await sock2.close();
  });

  it('should handle many sockets created concurrently', async () => {
    const count = 5;
    const sockets = [];

    try {
      const promises = [];
      for (let i = 0; i < count; i++) {
        const sock = new SchannelSocket();
        sockets.push(sock);
        promises.push(sock.connect({ host: 'www.example.com', port: 443 }));
      }

      const infos = await Promise.all(promises);
      for (const info of infos) {
        assert.ok(info.protocol);
      }

      console.log(`${count} concurrent connections established`);
    } finally {
      await Promise.all(sockets.map(s => s.close()));
    }
  });

  it('should triple-close without issues', async () => {
    const sock = new SchannelSocket();
    await sock.connect({ host: 'www.example.com', port: 443 });
    await sock.close();
    await sock.close();
    await sock.close();
    assert.strictEqual(sock.connected, false);
  });
});
