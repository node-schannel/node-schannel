# node-schannel

A Node.js native addon wrapping the **Windows Schannel SSPI** to establish **mTLS (mutual TLS) connections** using X.509 certificates stored in the **Windows Certificate Store**.

## Why?

Node.js's built-in `tls` module uses OpenSSL and requires PEM files for client certificates. On Windows, certificates are often managed in the OS certificate store (certmgr.msc) and may have non-exportable private keys. This module bridges that gap by using Windows' native TLS stack (Schannel) directly.

**No existing npm package does this.** This is novel.

## Requirements

- **Windows** (this module is Windows-only)
- **Node.js** ≥ 18
- **Visual Studio Build Tools** (for node-gyp compilation)
  - Install via: `npm install -g windows-build-tools` or install Visual Studio with "Desktop development with C++"

## Installation

```bash
npm install node-schannel
```

Or from source:

```bash
git clone https://github.com/node-schannel/node-schannel.git
cd node-schannel
npm install
```

## Quick Start

```js
const { SchannelSocket, listCertificates } = require('node-schannel/lib/schannel-socket');

async function main() {
  // 1. Browse available certificates
  const certs = await listCertificates();
  console.log('Available certificates:', certs);

  // 2. Connect with TLS (no client cert)
  const sock = new SchannelSocket();
  const info = await sock.connect({ host: 'example.com', port: 443 });
  console.log(`Connected: ${info.protocol}, cipher: ${info.cipher}`);

  // 3. Send HTTP request
  await sock.write(Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'));

  // 4. Read response
  const response = await sock.readAll();
  console.log(response.toString());

  // 5. Clean up
  await sock.close();
}

main().catch(console.error);
```

### mTLS Example

```js
const { SchannelSocket, listCertificates } = require('node-schannel/lib/schannel-socket');

async function mtlsConnect() {
  // Find a certificate with a private key
  const certs = await listCertificates();
  const clientCert = certs.find(c => c.hasPrivateKey && c.subject.includes('MyClient'));
  if (!clientCert) throw new Error('Client certificate not found');

  const sock = new SchannelSocket();
  const info = await sock.connect({
    host: 'secure-api.example.com',
    port: 8443,
    certThumbprint: clientCert.thumbprint,
  });

  console.log(`mTLS: ${info.mutualAuth}, protocol: ${info.protocol}`);

  // ... send/receive data ...

  await sock.close();
}
```

## API

### `listCertificates(options?)`

Enumerate certificates from a Windows certificate store.

**Options:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `storeName` | `string` | `'MY'` | Store name: `MY`, `Root`, `CA`, `Trust`, etc. |
| `storeLocation` | `string` | `'CurrentUser'` | `'CurrentUser'` or `'LocalMachine'` |

**Returns:** `Promise<CertInfo[]>`

Each `CertInfo` has: `subject`, `issuer`, `thumbprint`, `hasPrivateKey`, `notBefore` (Date), `notAfter` (Date), `friendlyName`.

---

### `new SchannelSocket()`

Creates a new Schannel socket instance.

---

### `socket.connect(options)`

Establish a TCP connection and perform a TLS handshake.

| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | `string` | ✓ | | Hostname or IP |
| `port` | `number` | ✓ | | TCP port |
| `certSubject` | `string` | | | Find client cert by subject |
| `certThumbprint` | `string` | | | Find client cert by SHA-1 thumbprint |
| `storeName` | `string` | | `'MY'` | Certificate store name |
| `storeLocation` | `string` | | `'CurrentUser'` | Store location |
| `serverName` | `string` | | = host | SNI target name |

**Returns:** `Promise<ConnectionInfo>` with `protocol`, `cipher`, `serverCertSubject`, `mutualAuth`.

---

### `socket.write(buffer)`

Encrypt and send data. Returns `Promise<number>` (bytes written).

---

### `socket.read()`

Receive and decrypt data. Returns `Promise<Buffer | null>`. Returns `null` when the connection is closed.

---

### `socket.readAll()`

Read all data until connection closes. Returns `Promise<Buffer>`.

---

### `socket.close()`

Graceful TLS shutdown and cleanup. Returns `Promise<void>`. Safe to call multiple times.

---

### `socket.connected`

`boolean` — whether the socket is currently connected.

## Testing

```bash
npm test
```

## License

MIT
