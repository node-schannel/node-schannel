# Contributing to node-schannel

## Prerequisites

- **Windows** (this is a Windows-only native addon)
- **Node.js** >= 18
- **Visual Studio Build Tools** with "Desktop development with C++" workload
  - Or full Visual Studio with the C++ workload
- **Python** 3.x (required by node-gyp)

## Getting started

```bash
git clone https://github.com/node-schannel/node-schannel.git
cd node-schannel
npm install      # installs dependencies and compiles the native addon
npm test         # runs the full test suite (76 tests)
```

## Development workflow

1. Create a feature branch from `main`
2. Make your changes
3. Build: `npm run build`
4. Test: `npm test`
5. Push your branch and open a Pull Request against `main`
6. CI must pass (builds + tests on Node 18, 20, 22)
7. Get at least one approving review

## Project structure

```
src/                      C++ source files
  schannel_common.h       Shared includes, helpers, constants
  schannel_socket.h/cc    SchannelSocket N-API ObjectWrap class
  cert_store.h/cc         Certificate store operations
  addon.cc                Module entry point
  async_workers/          Async worker classes (connect, read, write, close, list_certs)
lib/
  schannel-socket.js      JavaScript wrapper with input validation
index.js                  Native module loader
test/                     Test suites (node:test)
```

## Debug build

```bash
npm run build:debug
```

The debug build outputs to `build/Debug/schannels.node` and is loaded automatically by `index.js` if the Release build isn't found.

## Testing

Tests use the Node.js built-in test runner. Some tests connect to public HTTPS servers (example.com, badssl.com) and require network access.

```bash
npm test                              # run all tests
node --test test/test-cert-store.js   # run a single suite
```

## Code style

- C++: Follow existing patterns. Use N-API/node-addon-api. No exceptions (`NAPI_DISABLE_CPP_EXCEPTIONS`).
- JavaScript: CommonJS, `'use strict'`, no external dependencies in the library itself.

## Reporting issues

Please use the [issue templates](https://github.com/node-schannel/node-schannel/issues/new/choose) and include your OS version, Node.js version, and Visual Studio version.
