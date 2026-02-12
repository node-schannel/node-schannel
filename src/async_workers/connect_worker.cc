#include "connect_worker.h"
#include "../cert_store.h"

ConnectWorker::ConnectWorker(
    Napi::Env env,
    SchannelSocket* socket,
    const std::string& host,
    int port,
    const std::string& serverName,
    const std::string& certSubject,
    const std::string& certThumbprint,
    const std::string& storeName,
    const std::string& storeLocation)
    : Napi::AsyncWorker(env),
      socket_(socket),
      host_(host),
      port_(port),
      serverName_(serverName.empty() ? host : serverName),
      certSubject_(certSubject),
      certThumbprint_(certThumbprint),
      storeName_(storeName),
      storeLocation_(storeLocation),
      deferred_(Napi::Promise::Deferred::New(env)) {}

void ConnectWorker::Execute() {
    if (!DoAcquireCredentials()) return;
    if (!DoTcpConnect()) return;
    if (!DoHandshake()) return;
    QueryConnectionInfo();
}

bool ConnectWorker::DoTcpConnect() {
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(port_);
    int ret = getaddrinfo(host_.c_str(), portStr.c_str(), &hints, &result);
    if (ret != 0) {
        SetError("DNS resolution failed for '" + host_ + "': " + std::to_string(ret));
        return false;
    }

    SOCKET sock = INVALID_SOCKET;
    for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        if (connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        SetError(MakeWinsockErrorMessage("TCP connect to " + host_ + ":" + std::to_string(port_) + " failed"));
        return false;
    }

    socket_->sock_ = sock;
    return true;
}

bool ConnectWorker::DoAcquireCredentials() {
    // Open certificate store if we have cert identifiers
    bool hasCert = !certSubject_.empty() || !certThumbprint_.empty();

    if (hasCert) {
        std::wstring wStoreName = Utf8ToWide(storeName_);
        DWORD storeFlags = ParseStoreLocation(storeLocation_);

        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            (HCRYPTPROV_LEGACY)0,
            storeFlags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
            wStoreName.c_str());

        if (!hStore) {
            SetError("Failed to open certificate store '" + storeName_ + "' (" + storeLocation_ + "): " +
                     FormatWin32Error(GetLastError()));
            return false;
        }

        PCCERT_CONTEXT pCert = nullptr;
        if (!certThumbprint_.empty()) {
            pCert = FindCertificateByThumbprint(hStore, certThumbprint_);
            if (!pCert) {
                CertCloseStore(hStore, 0);
                SetError("Certificate not found with thumbprint: " + certThumbprint_);
                return false;
            }
        } else {
            pCert = FindCertificateBySubject(hStore, certSubject_);
            if (!pCert) {
                CertCloseStore(hStore, 0);
                SetError("Certificate not found with subject: " + certSubject_);
                return false;
            }
        }

        // Verify private key exists
        if (!CertHasPrivateKey(pCert)) {
            CertFreeCertificateContext(pCert);
            CertCloseStore(hStore, 0);
            SetError("Certificate does not have an associated private key (required for mTLS)");
            return false;
        }

        // Duplicate the cert context (store can be closed)
        socket_->pCertContext_ = CertDuplicateCertificateContext(pCert);
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
    }

    // Build SCHANNEL_CRED
    SCHANNEL_CRED schCred = {};
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.grbitEnabledProtocols = 0; // system default
    schCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

    if (socket_->pCertContext_) {
        schCred.cCreds = 1;
        schCred.paCred = &socket_->pCertContext_;
    }

    SECURITY_STATUS status = AcquireCredentialsHandleA(
        nullptr,
        (LPSTR)UNISP_NAME_A,
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &schCred,
        nullptr,
        nullptr,
        &socket_->credHandle_,
        nullptr);

    if (status != SEC_E_OK) {
        SetError(MakeSSPIErrorMessage("AcquireCredentialsHandle failed", status));
        return false;
    }

    socket_->hasCredHandle_ = true;
    return true;
}

bool ConnectWorker::DoHandshake() {
    std::vector<BYTE> recvBuffer(TLS_RECV_BUFFER_SIZE);
    DWORD recvOffset = 0;
    bool initialCall = true;
    SECURITY_STATUS status = SEC_I_CONTINUE_NEEDED;

    while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE) {
        SecBufferDescWrapper outBufDesc(1);
        outBufDesc.buffers[0].BufferType = SECBUFFER_TOKEN;

        DWORD outFlags = 0;

        if (initialCall) {
            // First call — no input
            std::wstring wServerName = Utf8ToWide(serverName_);
            status = InitializeSecurityContextW(
                &socket_->credHandle_,
                nullptr,
                (LPWSTR)wServerName.c_str(),
                SCHANNEL_ISC_FLAGS,
                0,
                0,
                nullptr,
                0,
                &socket_->ctxtHandle_,
                &outBufDesc.desc,
                &outFlags,
                nullptr);

            socket_->hasCtxtHandle_ = true;
            initialCall = false;
        } else {
            // Subsequent calls — pass received server data
            SecBufferDescWrapper inBufDesc(2);
            inBufDesc.buffers[0].BufferType = SECBUFFER_TOKEN;
            inBufDesc.buffers[0].pvBuffer = recvBuffer.data();
            inBufDesc.buffers[0].cbBuffer = recvOffset;
            inBufDesc.buffers[1].BufferType = SECBUFFER_EMPTY;

            std::wstring wServerName = Utf8ToWide(serverName_);
            status = InitializeSecurityContextW(
                &socket_->credHandle_,
                &socket_->ctxtHandle_,
                (LPWSTR)wServerName.c_str(),
                SCHANNEL_ISC_FLAGS,
                0,
                0,
                &inBufDesc.desc,
                0,
                nullptr,
                &outBufDesc.desc,
                &outFlags,
                nullptr);

            // Check for extra data
            if (inBufDesc.buffers[1].BufferType == SECBUFFER_EXTRA) {
                DWORD extraLen = inBufDesc.buffers[1].cbBuffer;
                memmove(recvBuffer.data(), recvBuffer.data() + (recvOffset - extraLen), extraLen);
                recvOffset = extraLen;
            } else if (status != SEC_E_INCOMPLETE_MESSAGE) {
                recvOffset = 0;
            }
        }

        // Send output token to server if any
        if (outBufDesc.buffers[0].cbBuffer > 0 && outBufDesc.buffers[0].pvBuffer) {
            int sent = send(socket_->sock_,
                           (const char*)outBufDesc.buffers[0].pvBuffer,
                           outBufDesc.buffers[0].cbBuffer, 0);
            FreeContextBuffer(outBufDesc.buffers[0].pvBuffer);
            if (sent == SOCKET_ERROR) {
                SetError(MakeWinsockErrorMessage("Failed to send handshake data"));
                return false;
            }
        }

        if (status == SEC_E_OK) {
            break; // Handshake complete
        }

        if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE) {
            // Receive more data from the server
            if (recvOffset >= recvBuffer.size()) {
                recvBuffer.resize(recvBuffer.size() * 2);
            }
            int received = recv(socket_->sock_,
                               (char*)recvBuffer.data() + recvOffset,
                               (int)(recvBuffer.size() - recvOffset), 0);
            if (received <= 0) {
                SetError("Server closed connection during TLS handshake");
                return false;
            }
            recvOffset += received;
        } else if (status == SEC_I_INCOMPLETE_CREDENTIALS) {
            // Server requested client cert but we didn't provide one,
            // or provided one it doesn't trust. Retry with what we have.
            SetError("Server rejected client credentials (SEC_I_INCOMPLETE_CREDENTIALS). "
                     "Ensure the client certificate is trusted by the server.");
            return false;
        } else if (FAILED(status)) {
            SetError(MakeSSPIErrorMessage("TLS handshake failed", status));
            return false;
        }
    }

    // Query stream sizes for encrypt/decrypt
    status = QueryContextAttributes(&socket_->ctxtHandle_, SECPKG_ATTR_STREAM_SIZES, &socket_->streamSizes_);
    if (status != SEC_E_OK) {
        SetError(MakeSSPIErrorMessage("QueryContextAttributes(STREAM_SIZES) failed", status));
        return false;
    }

    socket_->connected_ = true;
    return true;
}

void ConnectWorker::QueryConnectionInfo() {
    // Query negotiated protocol & cipher
    SecPkgContext_ConnectionInfo connInfo = {};
    if (QueryContextAttributes(&socket_->ctxtHandle_, SECPKG_ATTR_CONNECTION_INFO, &connInfo) == SEC_E_OK) {
        switch (connInfo.dwProtocol) {
            case SP_PROT_TLS1_CLIENT:   socket_->negotiatedProtocol_ = "TLS 1.0"; break;
            case SP_PROT_TLS1_1_CLIENT: socket_->negotiatedProtocol_ = "TLS 1.1"; break;
            case SP_PROT_TLS1_2_CLIENT: socket_->negotiatedProtocol_ = "TLS 1.2"; break;
            default:
                // Check for TLS 1.3 (SP_PROT_TLS1_3_CLIENT may not be defined in older SDKs)
                if (connInfo.dwProtocol == 0x00002000) {
                    socket_->negotiatedProtocol_ = "TLS 1.3";
                } else {
                    socket_->negotiatedProtocol_ = "Unknown (0x" +
                        std::to_string(connInfo.dwProtocol) + ")";
                }
                break;
        }

        switch (connInfo.aiCipher) {
            case CALG_AES_128: socket_->negotiatedCipher_ = "AES-128"; break;
            case CALG_AES_256: socket_->negotiatedCipher_ = "AES-256"; break;
            case CALG_3DES:    socket_->negotiatedCipher_ = "3DES"; break;
            case CALG_RC4:     socket_->negotiatedCipher_ = "RC4"; break;
            default:           socket_->negotiatedCipher_ = "Cipher(0x" +
                                   std::to_string(connInfo.aiCipher) + ")"; break;
        }
    }

    // Query server certificate subject
    PCCERT_CONTEXT pServerCert = nullptr;
    if (QueryContextAttributes(&socket_->ctxtHandle_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pServerCert) == SEC_E_OK) {
        wchar_t serverSubject[256] = {};
        CertGetNameStringW(pServerCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, serverSubject, 256);
        socket_->serverCertSubject_ = WideToUtf8(serverSubject);
        CertFreeCertificateContext(pServerCert);
    }

    // mTLS = we presented a client cert
    socket_->mutualAuth_ = (socket_->pCertContext_ != nullptr);
}

void ConnectWorker::OnOK() {
    Napi::Env env = Env();
    Napi::Object info = Napi::Object::New(env);
    info.Set("protocol", Napi::String::New(env, socket_->negotiatedProtocol_));
    info.Set("cipher", Napi::String::New(env, socket_->negotiatedCipher_));
    info.Set("serverCertSubject", Napi::String::New(env, socket_->serverCertSubject_));
    info.Set("mutualAuth", Napi::Boolean::New(env, socket_->mutualAuth_));
    deferred_.Resolve(info);
}

void ConnectWorker::OnError(const Napi::Error& error) {
    // Clean up on failure
    socket_->CleanupNative();
    deferred_.Reject(error.Value());
}
