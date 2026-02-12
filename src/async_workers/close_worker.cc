#include "close_worker.h"

CloseWorker::CloseWorker(Napi::Env env, SchannelSocket* socket)
    : Napi::AsyncWorker(env),
      socket_(socket),
      deferred_(Napi::Promise::Deferred::New(env)) {
    socket_->Ref();
}

void CloseWorker::Execute() {
    if (!socket_->connected_ && socket_->sock_ == INVALID_SOCKET) {
        // Already cleaned up — no-op
        return;
    }

    // Send TLS shutdown notification if we have an active context
    if (socket_->hasCtxtHandle_ && socket_->sock_ != INVALID_SOCKET && !socket_->shutdownSent_) {
        DWORD shutdownToken = SCHANNEL_SHUTDOWN;

        SecBufferDescWrapper tokenBufDesc(1);
        tokenBufDesc.buffers[0].BufferType = SECBUFFER_TOKEN;
        tokenBufDesc.buffers[0].pvBuffer = &shutdownToken;
        tokenBufDesc.buffers[0].cbBuffer = sizeof(shutdownToken);

        SECURITY_STATUS status = ApplyControlToken(&socket_->ctxtHandle_, &tokenBufDesc.desc);
        if (status == SEC_E_OK) {
            // Build the shutdown message
            SecBufferDescWrapper outBufDesc(1);
            outBufDesc.buffers[0].BufferType = SECBUFFER_TOKEN;

            DWORD outFlags = 0;
            std::wstring wServerName = L""; // don't need server name for shutdown

            status = InitializeSecurityContextW(
                &socket_->credHandle_,
                &socket_->ctxtHandle_,
                nullptr,
                ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY,
                0, 0,
                nullptr, 0,
                nullptr,
                &outBufDesc.desc,
                &outFlags,
                nullptr);

            if (outBufDesc.buffers[0].cbBuffer > 0 && outBufDesc.buffers[0].pvBuffer) {
                // Send shutdown token — best effort, ignore errors
                send(socket_->sock_,
                     (const char*)outBufDesc.buffers[0].pvBuffer,
                     outBufDesc.buffers[0].cbBuffer, 0);
                FreeContextBuffer(outBufDesc.buffers[0].pvBuffer);
            }
        }
        socket_->shutdownSent_ = true;
    }

    // Clean up native resources
    if (socket_->hasCtxtHandle_) {
        DeleteSecurityContext(&socket_->ctxtHandle_);
        socket_->hasCtxtHandle_ = false;
    }

    if (socket_->hasCredHandle_) {
        FreeCredentialsHandle(&socket_->credHandle_);
        socket_->hasCredHandle_ = false;
    }

    if (socket_->pCertContext_) {
        CertFreeCertificateContext(socket_->pCertContext_);
        socket_->pCertContext_ = nullptr;
    }

    if (socket_->sock_ != INVALID_SOCKET) {
        shutdown(socket_->sock_, SD_BOTH);
        closesocket(socket_->sock_);
        socket_->sock_ = INVALID_SOCKET;
    }

    socket_->connected_ = false;
    socket_->extraBuffer_.clear();
}

void CloseWorker::OnOK() {
    socket_->Unref();
    deferred_.Resolve(Env().Undefined());
}

void CloseWorker::OnError(const Napi::Error& error) {
    socket_->Unref();
    deferred_.Reject(error.Value());
}
