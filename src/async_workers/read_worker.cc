#include "read_worker.h"

ReadWorker::ReadWorker(Napi::Env env, SchannelSocket* socket)
    : Napi::AsyncWorker(env),
      socket_(socket),
      deferred_(Napi::Promise::Deferred::New(env)) {
    socket_->Ref();
}

void ReadWorker::Execute() {
    if (!socket_->connected_) {
        SetError("Socket is not connected");
        return;
    }

    std::vector<BYTE> recvBuf(TLS_RECV_BUFFER_SIZE);
    DWORD recvOffset = 0;

    // Prepend any extra data from a previous decrypt operation
    if (!socket_->extraBuffer_.empty()) {
        if (socket_->extraBuffer_.size() > recvBuf.size()) {
            recvBuf.resize(socket_->extraBuffer_.size() + TLS_RECV_BUFFER_SIZE);
        }
        memcpy(recvBuf.data(), socket_->extraBuffer_.data(), socket_->extraBuffer_.size());
        recvOffset = (DWORD)socket_->extraBuffer_.size();
        socket_->extraBuffer_.clear();
    }

    while (true) {
        // Try to decrypt what we have first (if any data present)
        if (recvOffset > 0) {
            SecBufferDescWrapper bufDesc(4);
            bufDesc.buffers[0].BufferType = SECBUFFER_DATA;
            bufDesc.buffers[0].pvBuffer = recvBuf.data();
            bufDesc.buffers[0].cbBuffer = recvOffset;
            bufDesc.buffers[1].BufferType = SECBUFFER_EMPTY;
            bufDesc.buffers[2].BufferType = SECBUFFER_EMPTY;
            bufDesc.buffers[3].BufferType = SECBUFFER_EMPTY;

            SECURITY_STATUS status = DecryptMessage(&socket_->ctxtHandle_, &bufDesc.desc, 0, nullptr);

            if (status == SEC_E_OK) {
                // Find the DATA buffer and EXTRA buffer
                for (int i = 0; i < 4; i++) {
                    if (bufDesc.buffers[i].BufferType == SECBUFFER_DATA && bufDesc.buffers[i].cbBuffer > 0) {
                        BYTE* data = (BYTE*)bufDesc.buffers[i].pvBuffer;
                        decryptedData_.insert(decryptedData_.end(), data, data + bufDesc.buffers[i].cbBuffer);
                    }
                    if (bufDesc.buffers[i].BufferType == SECBUFFER_EXTRA && bufDesc.buffers[i].cbBuffer > 0) {
                        BYTE* extra = (BYTE*)bufDesc.buffers[i].pvBuffer;
                        socket_->extraBuffer_.assign(extra, extra + bufDesc.buffers[i].cbBuffer);
                    }
                }
                return; // Got decrypted data
            }

            if (status == SEC_I_CONTEXT_EXPIRED) {
                // Server sent a TLS shutdown
                connectionClosed_ = true;
                return;
            }

            if (status == SEC_I_RENEGOTIATE) {
                // TODO: handle renegotiation properly
                // For now, treat as error
                SetError("Server requested TLS renegotiation (not yet supported)");
                return;
            }

            if (status != SEC_E_INCOMPLETE_MESSAGE) {
                SetError(MakeSSPIErrorMessage("DecryptMessage failed", status));
                return;
            }
            // SEC_E_INCOMPLETE_MESSAGE — need more data, fall through to recv
        }

        // Receive more data from the socket
        if (recvOffset >= recvBuf.size()) {
            recvBuf.resize(recvBuf.size() * 2);
        }

        int received = recv(socket_->sock_,
                           (char*)recvBuf.data() + recvOffset,
                           (int)(recvBuf.size() - recvOffset), 0);

        if (received == 0) {
            // TCP connection closed
            connectionClosed_ = true;
            return;
        }

        if (received == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAECONNRESET || err == WSAECONNABORTED) {
                connectionClosed_ = true;
                return;
            }
            SetError(MakeWinsockErrorMessage("recv failed"));
            return;
        }

        recvOffset += received;
    }
}

void ReadWorker::OnOK() {
    Napi::Env env = Env();
    socket_->Unref();

    if (connectionClosed_ && decryptedData_.empty()) {
        deferred_.Resolve(env.Null());
    } else {
        Napi::Buffer<BYTE> buf = Napi::Buffer<BYTE>::Copy(env, decryptedData_.data(), decryptedData_.size());
        deferred_.Resolve(buf);
    }
}

void ReadWorker::OnError(const Napi::Error& error) {
    socket_->Unref();
    deferred_.Reject(error.Value());
}
