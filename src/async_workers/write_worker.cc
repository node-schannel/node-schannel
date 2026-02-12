#include "write_worker.h"

WriteWorker::WriteWorker(
    Napi::Env env,
    SchannelSocket* socket,
    std::vector<BYTE>&& data)
    : Napi::AsyncWorker(env),
      socket_(socket),
      data_(std::move(data)),
      deferred_(Napi::Promise::Deferred::New(env)) {
    socket_->Ref();
}

void WriteWorker::Execute() {
    if (!socket_->connected_) {
        SetError("Socket is not connected");
        return;
    }

    const SecPkgContext_StreamSizes& sizes = socket_->streamSizes_;
    size_t offset = 0;
    bytesWritten_ = data_.size();

    while (offset < data_.size()) {
        // Determine chunk size (cannot exceed cbMaximumMessage)
        size_t chunkSize = data_.size() - offset;
        if (chunkSize > sizes.cbMaximumMessage) {
            chunkSize = sizes.cbMaximumMessage;
        }

        // Allocate send buffer: header + data + trailer
        size_t totalBufSize = sizes.cbHeader + chunkSize + sizes.cbTrailer;
        std::vector<BYTE> sendBuf(totalBufSize);

        // Copy plaintext data after header
        memcpy(sendBuf.data() + sizes.cbHeader, data_.data() + offset, chunkSize);

        // Set up 4 SecBuffers
        SecBufferDescWrapper bufDesc(4);
        bufDesc.buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufDesc.buffers[0].pvBuffer = sendBuf.data();
        bufDesc.buffers[0].cbBuffer = sizes.cbHeader;

        bufDesc.buffers[1].BufferType = SECBUFFER_DATA;
        bufDesc.buffers[1].pvBuffer = sendBuf.data() + sizes.cbHeader;
        bufDesc.buffers[1].cbBuffer = (unsigned long)chunkSize;

        bufDesc.buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufDesc.buffers[2].pvBuffer = sendBuf.data() + sizes.cbHeader + chunkSize;
        bufDesc.buffers[2].cbBuffer = sizes.cbTrailer;

        bufDesc.buffers[3].BufferType = SECBUFFER_EMPTY;

        SECURITY_STATUS status = EncryptMessage(&socket_->ctxtHandle_, 0, &bufDesc.desc, 0);
        if (status != SEC_E_OK) {
            SetError(MakeSSPIErrorMessage("EncryptMessage failed", status));
            return;
        }

        // Total encrypted bytes = header + data + trailer (actual sizes may differ after encryption)
        size_t encryptedLen = bufDesc.buffers[0].cbBuffer +
                              bufDesc.buffers[1].cbBuffer +
                              bufDesc.buffers[2].cbBuffer;

        // Send all encrypted data
        size_t totalSent = 0;
        while (totalSent < encryptedLen) {
            int sent = send(socket_->sock_,
                           (const char*)sendBuf.data() + totalSent,
                           (int)(encryptedLen - totalSent), 0);
            if (sent == SOCKET_ERROR) {
                SetError(MakeWinsockErrorMessage("Failed to send encrypted data"));
                return;
            }
            totalSent += sent;
        }

        offset += chunkSize;
    }
}

void WriteWorker::OnOK() {
    socket_->Unref();
    deferred_.Resolve(Napi::Number::New(Env(), (double)bytesWritten_));
}

void WriteWorker::OnError(const Napi::Error& error) {
    socket_->Unref();
    deferred_.Reject(error.Value());
}
