#ifndef WRITE_WORKER_H
#define WRITE_WORKER_H

#include "../schannel_socket.h"

class WriteWorker : public Napi::AsyncWorker {
public:
    WriteWorker(Napi::Env env,
                SchannelSocket* socket,
                std::vector<BYTE>&& data);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise GetPromise() { return deferred_.Promise(); }

private:
    SchannelSocket* socket_;
    std::vector<BYTE> data_;
    size_t bytesWritten_ = 0;
    Napi::Promise::Deferred deferred_;
};

#endif // WRITE_WORKER_H
