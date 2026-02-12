#ifndef READ_WORKER_H
#define READ_WORKER_H

#include "../schannel_socket.h"

class ReadWorker : public Napi::AsyncWorker {
public:
    ReadWorker(Napi::Env env, SchannelSocket* socket);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise GetPromise() { return deferred_.Promise(); }

private:
    SchannelSocket* socket_;
    std::vector<BYTE> decryptedData_;
    bool connectionClosed_ = false;
    Napi::Promise::Deferred deferred_;
};

#endif // READ_WORKER_H
