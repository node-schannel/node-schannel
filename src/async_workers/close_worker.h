#ifndef CLOSE_WORKER_H
#define CLOSE_WORKER_H

#include "../schannel_socket.h"

class CloseWorker : public Napi::AsyncWorker {
public:
    CloseWorker(Napi::Env env, SchannelSocket* socket);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise GetPromise() { return deferred_.Promise(); }

private:
    SchannelSocket* socket_;
    Napi::Promise::Deferred deferred_;
};

#endif // CLOSE_WORKER_H
