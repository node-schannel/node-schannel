#ifndef CONNECT_WORKER_H
#define CONNECT_WORKER_H

#include "../schannel_socket.h"

class ConnectWorker : public Napi::AsyncWorker {
public:
    ConnectWorker(Napi::Env env,
                  SchannelSocket* socket,
                  const std::string& host,
                  int port,
                  const std::string& serverName,
                  const std::string& certSubject,
                  const std::string& certThumbprint,
                  const std::string& storeName,
                  const std::string& storeLocation);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise GetPromise() { return deferred_.Promise(); }

private:
    SchannelSocket* socket_;
    std::string host_;
    int port_;
    std::string serverName_;
    std::string certSubject_;
    std::string certThumbprint_;
    std::string storeName_;
    std::string storeLocation_;
    Napi::Promise::Deferred deferred_;

    bool DoTcpConnect();
    bool DoAcquireCredentials();
    bool DoHandshake();
    void QueryConnectionInfo();
};

#endif // CONNECT_WORKER_H
