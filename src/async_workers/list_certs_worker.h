#ifndef LIST_CERTS_WORKER_H
#define LIST_CERTS_WORKER_H

#include "../cert_store.h"

class ListCertsWorker : public Napi::AsyncWorker {
public:
    ListCertsWorker(Napi::Env env, const std::string& storeName, const std::string& storeLocation);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise GetPromise() { return deferred_.Promise(); }

private:
    std::string storeName_;
    std::string storeLocation_;
    std::vector<CertInfo> results_;
    Napi::Promise::Deferred deferred_;
};

#endif // LIST_CERTS_WORKER_H
