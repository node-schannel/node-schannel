#include "list_certs_worker.h"

ListCertsWorker::ListCertsWorker(Napi::Env env, const std::string& storeName, const std::string& storeLocation)
    : Napi::AsyncWorker(env),
      storeName_(storeName),
      storeLocation_(storeLocation),
      deferred_(Napi::Promise::Deferred::New(env)) {}

void ListCertsWorker::Execute() {
    results_ = EnumerateCertificates(storeName_, storeLocation_);
}

void ListCertsWorker::OnOK() {
    Napi::Env env = Env();
    Napi::Array arr = Napi::Array::New(env, results_.size());

    for (size_t i = 0; i < results_.size(); i++) {
        const CertInfo& c = results_[i];
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("subject", Napi::String::New(env, c.subject));
        obj.Set("issuer", Napi::String::New(env, c.issuer));
        obj.Set("thumbprint", Napi::String::New(env, c.thumbprint));
        obj.Set("hasPrivateKey", Napi::Boolean::New(env, c.hasPrivateKey));
        obj.Set("notBefore", Napi::Date::New(env, c.notBefore));
        obj.Set("notAfter", Napi::Date::New(env, c.notAfter));
        obj.Set("friendlyName", Napi::String::New(env, c.friendlyName));
        arr.Set((uint32_t)i, obj);
    }

    deferred_.Resolve(arr);
}

void ListCertsWorker::OnError(const Napi::Error& error) {
    deferred_.Reject(error.Value());
}
