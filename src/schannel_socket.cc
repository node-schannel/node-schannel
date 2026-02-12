#include "schannel_socket.h"
#include "async_workers/connect_worker.h"
#include "async_workers/write_worker.h"
#include "async_workers/read_worker.h"
#include "async_workers/close_worker.h"

Napi::FunctionReference SchannelSocket::constructor;

Napi::Object SchannelSocket::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "SchannelSocket", {
        InstanceMethod("connect", &SchannelSocket::Connect),
        InstanceMethod("write", &SchannelSocket::Write),
        InstanceMethod("read", &SchannelSocket::Read),
        InstanceMethod("close", &SchannelSocket::Close),
        InstanceAccessor("connected", &SchannelSocket::GetConnected, nullptr),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    exports.Set("SchannelSocket", func);
    return exports;
}

SchannelSocket::SchannelSocket(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<SchannelSocket>(info) {
    memset(&credHandle_, 0, sizeof(credHandle_));
    memset(&ctxtHandle_, 0, sizeof(ctxtHandle_));
    memset(&streamSizes_, 0, sizeof(streamSizes_));
}

SchannelSocket::~SchannelSocket() {
    CleanupNative();
}

void SchannelSocket::CleanupNative() {
    if (hasCtxtHandle_) {
        DeleteSecurityContext(&ctxtHandle_);
        hasCtxtHandle_ = false;
    }
    if (hasCredHandle_) {
        FreeCredentialsHandle(&credHandle_);
        hasCredHandle_ = false;
    }
    if (pCertContext_) {
        CertFreeCertificateContext(pCertContext_);
        pCertContext_ = nullptr;
    }
    if (sock_ != INVALID_SOCKET) {
        shutdown(sock_, SD_BOTH);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    connected_ = false;
    extraBuffer_.clear();
}

Napi::Value SchannelSocket::GetConnected(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), connected_);
}

// ── connect(options) → Promise<ConnectionInfo> ─────────────

Napi::Value SchannelSocket::Connect(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (connected_) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "Socket is already connected").Value());
        return deferred.Promise();
    }

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "connect() requires an options object").Value());
        return deferred.Promise();
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("host") || !opts.Has("port")) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "connect() requires 'host' and 'port' options").Value());
        return deferred.Promise();
    }

    std::string host = opts.Get("host").As<Napi::String>();
    int port = opts.Get("port").As<Napi::Number>().Int32Value();

    std::string serverName = "";
    std::string certSubject = "";
    std::string certThumbprint = "";
    std::string storeName = "MY";
    std::string storeLocation = "CurrentUser";

    if (opts.Has("serverName") && opts.Get("serverName").IsString())
        serverName = opts.Get("serverName").As<Napi::String>();
    if (opts.Has("certSubject") && opts.Get("certSubject").IsString())
        certSubject = opts.Get("certSubject").As<Napi::String>();
    if (opts.Has("certThumbprint") && opts.Get("certThumbprint").IsString())
        certThumbprint = opts.Get("certThumbprint").As<Napi::String>();
    if (opts.Has("storeName") && opts.Get("storeName").IsString())
        storeName = opts.Get("storeName").As<Napi::String>();
    if (opts.Has("storeLocation") && opts.Get("storeLocation").IsString())
        storeLocation = opts.Get("storeLocation").As<Napi::String>();

    auto* worker = new ConnectWorker(env, this,
        host, port, serverName, certSubject, certThumbprint, storeName, storeLocation);
    Napi::Promise promise = worker->GetPromise();
    worker->Queue();
    return promise;
}

// ── write(buffer) → Promise<number> ───────────────────────

Napi::Value SchannelSocket::Write(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!connected_) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "Socket is not connected").Value());
        return deferred.Promise();
    }

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "write() requires a Buffer argument").Value());
        return deferred.Promise();
    }

    Napi::Buffer<BYTE> buf = info[0].As<Napi::Buffer<BYTE>>();
    std::vector<BYTE> data(buf.Data(), buf.Data() + buf.Length());

    auto* worker = new WriteWorker(env, this, std::move(data));
    Napi::Promise promise = worker->GetPromise();
    worker->Queue();
    return promise;
}

// ── read() → Promise<Buffer | null> ──────────────────────

Napi::Value SchannelSocket::Read(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!connected_) {
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "Socket is not connected").Value());
        return deferred.Promise();
    }

    auto* worker = new ReadWorker(env, this);
    Napi::Promise promise = worker->GetPromise();
    worker->Queue();
    return promise;
}

// ── close() → Promise<void> ──────────────────────────────

Napi::Value SchannelSocket::Close(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    auto* worker = new CloseWorker(env, this);
    Napi::Promise promise = worker->GetPromise();
    worker->Queue();
    return promise;
}
