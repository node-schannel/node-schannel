#include "schannel_common.h"
#include "schannel_socket.h"
#include "cert_store.h"
#include "async_workers/list_certs_worker.h"

// ── listCertificates(options?) → Promise<CertInfo[]> ──────

static Napi::Value ListCertificates(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string storeName = "MY";
    std::string storeLocation = "CurrentUser";

    if (info.Length() >= 1 && info[0].IsObject()) {
        Napi::Object opts = info[0].As<Napi::Object>();
        if (opts.Has("storeName") && opts.Get("storeName").IsString())
            storeName = opts.Get("storeName").As<Napi::String>();
        if (opts.Has("storeLocation") && opts.Get("storeLocation").IsString())
            storeLocation = opts.Get("storeLocation").As<Napi::String>();
    }

    auto* worker = new ListCertsWorker(env, storeName, storeLocation);
    Napi::Promise promise = worker->GetPromise();
    worker->Queue();
    return promise;
}

// ── Module init ────────────────────────────────────────────

static bool wsaInitialized = false;

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize Winsock
    if (!wsaInitialized) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            Napi::Error::New(env, "WSAStartup failed with error: " + std::to_string(result))
                .ThrowAsJavaScriptException();
            return exports;
        }
        wsaInitialized = true;

        // Register cleanup hook
        napi_add_env_cleanup_hook(env, [](void*) {
            if (wsaInitialized) {
                WSACleanup();
                wsaInitialized = false;
            }
        }, nullptr);
    }

    // Register SchannelSocket class
    SchannelSocket::Init(env, exports);

    // Register listCertificates function
    exports.Set("listCertificates",
        Napi::Function::New(env, ListCertificates, "listCertificates"));

    return exports;
}

NODE_API_MODULE(schannels, Init)
