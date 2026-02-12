#ifndef SCHANNEL_SOCKET_H
#define SCHANNEL_SOCKET_H

#include "schannel_common.h"

class SchannelSocket : public Napi::ObjectWrap<SchannelSocket> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    SchannelSocket(const Napi::CallbackInfo& info);
    ~SchannelSocket();

    // JS methods
    Napi::Value Connect(const Napi::CallbackInfo& info);
    Napi::Value Write(const Napi::CallbackInfo& info);
    Napi::Value Read(const Napi::CallbackInfo& info);
    Napi::Value Close(const Napi::CallbackInfo& info);
    Napi::Value GetConnected(const Napi::CallbackInfo& info);

    // Internal state (accessed by async workers)
    SOCKET sock_ = INVALID_SOCKET;
    CredHandle credHandle_;
    CtxtHandle ctxtHandle_;
    bool hasCredHandle_ = false;
    bool hasCtxtHandle_ = false;
    bool connected_ = false;
    bool shutdownSent_ = false;
    PCCERT_CONTEXT pCertContext_ = nullptr;
    SecPkgContext_StreamSizes streamSizes_;

    // Extra data from previous decrypt that wasn't consumed
    std::vector<BYTE> extraBuffer_;

    // Connection info (populated after handshake)
    std::string negotiatedProtocol_;
    std::string negotiatedCipher_;
    std::string serverCertSubject_;
    bool mutualAuth_ = false;

    // Cleanup
    void CleanupNative();

private:
    static Napi::FunctionReference constructor;
};

#endif // SCHANNEL_SOCKET_H
