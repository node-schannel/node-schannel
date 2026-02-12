#ifndef CERT_STORE_H
#define CERT_STORE_H

#include "schannel_common.h"

// Certificate info returned to JavaScript
struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string thumbprint;
    bool hasPrivateKey;
    double notBefore; // ms since epoch
    double notAfter;  // ms since epoch
    std::string friendlyName;
};

// Native helpers (called from worker threads)
std::vector<CertInfo> EnumerateCertificates(
    const std::string& storeName,
    const std::string& storeLocation);

PCCERT_CONTEXT FindCertificateBySubject(
    HCERTSTORE hStore,
    const std::string& subject);

PCCERT_CONTEXT FindCertificateByThumbprint(
    HCERTSTORE hStore,
    const std::string& thumbprintHex);

bool CertHasPrivateKey(PCCERT_CONTEXT pCert);

// Convert FILETIME to JS-compatible milliseconds since epoch
double FileTimeToJsTime(const FILETIME& ft);

// N-API registration
Napi::Object InitCertStore(Napi::Env env, Napi::Object exports);

#endif // CERT_STORE_H
