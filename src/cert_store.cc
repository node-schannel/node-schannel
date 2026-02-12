#include "cert_store.h"

// ── FileTime → JS epoch ms ────────────────────────────────

double FileTimeToJsTime(const FILETIME& ft) {
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    // FILETIME is 100ns intervals since 1601-01-01
    // JS epoch is ms since 1970-01-01
    // Difference: 11644473600 seconds
    return (double)(ul.QuadPart / 10000ULL) - 11644473600000.0;
}

// ── Check if cert has associated private key ───────────────

bool CertHasPrivateKey(PCCERT_CONTEXT pCert) {
    DWORD cbData = 0;
    return CertGetCertificateContextProperty(
        pCert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cbData) == TRUE;
}

// ── Enumerate certificates ─────────────────────────────────

std::vector<CertInfo> EnumerateCertificates(
    const std::string& storeName,
    const std::string& storeLocation)
{
    std::vector<CertInfo> results;
    std::wstring wStoreName = Utf8ToWide(storeName);
    DWORD flags = ParseStoreLocation(storeLocation);

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        (HCRYPTPROV_LEGACY)0,
        flags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        wStoreName.c_str());

    if (!hStore) return results;

    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr) {
        CertInfo info;

        // Subject
        wchar_t subject[256] = {};
        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject, 256);
        info.subject = WideToUtf8(subject);

        // Issuer
        wchar_t issuer[256] = {};
        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuer, 256);
        info.issuer = WideToUtf8(issuer);

        // Thumbprint (SHA1 hash)
        BYTE hash[20] = {};
        DWORD hashLen = sizeof(hash);
        if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash, &hashLen)) {
            info.thumbprint = ThumbprintToHex(hash, hashLen);
        }

        // Has private key?
        info.hasPrivateKey = CertHasPrivateKey(pCert);

        // Validity
        info.notBefore = FileTimeToJsTime(pCert->pCertInfo->NotBefore);
        info.notAfter = FileTimeToJsTime(pCert->pCertInfo->NotAfter);

        // Friendly name
        wchar_t friendly[256] = {};
        DWORD friendlyLen = sizeof(friendly);
        if (CertGetCertificateContextProperty(pCert, CERT_FRIENDLY_NAME_PROP_ID, friendly, &friendlyLen)) {
            info.friendlyName = WideToUtf8(friendly);
        }

        results.push_back(std::move(info));
    }

    CertCloseStore(hStore, 0);
    return results;
}

// ── Find certificate by subject ────────────────────────────

PCCERT_CONTEXT FindCertificateBySubject(
    HCERTSTORE hStore,
    const std::string& subject)
{
    std::wstring wSubject = Utf8ToWide(subject);
    return CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        wSubject.c_str(),
        nullptr);
}

// ── Find certificate by thumbprint ─────────────────────────

PCCERT_CONTEXT FindCertificateByThumbprint(
    HCERTSTORE hStore,
    const std::string& thumbprintHex)
{
    std::vector<BYTE> hashBytes;
    if (!HexToBytes(thumbprintHex, hashBytes)) return nullptr;

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = (DWORD)hashBytes.size();
    hashBlob.pbData = hashBytes.data();

    return CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &hashBlob,
        nullptr);
}
