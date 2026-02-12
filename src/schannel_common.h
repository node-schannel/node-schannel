#ifndef SCHANNEL_COMMON_H
#define SCHANNEL_COMMON_H

// Must be defined before including sspi.h
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>

#include <napi.h>

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>

// ── Constants ──────────────────────────────────────────────

static const DWORD SCHANNEL_ISC_FLAGS =
    ISC_REQ_STREAM |
    ISC_REQ_CONFIDENTIALITY |
    ISC_REQ_REPLAY_DETECT |
    ISC_REQ_SEQUENCE_DETECT |
    ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_EXTENDED_ERROR |
    ISC_REQ_MUTUAL_AUTH |
    ISC_REQ_USE_SUPPLIED_CREDS;

static const int TLS_RECV_BUFFER_SIZE = 16384 + 512; // max TLS record + overhead

// ── Error formatting ───────────────────────────────────────

inline std::string FormatWin32Error(DWORD errorCode) {
    char* msgBuf = nullptr;
    DWORD len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        (LPSTR)&msgBuf, 0, nullptr);
    std::string msg;
    if (len > 0 && msgBuf) {
        msg.assign(msgBuf, len);
        // Trim trailing whitespace
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' '))
            msg.pop_back();
        LocalFree(msgBuf);
    } else {
        msg = "Unknown error";
    }
    return msg;
}

inline std::string FormatSSPIError(SECURITY_STATUS status) {
    std::ostringstream oss;
    switch (status) {
        case SEC_E_OK:                      oss << "SEC_E_OK"; break;
        case SEC_I_CONTINUE_NEEDED:         oss << "SEC_I_CONTINUE_NEEDED"; break;
        case SEC_I_INCOMPLETE_CREDENTIALS:  oss << "SEC_I_INCOMPLETE_CREDENTIALS"; break;
        case SEC_E_INCOMPLETE_MESSAGE:      oss << "SEC_E_INCOMPLETE_MESSAGE"; break;
        case SEC_E_WRONG_PRINCIPAL:         oss << "SEC_E_WRONG_PRINCIPAL"; break;
        case SEC_E_UNTRUSTED_ROOT:          oss << "SEC_E_UNTRUSTED_ROOT"; break;
        case SEC_E_CERT_EXPIRED:            oss << "SEC_E_CERT_EXPIRED"; break;
        case SEC_E_CERT_UNKNOWN:            oss << "SEC_E_CERT_UNKNOWN"; break;
        case SEC_E_INVALID_TOKEN:           oss << "SEC_E_INVALID_TOKEN"; break;
        case SEC_E_LOGON_DENIED:            oss << "SEC_E_LOGON_DENIED"; break;
        case SEC_E_INTERNAL_ERROR:          oss << "SEC_E_INTERNAL_ERROR"; break;
        case SEC_E_NO_CREDENTIALS:          oss << "SEC_E_NO_CREDENTIALS"; break;
        case SEC_E_TARGET_UNKNOWN:          oss << "SEC_E_TARGET_UNKNOWN"; break;
        case SEC_E_ALGORITHM_MISMATCH:      oss << "SEC_E_ALGORITHM_MISMATCH"; break;
        default:                            oss << "SSPI_ERROR"; break;
    }
    oss << " (0x" << std::hex << std::setfill('0') << std::setw(8) << (unsigned long)status << ")";
    return oss.str();
}

inline std::string MakeSSPIErrorMessage(const std::string& context, SECURITY_STATUS status) {
    return context + ": " + FormatSSPIError(status);
}

inline std::string MakeWinsockErrorMessage(const std::string& context) {
    int err = WSAGetLastError();
    std::ostringstream oss;
    oss << context << ": WSA error " << err << " - " << FormatWin32Error(err);
    return oss.str();
}

// ── Thumbprint helpers ─────────────────────────────────────

inline std::string ThumbprintToHex(const BYTE* hash, DWORD hashLen) {
    std::ostringstream oss;
    for (DWORD i = 0; i < hashLen; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    return oss.str();
}

inline bool HexToBytes(const std::string& hex, std::vector<BYTE>& bytes) {
    if (hex.length() % 2 != 0) return false;
    bytes.resize(hex.length() / 2);
    for (size_t i = 0; i < bytes.size(); i++) {
        std::string byteStr = hex.substr(i * 2, 2);
        char* endPtr;
        unsigned long val = strtoul(byteStr.c_str(), &endPtr, 16);
        if (*endPtr != '\0' || val > 255) return false;
        bytes[i] = (BYTE)val;
    }
    return true;
}

// ── Wide string helpers ────────────────────────────────────

inline std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring wide(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &wide[0], len);
    return wide;
}

inline std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &utf8[0], len, nullptr, nullptr);
    return utf8;
}

// ── Store location mapping ─────────────────────────────────

inline DWORD ParseStoreLocation(const std::string& location) {
    if (location == "LocalMachine") return CERT_SYSTEM_STORE_LOCAL_MACHINE;
    return CERT_SYSTEM_STORE_CURRENT_USER; // default
}

// ── SecBuffer/SecBufferDesc RAII helper ─────────────────────

struct SecBufferDescWrapper {
    SecBufferDesc desc;
    std::vector<SecBuffer> buffers;

    SecBufferDescWrapper(size_t count) : buffers(count) {
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = (unsigned long)count;
        desc.pBuffers = buffers.data();
        for (auto& buf : buffers) {
            buf.cbBuffer = 0;
            buf.BufferType = SECBUFFER_EMPTY;
            buf.pvBuffer = nullptr;
        }
    }
};

#endif // SCHANNEL_COMMON_H
