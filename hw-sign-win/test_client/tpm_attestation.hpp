#pragma once

#include "test_client/types.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <wincrypt.h>

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <ctime>
#include <format>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ============ PCPTool-compatible helpers ============
static std::vector<uint8_t> Sha1Bytes(const void* data, size_t size) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    std::vector<uint8_t> hashObject;
    std::vector<uint8_t> hash;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA1) failed");
    }
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed");
    }
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGetProperty(HASH_LENGTH) failed");
    }
    hashObject.resize(cbHashObject);
    hash.resize(cbHash);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptCreateHash failed");
    }
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)size, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptHashData failed");
    }
    if (BCryptFinishHash(hHash, hash.data(), cbHash, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptFinishHash failed");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}


// ============ TPM Attestation Structures ============
struct TPMInfo {
    std::string manufacturer;
    std::string firmwareVersion;
    uint32_t tpmVersion;
    std::string platformType;
};

struct TPMCertificateChain {
    std::vector<uint8_t> ekPub;            // EK Public Key
    std::vector<uint8_t> aikPub;           // AIK Public Key
    std::vector<uint8_t> aikName;          // TPM2B_NAME of AIK
    std::vector<std::vector<uint8_t>> ekCerts;   // All EK certs found (DER)
    std::vector<std::vector<uint8_t>> ekNvCerts; // All EK NV certs found (DER)
    std::vector<std::vector<uint8_t>> eicaCerts; // Embedded Intermediate CA certs (Intel/AMD etc.)
    std::map<std::string, std::vector<uint8_t>> nvIndexBlobs; // NV index -> raw bytes (best-effort)
};

struct KeyAttestationBlob {
    std::vector<uint8_t> attestationBlob;  // TPM2B_ATTEST structure (certifyInfo)
    std::vector<uint8_t> signature;         // Signature over attestation
    std::vector<uint8_t> aikPub;            // Public key of AIK used for signing
    std::vector<uint8_t> keyName;           // TPM2B_NAME of the attested key
    std::vector<uint8_t> keyBlob;           // Opaque PCP key blob of attested key
    std::string keyType;                    // Type of attested key
};

// ============ TPM2.0 Command Buffer Helpers ============
namespace Tpm2CmdHelper {
    // Big-endian write helpers
    inline void writeU8(std::vector<uint8_t>& buf, uint8_t v) {
        buf.push_back(v);
    }
    inline void writeU16(std::vector<uint8_t>& buf, uint16_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    inline void writeU32(std::vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    inline void writeBytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
        buf.insert(buf.end(), data, data + len);
    }
    inline void setU32At(std::vector<uint8_t>& buf, size_t offset, uint32_t v) {
        buf[offset + 0] = static_cast<uint8_t>((v >> 24) & 0xFF);
        buf[offset + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        buf[offset + 2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        buf[offset + 3] = static_cast<uint8_t>(v & 0xFF);
    }

    // Big-endian read helpers
    inline uint16_t readU16(const uint8_t* p) {
        return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
    }
    inline uint32_t readU32(const uint8_t* p) {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) |
               static_cast<uint32_t>(p[3]);
    }
}

// ============ TPM Attestation Helper Class ============
class TPMAttestationHelper {
private:
    NCRYPT_PROV_HANDLE hProvider_ = NULL;
    NCRYPT_KEY_HANDLE hAikKey_ = NULL;
    TPMInfo tpmInfo_;
    TPMCertificateChain certChain_;
    bool initialized_ = false;

public:
    TPMAttestationHelper() {
        // Open the Platform Crypto Provider
        SECURITY_STATUS status = NCryptOpenStorageProvider(
            &hProvider_,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0
        );
        if (FAILED(status)) {
            std::cerr << "Failed to open Platform Crypto Provider: 0x" 
                      << std::hex << status << std::dec << std::endl;
            return;
        }

        // Collect TPM information
        collectTPMInfo();
        initialized_ = true;
        std::cout << "TPM Attestation Helper initialized successfully" << std::endl;
    }

    ~TPMAttestationHelper() {
        if (hAikKey_) {
            NCryptDeleteKey(hAikKey_, 0);
            NCryptFreeObject(hAikKey_);
        }
        if (hProvider_) {
            NCryptFreeObject(hProvider_);
        }
    }

    bool isInitialized() const { return initialized_; }

    // Collect basic TPM information
    void collectTPMInfo() {
        std::cout << "\n=== Collecting TPM Information ===" << std::endl;
        // IMPORTANT:
        // PCPTool reads EKCert/EKPub from the PROVIDER handle (MS_PLATFORM_CRYPTO_PROVIDER),
        // not from an arbitrary temp key handle. On many machines the key-handle properties are N/A.
        queryProviderInfo();
        collectEKCertificateFromProvider();
    }

    void queryProviderInfo() {
        // Provider version
        WCHAR wbuf[512] = {0};
        DWORD cb = 0;
        if (SUCCEEDED(NCryptGetProperty(hProvider_, BCRYPT_PCP_PROVIDER_VERSION_PROPERTY, (PBYTE)wbuf, sizeof(wbuf) - sizeof(WCHAR), &cb, 0))) {
            wbuf[cb / sizeof(WCHAR)] = 0;
            int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                std::string s(len - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, &s[0], len, NULL, NULL);
                tpmInfo_.firmwareVersion = s;
                std::cout << "Provider Version: " << s << std::endl;
            }
        }

        // Platform type string (contains VendorID:'INTC' etc.)
        ZeroMemory(wbuf, sizeof(wbuf));
        cb = 0;
        if (SUCCEEDED(NCryptGetProperty(hProvider_, BCRYPT_PCP_PLATFORM_TYPE_PROPERTY, (PBYTE)wbuf, sizeof(wbuf) - sizeof(WCHAR), &cb, 0))) {
            wbuf[cb / sizeof(WCHAR)] = 0;
            int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                std::string s(len - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, &s[0], len, NULL, NULL);
                tpmInfo_.platformType = s;
                std::cout << "Platform Type: " << s << std::endl;
                // Parse VendorID:'XXXX'
                auto pos = s.find("VendorID:'");
                if (pos != std::string::npos) {
                    auto start = pos + 10;
                    auto end = s.find("'", start);
                    if (end != std::string::npos) {
                        tpmInfo_.manufacturer = s.substr(start, end - start);
                        std::cout << "Manufacturer: " << tpmInfo_.manufacturer << std::endl;
                    }
                }
            }
        }

        // TPM version DWORD (1/2)
        DWORD tpmVer = 0;
        cb = 0;
        if (SUCCEEDED(NCryptGetProperty(hProvider_, NCRYPT_PCP_TPM_VERSION_PROPERTY, (PBYTE)&tpmVer, sizeof(tpmVer), &cb, 0))) {
            // Some systems return 0x00020000 for TPM 2.0, others return 2.
            uint32_t major = (tpmVer >> 16) & 0xFFFF;
            uint32_t minor = tpmVer & 0xFFFF;
            if (major == 0 && (tpmVer == 1 || tpmVer == 2)) {
                tpmInfo_.tpmVersion = tpmVer;
                std::cout << "TPM Version: " << (tpmVer == 2 ? "2.0" : "1.2") << std::endl;
            } else if (major != 0) {
                // Normalize to major only for server logic (2 => TPM2.0)
                tpmInfo_.tpmVersion = major;
                std::cout << "TPM Version: " << major << "." << minor << " (raw: 0x" << std::hex << tpmVer << std::dec << ")" << std::endl;
            } else {
                tpmInfo_.tpmVersion = tpmVer;
                std::cout << "TPM Version: " << "raw: 0x" << std::hex << tpmVer << std::dec << std::endl;
            }
        }
    }

    void queryTPMProperty(NCRYPT_KEY_HANDLE hKey, LPCWSTR propertyName, 
                          const char* displayName, std::string& outValue) {
        DWORD cbResult = 0;
        SECURITY_STATUS status = NCryptGetProperty(hKey, propertyName, NULL, 0, &cbResult, 0);
        
        if (SUCCEEDED(status) && cbResult > 0) {
            std::vector<BYTE> buffer(cbResult);
            status = NCryptGetProperty(hKey, propertyName, buffer.data(), cbResult, &cbResult, 0);
            if (SUCCEEDED(status)) {
                // Handle string property
                if (cbResult >= 2 && buffer[cbResult-1] == 0 && buffer[cbResult-2] == 0) {
                    // Wide string
                    outValue = std::string((char*)buffer.data(), cbResult);
                } else {
                    // Binary data - convert to hex
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0');
                    for (DWORD i = 0; i < cbResult; i++) {
                        ss << std::setw(2) << (int)buffer[i];
                    }
                    outValue = ss.str();
                }
                std::cout << displayName << ": " << outValue << std::endl;
            }
        } else {
            std::cout << displayName << ": Not available" << std::endl;
        }
    }

    void queryTPMPropertyDword(NCRYPT_KEY_HANDLE hKey, LPCWSTR propertyName,
                               const char* displayName, uint32_t& outValue) {
        DWORD cbResult = 0;
        SECURITY_STATUS status = NCryptGetProperty(hKey, propertyName, NULL, 0, &cbResult, 0);
        
        if (SUCCEEDED(status) && cbResult >= sizeof(DWORD)) {
            DWORD value = 0;
            status = NCryptGetProperty(hKey, propertyName, (PBYTE)&value, sizeof(value), &cbResult, 0);
            if (SUCCEEDED(status)) {
                outValue = value;
                std::cout << displayName << ": " << value << std::endl;
            }
        } else {
            std::cout << displayName << ": Not available" << std::endl;
        }
    }

    // Collect EK certificate chain from provider (PCPTool style)
    void collectEKCertificateFromProvider() {
        std::cout << "\n=== Collecting EK Certificate Chain ===" << std::endl;

        auto readAllCertsFromStoreProperty = [&](LPCWSTR propName, const char* label, std::vector<std::vector<uint8_t>>& out) {
            HCERTSTORE hStore = NULL;
            DWORD cbhStore = 0;
            SECURITY_STATUS st = NCryptGetProperty(
                hProvider_,
                propName,
                (PBYTE)&hStore,
                sizeof(hStore),
                &cbhStore,
                0
            );
            if (FAILED(st) || hStore == NULL) {
                std::cout << "  " << label << ": Not available" << std::endl;
                return;
            }

            PCCERT_CONTEXT ctx = NULL;
            uint32_t count = 0;
            while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != NULL) {
                if (ctx->pbCertEncoded && ctx->cbCertEncoded) {
                    std::vector<uint8_t> der(ctx->pbCertEncoded, ctx->pbCertEncoded + ctx->cbCertEncoded);
                    out.push_back(der);
                    count++;
                }
            }
            if (count == 0) {
                std::cout << "  " << label << ": empty store" << std::endl;
            } else {
                std::cout << "✓ " << label << ": " << count << " cert(s)" << std::endl;
            }
            CertCloseStore(hStore, 0);
        };

        readAllCertsFromStoreProperty(NCRYPT_PCP_EKCERT_PROPERTY, "EK Certificate (store)", certChain_.ekCerts);
        readAllCertsFromStoreProperty(NCRYPT_PCP_EKNVCERT_PROPERTY, "EK NV Certificate (store)", certChain_.ekNvCerts);

        // EK public key from provider
        DWORD cbResult = 0;
        SECURITY_STATUS status = NCryptGetProperty(hProvider_, NCRYPT_PCP_EKPUB_PROPERTY, NULL, 0, &cbResult, 0);
        if (SUCCEEDED(status) && cbResult > 0) {
            certChain_.ekPub.resize(cbResult);
            status = NCryptGetProperty(hProvider_, NCRYPT_PCP_EKPUB_PROPERTY,
                                       certChain_.ekPub.data(), cbResult, &cbResult, 0);
            if (SUCCEEDED(status)) {
                std::cout << "✓ EK Public Key: " << cbResult << " bytes" << std::endl;
            }
        } else {
            std::cout << "  EK Public Key: Not available" << std::endl;
        }

        collectEICACertificates();
        collectNVIndexCertsBestEffort();
    }

    // Best-effort: read common EK / EK chain NV indices directly via TBS (TPM2.0).
    // We do NOT try to parse/convert here; we just upload raw bytes to server for vendor-specific parsing.
    void collectNVIndexCertsBestEffort() {
        std::cout << "\n=== Collecting NV Index Certs (best-effort) ===" << std::endl;
        DWORD cb = 0;
        TBS_HCONTEXT hTbs = 0;
        SECURITY_STATUS st = NCryptGetProperty(hProvider_, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, (PBYTE)&hTbs, sizeof(hTbs), &cb, 0);
        if (FAILED(st)) {
            std::cout << "  TBS handle not available" << std::endl;
            return;
        }

        auto u32hex = [](uint32_t v) {
            std::stringstream ss;
            ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << v;
            return ss.str();
        };

        auto readU16 = [](const uint8_t* p) -> uint16_t {
            return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
        };
        auto readU32 = [](const uint8_t* p) -> uint32_t {
            return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        };
        auto writeU16 = [](std::vector<uint8_t>& b, uint16_t v) {
            b.push_back(uint8_t((v >> 8) & 0xFF));
            b.push_back(uint8_t(v & 0xFF));
        };
        auto writeU32 = [](std::vector<uint8_t>& b, uint32_t v) {
            b.push_back(uint8_t((v >> 24) & 0xFF));
            b.push_back(uint8_t((v >> 16) & 0xFF));
            b.push_back(uint8_t((v >> 8) & 0xFF));
            b.push_back(uint8_t(v & 0xFF));
        };
        auto setU32At = [](std::vector<uint8_t>& b, size_t off, uint32_t v) {
            b[off + 0] = uint8_t((v >> 24) & 0xFF);
            b[off + 1] = uint8_t((v >> 16) & 0xFF);
            b[off + 2] = uint8_t((v >> 8) & 0xFF);
            b[off + 3] = uint8_t(v & 0xFF);
        };

        auto nvReadPublic = [&](uint32_t nvIndex, uint16_t& outDataSize) -> bool {
            // TPM2_NV_ReadPublic: CC=0x00000169, no sessions
            std::vector<uint8_t> cmd;
            cmd.reserve(64);
            writeU16(cmd, 0x8001);          // TPM_ST_NO_SESSIONS
            writeU32(cmd, 0);               // size
            writeU32(cmd, 0x00000169);      // TPM_CC_NV_ReadPublic
            writeU32(cmd, nvIndex);         // nvIndex
            setU32At(cmd, 2, (uint32_t)cmd.size());

            std::vector<uint8_t> rsp(2048);
            UINT32 cbRsp = (UINT32)rsp.size();
            TBS_RESULT tr = Tbsip_Submit_Command(hTbs, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                cmd.data(), (UINT32)cmd.size(), rsp.data(), &cbRsp);
            if (tr != TBS_SUCCESS) return false;
            if (cbRsp < 10) return false;
            size_t pos = 0;
            pos += 2;
            uint32_t respSize = readU32(&rsp[pos]); pos += 4;
            uint32_t respCode = readU32(&rsp[pos]); pos += 4;
            if (respSize != cbRsp || respCode != 0) return false;
            // outPublic: TPM2B_NV_PUBLIC (size u16 + body)
            if (pos + 2 > cbRsp) return false;
            uint16_t outPublicSize = readU16(&rsp[pos]); pos += 2;
            if (pos + outPublicSize > cbRsp) return false;
            // Parse NV_PUBLIC from outPublic body to get dataSize:
            // nvIndex(4) nameAlg(2) attributes(4) authPolicy(2+N) dataSize(2)
            if (outPublicSize < 4 + 2 + 4 + 2 + 2) return false;
            size_t p2 = pos;
            p2 += 4; // nvIndex
            p2 += 2; // nameAlg
            p2 += 4; // attributes
            if (p2 + 2 > pos + outPublicSize) return false;
            uint16_t authPolicySize = readU16(&rsp[p2]); p2 += 2;
            if (p2 + authPolicySize > pos + outPublicSize) return false;
            p2 += authPolicySize;
            if (p2 + 2 > pos + outPublicSize) return false;
            outDataSize = readU16(&rsp[p2]);
            return true;
        };

        auto nvRead = [&](uint32_t nvIndex, uint16_t size, uint16_t offset, std::vector<uint8_t>& outData) -> bool {
            // TPM2_NV_Read: CC=0x0000014E, requires sessions (use password session with empty auth)
            std::vector<uint8_t> cmd;
            cmd.reserve(128);
            writeU16(cmd, 0x8002);     // TPM_ST_SESSIONS
            writeU32(cmd, 0);          // size
            writeU32(cmd, 0x0000014E); // TPM_CC_NV_Read
            writeU32(cmd, nvIndex);    // authHandle
            writeU32(cmd, nvIndex);    // nvIndex
            // authSize = one session: TPM_RS_PW + nonce(0) + attr(0) + hmac(0)
            writeU32(cmd, (uint32_t)(4 + 2 + 1 + 2));
            writeU32(cmd, 0x40000009); // TPM_RS_PW
            writeU16(cmd, 0x0000);     // nonce
            cmd.push_back(0x00);       // sessionAttributes
            writeU16(cmd, 0x0000);     // hmac size
            // params
            writeU16(cmd, size);
            writeU16(cmd, offset);
            setU32At(cmd, 2, (uint32_t)cmd.size());

            std::vector<uint8_t> rsp(4096);
            UINT32 cbRsp = (UINT32)rsp.size();
            TBS_RESULT tr = Tbsip_Submit_Command(hTbs, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                cmd.data(), (UINT32)cmd.size(), rsp.data(), &cbRsp);
            if (tr != TBS_SUCCESS) return false;
            if (cbRsp < 10) return false;
            size_t pos = 0;
            pos += 2;
            uint32_t respSize = readU32(&rsp[pos]); pos += 4;
            uint32_t respCode = readU32(&rsp[pos]); pos += 4;
            if (respSize != cbRsp || respCode != 0) return false;
            // parameterSize (u32)
            if (pos + 4 > cbRsp) return false;
            pos += 4;
            // data: TPM2B_MAX_NV_BUFFER (u16 size + bytes)
            if (pos + 2 > cbRsp) return false;
            uint16_t dataSize = readU16(&rsp[pos]); pos += 2;
            if (pos + dataSize > cbRsp) return false;
            outData.assign(&rsp[pos], &rsp[pos + dataSize]);
            return true;
        };

        auto readFullNV = [&](uint32_t nvIndex) -> bool {
            uint16_t total = 0;
            if (!nvReadPublic(nvIndex, total) || total == 0) return false;
            std::vector<uint8_t> all;
            all.reserve(total);
            uint16_t off = 0;
            while (off < total) {
                uint16_t chunk = (uint16_t)std::min<uint32_t>(512, total - off);
                std::vector<uint8_t> part;
                if (!nvRead(nvIndex, chunk, off, part)) return false;
                all.insert(all.end(), part.begin(), part.end());
                off = (uint16_t)(off + chunk);
            }
            certChain_.nvIndexBlobs[u32hex(nvIndex)] = std::move(all);
            return true;
        };

        // Common EK cert indices (TCG EK Credential Profile)
        const uint32_t nvList[] = {
            0x01C00002, // RSA EKCert
            0x01C0000A, // ECC EKCert
        };
        for (uint32_t idx : nvList) {
            if (readFullNV(idx)) {
                std::cout << "✓ NV " << u32hex(idx) << " read" << std::endl;
            }
        }

        // EK chain range (Intel PTT often uses 0x01C00100+)
        for (uint32_t idx = 0x01C00100; idx <= 0x01C00105; idx++) {
            if (readFullNV(idx)) {
                std::cout << "✓ NV " << u32hex(idx) << " read" << std::endl;
            }
        }
    }

    void collectEICACertificates() {
        std::cout << "\n=== Collecting EICA Certificates ===" << std::endl;
        HKEY hKey = NULL;
        LPCWSTR keyPath = L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement\\IntermediateCACertStore\\Certificates";
        LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            std::cout << "  EICA registry key not found" << std::endl;
            return;
        }

        // Registry "Blob" entries are not always raw DER. On many systems they wrap DER cert(s)
        // with a small header/metadata. We extract embedded X.509 cert(s) in DER form.
        auto extractDerCertsFromRegistryBlob = [&](const std::vector<uint8_t>& blob) -> std::vector<std::vector<uint8_t>> {
            std::vector<std::vector<uint8_t>> out;
            if (blob.size() < 4) return out;

            auto tryParseAt = [&](size_t off, size_t& outLen) -> bool {
                if (off + 2 > blob.size()) return false;
                if (blob[off] != 0x30) return false; // ASN.1 SEQUENCE
                uint8_t len1 = blob[off + 1];
                size_t hdr = 2;
                size_t len = 0;
                if (len1 < 0x80) {
                    len = len1;
                } else if (len1 == 0x81) {
                    if (off + 3 > blob.size()) return false;
                    len = blob[off + 2];
                    hdr = 3;
                } else if (len1 == 0x82) {
                    if (off + 4 > blob.size()) return false;
                    len = (size_t(blob[off + 2]) << 8) | size_t(blob[off + 3]);
                    hdr = 4;
                } else {
                    return false;
                }
                size_t total = hdr + len;
                if (off + total > blob.size()) return false;

                PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, blob.data() + off, (DWORD)total);
                if (!ctx) return false;
                CertFreeCertificateContext(ctx);
                outLen = total;
                return true;
            };

            // Scan for DER cert(s)
            for (size_t i = 0; i + 4 < blob.size(); ) {
                size_t derLen = 0;
                if (tryParseAt(i, derLen)) {
                    out.emplace_back(blob.begin() + (ptrdiff_t)i, blob.begin() + (ptrdiff_t)(i + derLen));
                    i += derLen;
                    continue;
                }
                i++;
            }
            return out;
        };

        // Enumerate subkeys and read their "Blob" value (your registry screenshot):
        // HKLM\...\IntermediateCACertStore\Certificates\<hash>\Blob
        {
            DWORD idx = 0;
            WCHAR subKeyName[512];
            DWORD subKeyNameLen = 512;
            while (true) {
                subKeyNameLen = 512;
                LSTATUS er = RegEnumKeyExW(hKey, idx, subKeyName, &subKeyNameLen, NULL, NULL, NULL, NULL);
                if (er == ERROR_NO_MORE_ITEMS) break;
                if (er != ERROR_SUCCESS) break;

                HKEY hSub = NULL;
                if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    DWORD dataType = 0;
                    DWORD dataSize = 0;
                    if (RegQueryValueExW(hSub, L"Blob", NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS &&
                        dataType == REG_BINARY && dataSize > 0) {
                        std::vector<uint8_t> certData(dataSize);
                        DWORD dataSize2 = dataSize;
                        if (RegQueryValueExW(hSub, L"Blob", NULL, &dataType, certData.data(), &dataSize2) == ERROR_SUCCESS) {
                            certData.resize(dataSize2);
                            auto ders = extractDerCertsFromRegistryBlob(certData);
                            if (ders.empty()) {
                                std::wcout << L"  EICA blob " << subKeyName << L" did not contain parsable DER cert" << std::endl;
                            } else {
                                for (auto& der : ders) {
                                    certChain_.eicaCerts.push_back(std::move(der));
                                }
                                std::wcout << L"✓ EICA cert subkey " << subKeyName << L"\\Blob: " << ders.size() << L" DER cert(s)" << std::endl;
                            }
                        }
                    }
                    RegCloseKey(hSub);
                }
                idx++;
            }
        }

        RegCloseKey(hKey);
        std::cout << "  Total EICA certs: " << certChain_.eicaCerts.size() << std::endl;
    }

    // Create an AIK (Attestation Identity Key)
    // PCPTool-style AIK creation:
    // - Uses MS_PLATFORM_CRYPTO_PROVIDER
    // - Sets NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY = NCRYPT_PCP_IDENTITY_KEY
    // - Optionally sets NCRYPT_PCP_TPM12_IDBINDING_PROPERTY to SHA1(nonce) to create IdBinding
    // - Optionally sets NCRYPT_PIN_PROPERTY for usageAuth (PIN)
    bool createAIK(const std::wstring& aikName, const std::wstring& nonce = L"", const std::wstring& usageAuth = L"") {
        std::wcout << L"\n=== Creating AIK (PCPTool style) ===" << std::endl;

        if (hAikKey_) {
            NCryptDeleteKey(hAikKey_, 0);
            hAikKey_ = NULL;
        }

        // Create AIK
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            hProvider_,
            &hAikKey_,
            BCRYPT_RSA_ALGORITHM,  // AIK is typically RSA for compatibility
            aikName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG
        );

        if (FAILED(status)) {
            std::cerr << "Failed to create AIK: 0x" << std::hex << status << std::dec << std::endl;
            return false;
        }

        // Optional: usageAuth (PIN) - PCPTool uses NCRYPT_PIN_PROPERTY
        if (!usageAuth.empty()) {
            status = NCryptSetProperty(
                hAikKey_,
                NCRYPT_PIN_PROPERTY,
                (PBYTE)usageAuth.c_str(),
                (DWORD)((usageAuth.size() + 1) * sizeof(wchar_t)),
                0);
            if (FAILED(status)) {
                std::cerr << "Failed to set AIK PIN: 0x" << std::hex << status << std::dec << std::endl;
                return false;
            }
        }

        // PCPTool: NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY = NCRYPT_PCP_IDENTITY_KEY
        DWORD dwKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
        status = NCryptSetProperty(
            hAikKey_,
            NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
            (PBYTE)&dwKeyUsage,
            sizeof(dwKeyUsage),
            0);
        if (FAILED(status)) {
            std::cerr << "Failed to set AIK usage policy: 0x" << std::hex << status << std::dec << std::endl;
            return false;
        }

        // Optional: nonce -> SHA1 digest -> NCRYPT_PCP_TPM12_IDBINDING_PROPERTY (creates IdentityBinding)
        if (!nonce.empty()) {
            auto nonceDigest = Sha1Bytes(nonce.data(), nonce.size() * sizeof(wchar_t));
            if (nonceDigest.size() != 20) {
                std::cerr << "Unexpected SHA1 size" << std::endl;
                return false;
            }
            status = NCryptSetProperty(
                hAikKey_,
                NCRYPT_PCP_TPM12_IDBINDING_PROPERTY,
                (PBYTE)nonceDigest.data(),
                (DWORD)nonceDigest.size(),
                0);
            if (FAILED(status)) {
                std::cerr << "Failed to set AIK IdBinding nonce digest: 0x" << std::hex << status << std::dec << std::endl;
                return false;
            }
        }

        // Finalize the AIK
        status = NCryptFinalizeKey(hAikKey_, 0);
        if (FAILED(status)) {
            std::cerr << "Failed to finalize AIK: 0x" << std::hex << status << std::dec << std::endl;
            NCryptFreeObject(hAikKey_);
            hAikKey_ = NULL;
            return false;
        }

        // Export AIK public key (BCRYPT_RSAPUBLIC_BLOB) like PCPTool
        DWORD cbResult = 0;
        status = NCryptExportKey(hAikKey_, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cbResult, 0);
        if (SUCCEEDED(status) && cbResult > 0) {
            certChain_.aikPub.resize(cbResult);
            status = NCryptExportKey(hAikKey_, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL,
                                     certChain_.aikPub.data(), cbResult, &cbResult, 0);
            if (SUCCEEDED(status)) {
                std::cout << "✓ AIK created and public key exported, size: " << cbResult << " bytes" << std::endl;
            }
        }

        // Get AIK TPM2B_NAME
        status = NCryptGetProperty(hAikKey_, NCRYPT_PCP_TPM2BNAME_PROPERTY, NULL, 0, &cbResult, 0);
        if (SUCCEEDED(status) && cbResult > 0) {
            certChain_.aikName.resize(cbResult);
            status = NCryptGetProperty(hAikKey_, NCRYPT_PCP_TPM2BNAME_PROPERTY,
                                       certChain_.aikName.data(), cbResult, &cbResult, 0);
            if (SUCCEEDED(status)) {
                std::cout << "✓ AIK TPM2B_NAME retrieved, size: " << cbResult << " bytes" << std::endl;
            }
        }

        return true;
    }

    // PCPTool-style: export IdentityBinding blob if present
    std::vector<uint8_t> exportIdBinding() {
        std::vector<uint8_t> out;
        if (!hAikKey_) return out;
        DWORD cb = 0;
        SECURITY_STATUS status = NCryptGetProperty(hAikKey_, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, nullptr, 0, &cb, 0);
        if (FAILED(status) || cb == 0) return out;
        out.resize(cb);
        status = NCryptGetProperty(hAikKey_, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, out.data(), cb, &cb, 0);
        if (FAILED(status)) return {};
        out.resize(cb);
        return out;
    }

    // PCPTool-style: ActivateCredential via NCrypt property (works for TPM 2.0 in PCP provider)
    // Server provides activation blob (TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET).
    std::vector<uint8_t> activateAIK(const std::vector<uint8_t>& activationBlob) {
        if (!hAikKey_) {
            throw std::runtime_error("AIK not available");
        }
        if (activationBlob.empty()) {
            throw std::runtime_error("activationBlob is empty");
        }

        SECURITY_STATUS status = NCryptSetProperty(
            hAikKey_,
            NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
            (PBYTE)activationBlob.data(),
            (DWORD)activationBlob.size(),
            0
        );
        if (FAILED(status)) {
            std::stringstream ss;
            ss << "NCryptSetProperty(NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY) failed: 0x"
               << std::hex << status;
            throw std::runtime_error(ss.str());
        }

        DWORD cbResult = 0;
        status = NCryptGetProperty(
            hAikKey_,
            NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
            NULL,
            0,
            &cbResult,
            0
        );
        if (FAILED(status) || cbResult == 0) {
            std::stringstream ss;
            ss << "NCryptGetProperty(IDACTIVATION size) failed: 0x" << std::hex << status;
            throw std::runtime_error(ss.str());
        }

        std::vector<uint8_t> secret(cbResult);
        status = NCryptGetProperty(
            hAikKey_,
            NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
            secret.data(),
            (DWORD)secret.size(),
            &cbResult,
            0
        );
        if (FAILED(status)) {
            std::stringstream ss;
            ss << "NCryptGetProperty(IDACTIVATION data) failed: 0x" << std::hex << status;
            throw std::runtime_error(ss.str());
        }
        secret.resize(cbResult);
        return secret;
    }

    // Create a fresh ECDSA P-256 signing key in TPM (best-effort, persisted then returned as handle).
    // Caller should NCryptDeleteKey/NCryptFreeObject when done if they don't want it persisted.
    NCRYPT_KEY_HANDLE createTpmEcdsaP256Key(const std::wstring& keyName) {
        NCRYPT_KEY_HANDLE hKey = NULL;
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            hProvider_,
            &hKey,
            BCRYPT_ECDSA_P256_ALGORITHM,
            keyName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG
        );
        if (FAILED(status)) {
            std::stringstream ss;
            ss << "NCryptCreatePersistedKey(ECDSA-P256) failed: 0x" << std::hex << status;
            throw std::runtime_error(ss.str());
        }
        status = NCryptFinalizeKey(hKey, 0);
        if (FAILED(status)) {
            NCryptDeleteKey(hKey, 0);
            NCryptFreeObject(hKey);
            std::stringstream ss;
            ss << "NCryptFinalizeKey(ECDSA-P256) failed: 0x" << std::hex << status;
            throw std::runtime_error(ss.str());
        }
        return hKey;
    }

    // ============ TPM2.0 Key Certification ============
    // Generate Key Attestation - tries NCrypt API first, then falls back to TPM2_Certify
    std::optional<KeyAttestationBlob> generateKeyAttestation(NCRYPT_KEY_HANDLE hTargetKey, 
                                                              const std::string& keyType,
                                                              const std::vector<uint8_t>& nonce = {}) {
        std::cout << "\n=== Generating Key Attestation ===" << std::endl;

        KeyAttestationBlob attestation;
        attestation.keyType = keyType;
        attestation.aikPub = certChain_.aikPub;
        DWORD cbResult = 0;

        // Method 1: Try NCrypt API directly (NCRYPT_PCP_KEYATTESTATION_PROPERTY)
        // This works if the key was created with a registered AIK
        SECURITY_STATUS status = NCryptGetProperty(hTargetKey, NCRYPT_PCP_KEYATTESTATION_PROPERTY,
                                                   NULL, 0, &cbResult, 0);
        if (SUCCEEDED(status) && cbResult > 0) {
            std::vector<uint8_t> attestData(cbResult);
            status = NCryptGetProperty(hTargetKey, NCRYPT_PCP_KEYATTESTATION_PROPERTY,
                                       attestData.data(), cbResult, &cbResult, 0);
            if (SUCCEEDED(status)) {
                std::cout << "✓ Got attestation via NCrypt API (KEYATTESTATION_PROPERTY)" << std::endl;
                std::cout << "  Size: " << cbResult << " bytes" << std::endl;
                
                // This blob contains the full attestation structure
                attestation.attestationBlob = std::move(attestData);
                
                // Get key name and blob
                getKeyNameAndBlob(hTargetKey, attestation);
                return attestation;
            }
        }
        
        std::cout << "  NCrypt KEYATTESTATION_PROPERTY not available, using TPM2_Certify..." << std::endl;

        // Method 2: Use TPM2_Certify directly (requires AIK)
        if (!hAikKey_) {
            std::cerr << "AIK not available, cannot generate attestation" << std::endl;
            return std::nullopt;
        }

        // Get provider and TBS handles
        NCRYPT_PROV_HANDLE hProvAik = NULL;
        if (FAILED(NCryptGetProperty(hAikKey_, NCRYPT_PROVIDER_HANDLE_PROPERTY,
                                     (PBYTE)&hProvAik, sizeof(hProvAik), &cbResult, 0))) {
            std::cerr << "Failed to get AIK provider handle" << std::endl;
            return std::nullopt;
        }

        TBS_HCONTEXT hTbsContext = 0;
        if (FAILED(NCryptGetProperty(hProvAik, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                     (PBYTE)&hTbsContext, sizeof(hTbsContext), &cbResult, 0))) {
            std::cerr << "Failed to get TBS context handle" << std::endl;
            return std::nullopt;
        }

        // Get TPM handles for both keys
        uint32_t hTpmAik = 0, hTpmKey = 0;
        if (FAILED(NCryptGetProperty(hAikKey_, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                     (PBYTE)&hTpmAik, sizeof(hTpmAik), &cbResult, 0)) ||
            FAILED(NCryptGetProperty(hTargetKey, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                     (PBYTE)&hTpmKey, sizeof(hTpmKey), &cbResult, 0))) {
            std::cerr << "Failed to get TPM key handles" << std::endl;
            return std::nullopt;
        }

        std::cout << "  AIK TPM handle: 0x" << std::hex << hTpmAik << std::dec << std::endl;
        std::cout << "  Key TPM handle: 0x" << std::hex << hTpmKey << std::dec << std::endl;

        // Get usageAuth if required
        std::vector<uint8_t> aikAuth, keyAuth;
        getKeyUsageAuth(hAikKey_, aikAuth);
        getKeyUsageAuth(hTargetKey, keyAuth);

        // Send TPM2_Certify
        std::vector<uint8_t> certifyInfo, signature;
        if (!sendTpm2Certify(hTbsContext, hTpmAik, hTpmKey, 
                             aikAuth, keyAuth, nonce,
                             certifyInfo, signature)) {
            std::cerr << "TPM2_Certify command failed" << std::endl;
            return std::nullopt;
        }

        attestation.attestationBlob = std::move(certifyInfo);
        attestation.signature = std::move(signature);
        
        std::cout << "✓ TPM2_Certify successful" << std::endl;
        std::cout << "  CertifyInfo: " << attestation.attestationBlob.size() << " bytes" << std::endl;
        std::cout << "  Signature: " << attestation.signature.size() << " bytes" << std::endl;

        getKeyNameAndBlob(hTargetKey, attestation);
        return attestation;
    }

private:
    // Helper: get key TPM2B_NAME and opaque blob
    void getKeyNameAndBlob(NCRYPT_KEY_HANDLE hKey, KeyAttestationBlob& attestation) {
        DWORD cbResult = 0;
        
        // Get TPM2B_NAME
        if (SUCCEEDED(NCryptGetProperty(hKey, NCRYPT_PCP_TPM2BNAME_PROPERTY, 
                                        NULL, 0, &cbResult, 0)) && cbResult > 0) {
            attestation.keyName.resize(cbResult);
            NCryptGetProperty(hKey, NCRYPT_PCP_TPM2BNAME_PROPERTY,
                              attestation.keyName.data(), cbResult, &cbResult, 0);
            std::cout << "  Key TPM2B_NAME: " << cbResult << " bytes" << std::endl;
        }

        // Get opaque key blob
        if (SUCCEEDED(NCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL,
                                      NULL, 0, &cbResult, 0)) && cbResult > 0) {
            attestation.keyBlob.resize(cbResult);
            NCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL,
                            attestation.keyBlob.data(), cbResult, &cbResult, 0);
            std::cout << "  Key blob: " << cbResult << " bytes" << std::endl;
        }
    }

    // Get usageAuth (SHA1 digest of PIN) if key requires authorization
    void getKeyUsageAuth(NCRYPT_KEY_HANDLE hKey, std::vector<uint8_t>& auth) {
        DWORD cbResult = 0;
        BYTE required = 0;
        
        if (FAILED(NCryptGetProperty(hKey, NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
                                     &required, sizeof(required), &cbResult, 0))) {
            return;
        }
        
        if (required) {
            auth.resize(20); // SHA1 digest size
            if (FAILED(NCryptGetProperty(hKey, NCRYPT_PCP_USAGEAUTH_PROPERTY,
                                         auth.data(), (DWORD)auth.size(), &cbResult, 0))) {
                auth.clear();
            }
        }
    }

    // Send TPM2_Certify command via TBS
    // Command: TPM2_Certify (CC 0x00000148)
    // objectHandle = key to be certified
    // signHandle = AIK that will sign the certification
    bool sendTpm2Certify(TBS_HCONTEXT hTbs,
                         uint32_t hAik, uint32_t hKey,
                         const std::vector<uint8_t>& aikAuth,
                         const std::vector<uint8_t>& keyAuth,
                         const std::vector<uint8_t>& nonce,
                         std::vector<uint8_t>& outCertifyInfo,
                         std::vector<uint8_t>& outSignature) {
        using namespace Tpm2CmdHelper;
        
        // Build command buffer
        std::vector<uint8_t> cmd;
        cmd.reserve(512);
        
        // Header
        writeU16(cmd, 0x8002);              // TPM_ST_SESSIONS
        writeU32(cmd, 0);                   // placeholder for commandSize
        writeU32(cmd, 0x00000148);          // TPM_CC_Certify
        
        // Handles
        writeU32(cmd, hKey);                // objectHandle (key to certify)
        writeU32(cmd, hAik);                // signHandle (AIK)
        
        // Authorization area size (calculate first)
        uint32_t authSize = 
            sizeof(uint32_t) +              // authHandle (TPM_RS_PW)
            sizeof(uint16_t) +              // nonceTpm.size = 0
            sizeof(uint8_t) +               // sessionAttributes
            sizeof(uint16_t) +              // hmac.size
            keyAuth.size() +                // keyAuth
            sizeof(uint32_t) +              // authHandle (TPM_RS_PW)
            sizeof(uint16_t) +              // nonceTpm.size = 0
            sizeof(uint8_t) +               // sessionAttributes
            sizeof(uint16_t) +              // hmac.size
            aikAuth.size();                 // aikAuth
        
        writeU32(cmd, authSize);
        
        // Authorization for objectHandle (key)
        writeU32(cmd, 0x40000009);          // TPM_RS_PW (password session)
        writeU16(cmd, 0);                   // nonceTpm = empty
        writeU8(cmd, 0);                    // sessionAttributes = 0
        writeU16(cmd, (uint16_t)keyAuth.size());
        if (!keyAuth.empty()) {
            writeBytes(cmd, keyAuth.data(), keyAuth.size());
        }
        
        // Authorization for signHandle (AIK)
        writeU32(cmd, 0x40000009);          // TPM_RS_PW
        writeU16(cmd, 0);                   // nonceTpm = empty
        writeU8(cmd, 0);                    // sessionAttributes = 0
        writeU16(cmd, (uint16_t)aikAuth.size());
        if (!aikAuth.empty()) {
            writeBytes(cmd, aikAuth.data(), aikAuth.size());
        }
        
        // qualifyingData (nonce)
        writeU16(cmd, (uint16_t)nonce.size());
        if (!nonce.empty()) {
            writeBytes(cmd, nonce.data(), nonce.size());
        }
        
        // inScheme = TPM_ALG_NULL (let TPM use key's default scheme)
        writeU16(cmd, 0x0010);              // TPM_ALG_NULL
        
        // Set commandSize
        setU32At(cmd, 2, (uint32_t)cmd.size());
        
        // Send command
        std::vector<uint8_t> rsp(512);
        UINT32 cbRsp = (UINT32)rsp.size();
        
        TBS_RESULT tbsResult = Tbsip_Submit_Command(
            hTbs,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            cmd.data(),
            (UINT32)cmd.size(),
            rsp.data(),
            &cbRsp
        );
        
        if (tbsResult != TBS_SUCCESS) {
            std::cerr << "Tbsip_Submit_Command failed: 0x" << std::hex << tbsResult << std::dec << std::endl;
            return false;
        }
        
        // Parse response
        if (cbRsp < 10) {
            std::cerr << "Response too short" << std::endl;
            return false;
        }
        
        size_t pos = 0;
        
        // uint16_t tag = readU16(&rsp[pos]); 
        pos += 2;
        uint32_t responseSize = readU32(&rsp[pos]); pos += 4;
        uint32_t responseCode = readU32(&rsp[pos]); pos += 4;
        
        if (responseSize != cbRsp) {
            std::cerr << "Response size mismatch" << std::endl;
            return false;
        }
        
        if (responseCode != 0) {
            std::cerr << "TPM2_Certify failed with code: 0x" << std::hex << responseCode << std::dec << std::endl;
            return false;
        }
        
        // Skip parameterSize
        // uint32_t paramSize = readU32(&rsp[pos]); 
        pos += 4;
        
        // Read certifyInfo (TPM2B_ATTEST)
        uint16_t certifyInfoSize = readU16(&rsp[pos]); pos += 2;
        if (pos + certifyInfoSize > cbRsp) {
            std::cerr << "Invalid certifyInfo size" << std::endl;
            return false;
        }
        outCertifyInfo.assign(&rsp[pos], &rsp[pos + certifyInfoSize]);
        pos += certifyInfoSize;
        
        // Read signature (TPMT_SIGNATURE)
        // First: sigAlg (uint16)
        if (pos + 2 > cbRsp) return false;
        uint16_t sigAlg = readU16(&rsp[pos]); pos += 2;
        
        // For RSASSA: hashAlg (uint16) + sig (TPM2B_PUBLIC_KEY_RSA)
        if (sigAlg == 0x0014) {  // TPM_ALG_RSASSA
            if (pos + 2 > cbRsp) return false;
            // uint16_t hashAlg = readU16(&rsp[pos]); 
            pos += 2;  // hashAlg
            
            if (pos + 2 > cbRsp) return false;
            uint16_t sigSize = readU16(&rsp[pos]); pos += 2;
            
            if (pos + sigSize > cbRsp) return false;
            outSignature.assign(&rsp[pos], &rsp[pos + sigSize]);
            pos += sigSize;
        } 
        // For RSAPSS: hashAlg (uint16) + sig (TPM2B_PUBLIC_KEY_RSA)
        else if (sigAlg == 0x0016) {  // TPM_ALG_RSAPSS
            if (pos + 2 > cbRsp) return false;
            // uint16_t hashAlg = readU16(&rsp[pos]); 
            pos += 2;  // hashAlg
            
            if (pos + 2 > cbRsp) return false;
            uint16_t sigSize = readU16(&rsp[pos]); pos += 2;
            
            if (pos + sigSize > cbRsp) return false;
            outSignature.assign(&rsp[pos], &rsp[pos + sigSize]);
            pos += sigSize;
        }
        // For ECDSA: hashAlg + signatureR + signatureS
        else if (sigAlg == 0x0018) {  // TPM_ALG_ECDSA
            if (pos + 2 > cbRsp) return false;
            // uint16_t hashAlg = readU16(&rsp[pos]); 
            pos += 2;  // hashAlg
            
            // signatureR
            if (pos + 2 > cbRsp) return false;
            uint16_t rSize = readU16(&rsp[pos]); pos += 2;
            size_t rStart = pos;
            pos += rSize;
            
            // signatureS
            if (pos + 2 > cbRsp) return false;
            uint16_t sSize = readU16(&rsp[pos]); pos += 2;
            size_t sStart = pos;
            pos += sSize;
            
            // Combine R and S into signature
            outSignature.clear();
            outSignature.insert(outSignature.end(), &rsp[rStart], &rsp[rStart + rSize]);
            outSignature.insert(outSignature.end(), &rsp[sStart], &rsp[sStart + sSize]);
        }
        else {
            std::cerr << "Unsupported signature algorithm: 0x" << std::hex << sigAlg << std::dec << std::endl;
            return false;
        }
        
        return true;
    }

public:

    // Get the certificate chain for verification
    const TPMCertificateChain& getCertificateChain() const { return certChain_; }
    const TPMInfo& getTPMInfo() const { return tpmInfo_; }
    NCRYPT_KEY_HANDLE getAIKHandle() const { return hAikKey_; }

    // Export certificate chain as JSON
    nlohmann::json exportCertificateChainJson() {
        nlohmann::json chain;
        
        chain["tpm_info"] = {
            {"manufacturer", tpmInfo_.manufacturer},
            {"firmware_version", tpmInfo_.firmwareVersion},
            {"tpm_version", tpmInfo_.tpmVersion},
            {"platform_type", tpmInfo_.platformType}
        };

        if (!certChain_.ekCerts.empty()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& c : certChain_.ekCerts) arr.push_back(base64Encode(c));
            chain["ek_certs"] = arr;
        }
        if (!certChain_.ekNvCerts.empty()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& c : certChain_.ekNvCerts) arr.push_back(base64Encode(c));
            chain["ek_nv_certs"] = arr;
        }
        if (!certChain_.ekPub.empty()) {
            chain["ek_pub"] = base64Encode(certChain_.ekPub);
        }
        if (!certChain_.aikPub.empty()) {
            chain["aik_pub"] = base64Encode(certChain_.aikPub);
        }
        if (!certChain_.aikName.empty()) {
            chain["aik_name"] = base64Encode(certChain_.aikName);
        }

        if (!certChain_.eicaCerts.empty()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& c : certChain_.eicaCerts) {
                arr.push_back(base64Encode(c));
            }
            chain["eica_certs"] = arr;
        }
        if (!certChain_.nvIndexBlobs.empty()) {
            nlohmann::json nv;
            for (const auto& kv : certChain_.nvIndexBlobs) {
                nv[kv.first] = base64Encode(kv.second);
            }
            chain["nv_index_blobs"] = nv;
        }

        return chain;
    }

    // Export key attestation as JSON
    nlohmann::json exportKeyAttestationJson(const KeyAttestationBlob& attestation) {
        nlohmann::json att;
        
        att["key_type"] = attestation.keyType;
        
        if (!attestation.attestationBlob.empty()) {
            att["certify_info"] = base64Encode(attestation.attestationBlob);  // TPMS_ATTEST
        }
        if (!attestation.signature.empty()) {
            att["signature"] = base64Encode(attestation.signature);           // AIK signature
        }
        if (!attestation.aikPub.empty()) {
            att["aik_pub"] = base64Encode(attestation.aikPub);               // AIK public key
        }
        if (!attestation.keyName.empty()) {
            att["key_name"] = base64Encode(attestation.keyName);             // TPM2B_NAME
        }
        if (!attestation.keyBlob.empty()) {
            att["key_blob"] = base64Encode(attestation.keyBlob);             // Opaque PCP blob
        }

        return att;
    }

private:
    std::string base64Encode(const std::vector<uint8_t>& data) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);

        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);

        return result;
    }
};

