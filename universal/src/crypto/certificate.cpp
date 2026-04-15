// All Certificate / BasicCertificate<OpenSslBackend> method bodies are now
// defined inline in certificate.hpp (calling OpenSslBackend static methods).
// This file retains the free function LoadCertificatesChainFromString, which
// chains over BEGIN/END markers without needing OpenSSL types directly.

#include <userver/crypto/certificate.hpp>

#include <userver/utils/assert.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

template class BasicCertificate<OpenSslBackend>;

constexpr std::string_view kBeginMarker = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kEndMarker = "-----END CERTIFICATE-----";

CertificatesChain LoadCertificatesChainFromString(std::string_view chain) {
    CertificatesChain certificates;

    std::size_t start = 0;
    while ((start = chain.find(kBeginMarker, start)) != std::string_view::npos) {
        auto end = chain.find(kEndMarker, start);
        UINVARIANT(end != std::string_view::npos, "No matching end marker found for certificate");

        end += kEndMarker.length();
        certificates.push_back(Certificate::LoadFromString(chain.substr(start, end - start)));
        start = end;
    }
    if (certificates.empty()) {
        throw KeyParseError("There are no certificates in chain");
    }

    return certificates;
}

}  // namespace crypto

USERVER_NAMESPACE_END
