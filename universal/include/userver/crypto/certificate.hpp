#pragma once

/// @file userver/crypto/certificate.hpp
/// @brief @copybrief crypto::Certificate

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <userver/crypto/openssl_backend.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @ingroup userver_universal userver_containers
///
/// Loaded into memory X509 certificate parameterised on the crypto backend.
///
/// The default backend is `DefaultBackend` (OpenSSL).  Use the
/// `Certificate` alias for the common case.
template <typename Backend = DefaultBackend>
class BasicCertificate {
public:
    using NativeType = typename Backend::NativeCertHandle;

    BasicCertificate() = default;

    NativeType* GetNative() const noexcept { return cert_.get(); }
    explicit operator bool() const noexcept { return !!cert_; }

    /// Returns a PEM-encoded representation of stored certificate.
    ///
    /// @throw crypto::SerializationError if serialization fails.
    std::optional<std::string> GetPemString() const {
        return Backend::GetCertificatePem(cert_.get());
    }

    /// Accepts a string that contains a certificate, checks that
    /// it's correct, loads it into backend structures and returns as a
    /// BasicCertificate variable.
    ///
    /// @throw crypto::KeyParseError if failed to load the certificate.
    static BasicCertificate LoadFromString(std::string_view certificate) {
        Backend::Init();
        return BasicCertificate{Backend::LoadNativeCertificate(certificate)};
    }

    /// Loads the certificate and skips the meta information in it.
    ///
    /// @throw crypto::KeyParseError if failed to load the certificate.
    static BasicCertificate LoadFromStringSkippingAttributes(std::string_view certificate) {
        Backend::Init();
        return BasicCertificate{Backend::LoadNativeCertificateSkippingAttributes(certificate)};
    }

    /// Returns Subject
    std::string GetSubject() const {
        return Backend::GetCertificateSubject(cert_.get());
    }

private:
    explicit BasicCertificate(std::shared_ptr<NativeType> cert)
        : cert_(std::move(cert))
    {}

    std::shared_ptr<NativeType> cert_;
};

/// @brief Backward-compatible alias for the OpenSSL-backed certificate type.
using Certificate = BasicCertificate<>;

using CertificatesChain = std::list<Certificate>;

/// Accepts a string that contains a chain of certificates (primary and intermediate), checks that
/// it's correct, loads it into OpenSSL structures and returns as a
/// list of 'Certificate's.
///
/// @throw crypto::KeyParseError if failed to load the certificate.
CertificatesChain LoadCertificatesChainFromString(std::string_view chain);

}  // namespace crypto

USERVER_NAMESPACE_END
