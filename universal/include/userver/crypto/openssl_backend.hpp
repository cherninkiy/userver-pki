#pragma once

/// @file userver/crypto/openssl_backend.hpp
/// @brief OpenSSL-backed implementation of CryptoBackend.

#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <userver/crypto/backend_traits.hpp>
#include <userver/crypto/hash.hpp>

/// @cond
// Forward-declare the four OpenSSL struct tags so that this header does not
// need to pull in any <openssl/*.h> header.
struct evp_pkey_st;
struct x509_st;
struct evp_md_ctx_st;
struct ssl_ctx_st;
/// @endcond

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @brief OpenSSL-backed CryptoBackend implementation.
///
/// All static methods declared here are defined in `openssl_backend.cpp`.
/// No `<openssl/*.h>` header is included from here; all OpenSSL includes are
/// confined to the implementation file.
struct OpenSslBackend {
    // ------------------------------------------------------------------ types

    /// @cond
    using NativeKeyHandle = evp_pkey_st;
    using NativeCertHandle = x509_st;
    using NativeCtxHandle = evp_md_ctx_st;
    using NativeSslCtxHandle = ssl_ctx_st;
    /// @endcond

    // ------------------------------------------------------------ lifecycle

    /// Idempotent OpenSSL initialisation (thread-safe).
    static void Init() noexcept;

    // ------------------------------------------------------------ DSA sign

    /// Sign @p data with @p key using the algorithm selected by @p Type / @p Bits.
    template <DsaType Type, DigestSize Bits>
    static std::string DoSign(NativeKeyHandle* key, std::initializer_list<std::string_view> data);

    /// Sign a pre-hashed @p digest with @p key.
    template <DsaType Type, DigestSize Bits>
    static std::string DoSignDigest(NativeKeyHandle* key, std::string_view digest);

    // ----------------------------------------------------------- DSA verify

    /// Verify @p raw_signature over @p data using @p key (throws on failure).
    template <DsaType Type, DigestSize Bits>
    static void DoVerify(NativeKeyHandle* key, std::initializer_list<std::string_view> data, std::string_view raw_signature);

    /// Verify @p raw_signature over a pre-hashed @p digest (throws on failure).
    template <DsaType Type, DigestSize Bits>
    static void DoVerifyDigest(NativeKeyHandle* key, std::string_view digest, std::string_view raw_signature);

    // ----------------------------------------------------------------- hash

    /// Compute hash using the algorithm identified by @p AlgoTag.
    template <typename AlgoTag>
    static std::string ComputeHash(std::initializer_list<std::string_view> data, hash::OutputEncoding enc);

    /// Compute HMAC using the algorithm identified by @p AlgoTag.
    template <typename AlgoTag>
    static std::string ComputeHmac(
        std::string_view key,
        std::initializer_list<std::string_view> data,
        hash::OutputEncoding enc
    );

    // ------------------------------------------- key / cert validation helpers

    /// Validate that @p key is appropriate for signing with @p Type / @p Bits
    /// (throws crypto::SignError if not).
    template <DsaType Type, DigestSize Bits>
    static void ValidateForSigning(NativeKeyHandle* key, const std::string& algo_name);

    /// Validate that @p key is appropriate for verifying with @p Type / @p Bits
    /// (throws crypto::VerificationError if not).
    template <DsaType Type, DigestSize Bits>
    static void ValidateForVerification(NativeKeyHandle* key, const std::string& algo_name);

    // ------------------------------------------ secure memory helpers

    /// Securely zero-wipe @p s (uses OPENSSL_cleanse internally).
    static void SecureClear(std::string& s) noexcept;

    // ------------------------------------------ native handle loading

    /// Load a private key from a PEM string with an optional @p password.
    static std::shared_ptr<NativeKeyHandle>
    LoadNativePrivateKey(std::string_view pem, std::string_view password);

    /// Load a public key or certificate-wrapped public key from a PEM string.
    static std::shared_ptr<NativeKeyHandle> LoadNativePublicKey(std::string_view pem);

    /// Extract the public key from a certificate.
    static std::shared_ptr<NativeKeyHandle> LoadNativePublicKeyFromCertificate(const NativeCertHandle* cert);

    /// Build a public key from RSA components (modulus and exponent, big-endian).
    static std::shared_ptr<NativeKeyHandle>
    LoadNativeRSAPublicKeyFromComponents(std::string_view modulus, std::string_view exponent);

    /// Build a public key from EC components (curve name, X and Y coordinates).
    static std::shared_ptr<NativeKeyHandle>
    LoadNativeECPublicKeyFromComponents(std::string_view curve, std::string_view x, std::string_view y);

    /// Load a certificate from a PEM string.
    static std::shared_ptr<NativeCertHandle> LoadNativeCertificate(std::string_view pem);

    /// Load a certificate from a PEM string, skipping any leading attributes.
    static std::shared_ptr<NativeCertHandle> LoadNativeCertificateSkippingAttributes(std::string_view pem);

    // --------------------------------------- native handle serialisation helpers

    /// Return the PEM-encoded private key encrypted with @p password
    /// (uses AES-128-CBC).
    static std::optional<std::string> GetPrivateKeyPem(NativeKeyHandle* key, std::string_view password);

    /// Return the PEM-encoded private key in unencrypted form.
    static std::optional<std::string> GetPrivateKeyPemUnencrypted(NativeKeyHandle* key);

    /// Return the PEM-encoded certificate.
    static std::optional<std::string> GetCertificatePem(NativeCertHandle* cert);

    /// Return the RFC 2253 subject string for a certificate.
    static std::string GetCertificateSubject(NativeCertHandle* cert);
};

/// The default backend used when no explicit Backend template argument is given.
using DefaultBackend = OpenSslBackend;

// Verify at translation-unit level that OpenSslBackend satisfies the concept.
static_assert(CryptoBackend<OpenSslBackend>, "OpenSslBackend must satisfy CryptoBackend");

}  // namespace crypto

USERVER_NAMESPACE_END
