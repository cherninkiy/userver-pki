#pragma once

/// @file userver/crypto/null_backend.hpp
/// @brief Stub CryptoBackend for use in tests where real cryptography is not
/// needed.  All operations are no-ops / return empty values and never throw.
///
/// @note This backend must **not** be used in production.

#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <userver/crypto/backend_traits.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @cond  — opaque handle types for NullCryptoBackend
struct NullKeyHandle {};
struct NullCertHandle {};
struct NullCtxHandle {};
struct NullSslCtxHandle {};
/// @endcond

/// @brief A fully-inline stub backend that satisfies `CryptoBackend` but
/// performs no actual cryptographic operations.
///
/// Intended for unit tests that exercise code which is parameterised on a
/// backend but does not exercise the cryptographic primitives themselves.
struct NullCryptoBackend {
    // ------------------------------------------------------------------ types
    /// @cond
    using NativeKeyHandle = NullKeyHandle;
    using NativeCertHandle = NullCertHandle;
    using NativeCtxHandle = NullCtxHandle;
    using NativeSslCtxHandle = NullSslCtxHandle;
    /// @endcond

    // ------------------------------------------------------------ lifecycle
    static void Init() noexcept {}

    // ------------------------------------------------------------ DSA sign

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static std::string DoSign(NativeKeyHandle* /*key*/, std::initializer_list<std::string_view> /*data*/) {
        return {};
    }

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static std::string DoSignDigest(NativeKeyHandle* /*key*/, std::string_view /*digest*/) {
        return {};
    }

    // ----------------------------------------------------------- DSA verify

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static void
    DoVerify(NativeKeyHandle* /*key*/, std::initializer_list<std::string_view> /*data*/, std::string_view /*sig*/) {}

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static void DoVerifyDigest(NativeKeyHandle* /*key*/, std::string_view /*digest*/, std::string_view /*sig*/) {}

    // ----------------------------------------------------------------- hash

    template <typename /*AlgoTag*/>
    static std::string ComputeHash(std::initializer_list<std::string_view> /*data*/, hash::OutputEncoding /*enc*/) {
        return {};
    }

    template <typename /*AlgoTag*/>
    static std::string ComputeHmac(
        std::string_view /*key*/,
        std::initializer_list<std::string_view> /*data*/,
        hash::OutputEncoding /*enc*/
    ) {
        return {};
    }

    // ------------------------------------------- key / cert validation helpers

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static void ValidateForSigning(NativeKeyHandle* /*key*/, const std::string& /*algo_name*/) {}

    template <DsaType /*Type*/, DigestSize /*Bits*/>
    static void ValidateForVerification(NativeKeyHandle* /*key*/, const std::string& /*algo_name*/) {}

    // ------------------------------------------ secure memory helpers

    static void SecureClear(std::string& s) noexcept { s.clear(); }

    // ------------------------------------------ native handle loading

    static std::shared_ptr<NativeKeyHandle>
    LoadNativePrivateKey(std::string_view /*pem*/, std::string_view /*password*/) {
        return std::make_shared<NativeKeyHandle>();
    }

    static std::shared_ptr<NativeKeyHandle> LoadNativePublicKey(std::string_view /*pem*/) {
        return std::make_shared<NativeKeyHandle>();
    }

    static std::shared_ptr<NativeKeyHandle> LoadNativePublicKeyFromCertificate(const NativeCertHandle* /*cert*/) {
        return std::make_shared<NativeKeyHandle>();
    }

    static std::shared_ptr<NativeKeyHandle>
    LoadNativeRSAPublicKeyFromComponents(std::string_view /*modulus*/, std::string_view /*exponent*/) {
        return std::make_shared<NativeKeyHandle>();
    }

    static std::shared_ptr<NativeKeyHandle>
    LoadNativeECPublicKeyFromComponents(std::string_view /*curve*/, std::string_view /*x*/, std::string_view /*y*/) {
        return std::make_shared<NativeKeyHandle>();
    }

    static std::shared_ptr<NativeCertHandle> LoadNativeCertificate(std::string_view /*pem*/) {
        return std::make_shared<NativeCertHandle>();
    }

    static std::shared_ptr<NativeCertHandle> LoadNativeCertificateSkippingAttributes(std::string_view /*pem*/) {
        return std::make_shared<NativeCertHandle>();
    }

    // --------------------------------------- native handle serialisation helpers

    static std::optional<std::string> GetPrivateKeyPem(NativeKeyHandle* /*key*/, std::string_view /*password*/) {
        return {};
    }

    static std::optional<std::string> GetPrivateKeyPemUnencrypted(NativeKeyHandle* /*key*/) { return {}; }

    static std::optional<std::string> GetCertificatePem(NativeCertHandle* /*cert*/) { return {}; }

    static std::string GetCertificateSubject(NativeCertHandle* /*cert*/) { return {}; }
};

// Verify at translation-unit level that NullCryptoBackend satisfies the concept.
static_assert(CryptoBackend<NullCryptoBackend>, "NullCryptoBackend must satisfy CryptoBackend");

}  // namespace crypto

USERVER_NAMESPACE_END
