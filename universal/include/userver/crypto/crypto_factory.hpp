#pragma once

/// @file userver/crypto/crypto_factory.hpp
/// @brief Compile-time crypto factory parameterised on a `CryptoBackend`.

#include <initializer_list>
#include <string>
#include <string_view>

#include <userver/crypto/backend_traits.hpp>
#include <userver/crypto/certificate.hpp>
#include <userver/crypto/private_key.hpp>
#include <userver/crypto/public_key.hpp>
#include <userver/crypto/signers.hpp>
#include <userver/crypto/verifiers.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @brief Stateless compile-time factory for cryptographic objects.
///
/// All methods are `static` — the struct has no data members, no state and
/// no vtable.  The backend is selected at compile time:
///
/// ```cpp
/// // Default backend (OpenSSL):
/// auto signer = CryptoFactory<>::MakeSigner<DsaType::kRsa, DigestSize::k256>(pem);
///
/// // Explicit backend:
/// auto signer = CryptoFactory<OpenSslBackend>::MakeSigner<DsaType::kRsa, DigestSize::k256>(pem);
///
/// // Stub backend for tests:
/// auto signer = CryptoFactory<NullCryptoBackend>::MakeSigner<DsaType::kRsa, DigestSize::k256>(pem);
/// ```
///
/// @tparam Backend  A type satisfying the `CryptoBackend` concept.
template <CryptoBackend Backend = DefaultBackend>
struct CryptoFactory {
    // --------------------------------------------------------------- key / cert loading

    /// Load a private key from a PEM string with an optional passphrase.
    ///
    /// Calls `Backend::Init()` before parsing.
    /// @throw crypto::KeyParseError on failure.
    static BasicPrivateKey<Backend> LoadPrivateKey(std::string_view pem, std::string_view password = {}) {
        Backend::Init();
        return BasicPrivateKey<Backend>{
            BasicPrivateKey<Backend>::LoadFromString(pem, password)
        };
    }

    /// Load a public key from a PEM string.
    ///
    /// Calls `Backend::Init()` before parsing.
    /// @throw crypto::KeyParseError on failure.
    static BasicPublicKey<Backend> LoadPublicKey(std::string_view pem) {
        Backend::Init();
        return BasicPublicKey<Backend>::LoadFromString(pem);
    }

    /// Load an X.509 certificate from a PEM string.
    ///
    /// Calls `Backend::Init()` before parsing.
    /// @throw crypto::KeyParseError on failure.
    static BasicCertificate<Backend> LoadCertificate(std::string_view pem) {
        Backend::Init();
        return BasicCertificate<Backend>::LoadFromString(pem);
    }

    // --------------------------------------------------------------- hashing

    /// Compute hash using the algorithm identified by @p AlgoTag.
    template <typename AlgoTag>
    static std::string ComputeHash(std::initializer_list<std::string_view> data, hash::OutputEncoding enc) {
        return Backend::template ComputeHash<AlgoTag>(data, enc);
    }

    /// Compute HMAC using the algorithm identified by @p AlgoTag.
    template <typename AlgoTag>
    static std::string ComputeHmac(
        std::string_view key,
        std::initializer_list<std::string_view> data,
        hash::OutputEncoding enc
    ) {
        return Backend::template ComputeHmac<AlgoTag>(key, data, enc);
    }

    // --------------------------------------------------------------- signer / verifier construction

    /// Build a `DsaSigner` for the given algorithm from a PEM-encoded private key.
    template <DsaType T, DigestSize B>
    static DsaSigner<T, B, Backend> MakeSigner(std::string_view privkey_pem, std::string_view password = {}) {
        return DsaSigner<T, B, Backend>{std::string(privkey_pem), std::string(password)};
    }

    /// Build a `DsaVerifier` from an already-loaded public key.
    template <DsaType T, DigestSize B>
    static DsaVerifier<T, B, Backend> MakeVerifier(BasicPublicKey<Backend> pubkey) {
        return DsaVerifier<T, B, Backend>{std::move(pubkey)};
    }

    /// Build a `DsaVerifier` from a PEM-encoded public key or certificate.
    template <DsaType T, DigestSize B>
    static DsaVerifier<T, B, Backend> MakeVerifier(std::string_view pubkey_pem) {
        return DsaVerifier<T, B, Backend>{pubkey_pem};
    }
};

}  // namespace crypto

USERVER_NAMESPACE_END
