#pragma once

/// @file userver/crypto/public_key.hpp
/// @brief @copybrief crypto::PublicKey

#include <memory>
#include <string_view>

#include <userver/crypto/certificate.hpp>
#include <userver/crypto/openssl_backend.hpp>
#include <userver/utils/strong_typedef.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @ingroup userver_universal userver_containers
///
/// Loaded into memory public key parameterised on the crypto backend.
///
/// The default backend is `DefaultBackend` (OpenSSL).  Use the
/// `PublicKey` alias for the common case.
template <typename Backend = DefaultBackend>
class BasicPublicKey {
public:
    using NativeType = typename Backend::NativeKeyHandle;

    /// Modulus wrapper
    using ModulusView = utils::StrongTypedef<class ModulusTag, std::string_view>;

    /// Exponent wrapper
    using ExponentView = utils::StrongTypedef<class ExponentTag, std::string_view>;

    using CoordinateView = utils::StrongTypedef<class CoordinateTag, std::string_view>;

    using CurveTypeView = utils::StrongTypedef<class CurveTypeTag, std::string_view>;

    BasicPublicKey() = default;

    NativeType* GetNative() const noexcept { return pkey_.get(); }
    explicit operator bool() const noexcept { return !!pkey_; }

    /// Accepts a string that contains a certificate or public key, checks that
    /// it's correct, loads it into backend structures and returns as a
    /// BasicPublicKey variable.
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPublicKey LoadFromString(std::string_view key) {
        Backend::Init();
        return BasicPublicKey{Backend::LoadNativePublicKey(key)};
    }

    /// Extracts BasicPublicKey from certificate.
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPublicKey LoadFromCertificate(const BasicCertificate<Backend>& cert) {
        return BasicPublicKey{Backend::LoadNativePublicKeyFromCertificate(cert.GetNative())};
    }

    /// Creates RSA BasicPublicKey from components
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPublicKey LoadRSAFromComponents(ModulusView modulus, ExponentView exponent) {
        return BasicPublicKey{Backend::LoadNativeRSAPublicKeyFromComponents(
            modulus.GetUnderlying(), exponent.GetUnderlying()
        )};
    }

    /// Creates EC BasicPublicKey from components
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPublicKey LoadECFromComponents(CurveTypeView curve, CoordinateView x, CoordinateView y) {
        return BasicPublicKey{Backend::LoadNativeECPublicKeyFromComponents(
            curve.GetUnderlying(), x.GetUnderlying(), y.GetUnderlying()
        )};
    }

private:
    explicit BasicPublicKey(std::shared_ptr<NativeType> pkey)
        : pkey_(std::move(pkey))
    {}

    std::shared_ptr<NativeType> pkey_;
};

/// @brief Backward-compatible alias for the OpenSSL-backed public key type.
using PublicKey = BasicPublicKey<>;

}  // namespace crypto

USERVER_NAMESPACE_END
