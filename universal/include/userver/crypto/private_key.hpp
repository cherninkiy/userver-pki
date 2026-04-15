#pragma once

/// @file userver/crypto/private_key.hpp
/// @brief @copybrief crypto::PrivateKey

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <userver/crypto/openssl_backend.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @ingroup userver_universal userver_containers
///
/// Loaded into memory private key parameterised on the crypto backend.
///
/// The default backend is `DefaultBackend` (OpenSSL).  Use the
/// `PrivateKey` alias for the common case.
template <typename Backend = DefaultBackend>
class BasicPrivateKey {
public:
    using NativeType = typename Backend::NativeKeyHandle;

    BasicPrivateKey() = default;

    NativeType* GetNative() const noexcept { return pkey_.get(); }
    explicit operator bool() const noexcept { return !!pkey_; }

    /// Returns a PEM-encoded representation of stored private key encrypted by
    /// the provided password.
    ///
    /// @throw crypto::SerializationError if the password is empty or
    /// serialization fails.
    std::optional<std::string> GetPemString(std::string_view password) const {
        return Backend::GetPrivateKeyPem(pkey_.get(), password);
    }

    /// Returns a PEM-encoded representation of stored private key in an
    /// unencrypted form.
    ///
    /// @throw crypto::SerializationError if serialization fails.
    std::optional<std::string> GetPemStringUnencrypted() const {
        return Backend::GetPrivateKeyPemUnencrypted(pkey_.get());
    }

    /// Accepts a string that contains a private key and a password, checks the
    /// key and password, loads it into backend structures and returns as a
    /// BasicPrivateKey variable.
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPrivateKey LoadFromString(std::string_view key, std::string_view password) {
        Backend::Init();
        return BasicPrivateKey{Backend::LoadNativePrivateKey(key, password)};
    }

    /// Accepts a string that contains a private key (not protected with
    /// password), checks it, loads it into backend structures and returns as a
    /// BasicPrivateKey variable.
    ///
    /// @throw crypto::KeyParseError if failed to load the key.
    static BasicPrivateKey LoadFromString(std::string_view key) {
        return LoadFromString(key, {});
    }

private:
    explicit BasicPrivateKey(std::shared_ptr<NativeType> pkey)
        : pkey_(std::move(pkey))
    {}

    std::shared_ptr<NativeType> pkey_{};
};

/// @brief Backward-compatible alias for the OpenSSL-backed private key type.
using PrivateKey = BasicPrivateKey<>;

}  // namespace crypto

USERVER_NAMESPACE_END
