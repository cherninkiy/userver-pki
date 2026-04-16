#pragma once

/// @file userver/crypto/backend_traits.hpp
/// @brief C++20 concept and type tags for compile-time crypto backend selection

#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>

#include <userver/crypto/basic_types.hpp>
#include <userver/crypto/hash.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

/// @brief Hash algorithm tags used as template parameters for backend
/// ComputeHash / ComputeHmac methods.
namespace hash_algo {

/// @warning SHA-1 is cryptographically broken and considered insecure for most
/// use cases since 2017.  NIST officially deprecated SHA-1, recommending
/// migration to SHA-2 or SHA-3 by December 31, 2030.  Practical collision
/// attacks (SHAttered) have demonstrated that two different files can produce
/// the same hash.  Prefer `Sha256`, `Sha384`, or `Sha512`.
struct Sha1 {};    ///< SHA-1 algorithm tag (deprecated — see warning above)
struct Sha256 {};  ///< SHA-256 algorithm tag
struct Sha384 {};  ///< SHA-384 algorithm tag
struct Sha512 {};  ///< SHA-512 algorithm tag

}  // namespace hash_algo

/// @brief Maps DigestSize enum to the corresponding hash_algo tag type.
template <DigestSize Bits>
struct HmacAlgoTag;

/// @cond
template <>
struct HmacAlgoTag<DigestSize::k160> {
    using type = hash_algo::Sha1;
};
template <>
struct HmacAlgoTag<DigestSize::k256> {
    using type = hash_algo::Sha256;
};
template <>
struct HmacAlgoTag<DigestSize::k384> {
    using type = hash_algo::Sha384;
};
template <>
struct HmacAlgoTag<DigestSize::k512> {
    using type = hash_algo::Sha512;
};
/// @endcond

/// @brief C++20 concept satisfied by any type that provides a complete
/// cryptographic backend.
///
/// A conforming backend `B` must supply:
///   - Four nested native-handle type aliases
///   - A static `Init()` (noexcept) — idempotent; safe to call multiple times
///   - A static `Cleanup()` (noexcept) — release global resources (OpenSSL
///     locks, HSM sessions, etc.)
///   - Static template methods for DSA sign/verify (raw-message and pre-hashed)
///   - Static template methods for hash and HMAC computation
///
/// @note Call `Init()` once at process startup (e.g. from a userver component)
///   before any crypto operations.  Call `Cleanup()` at process shutdown to
///   release backend resources.
///
/// @tparam B  Candidate backend type
template <typename B>
concept CryptoBackend = requires {
    /// Four opaque native-handle types
    typename B::NativeKeyHandle;
    typename B::NativeCertHandle;
    typename B::NativeCtxHandle;
    typename B::NativeSslCtxHandle;
} &&
    requires {
        /// One-time (idempotent) initialisation, noexcept
        { B::Init() } noexcept;
        /// Release global backend resources, noexcept
        { B::Cleanup() } noexcept;
    } &&
    requires(
        typename B::NativeKeyHandle* privkey,
        typename B::NativeKeyHandle* pubkey,
        std::initializer_list<std::string_view> data,
        std::string_view sv,
        std::string_view hmac_key,
        hash::OutputEncoding enc
    ) {
        /// DSA signing of raw message
        { B::template DoSign<DsaType::kRsa, DigestSize::k256>(privkey, data) } -> std::same_as<std::string>;

        /// DSA verification of raw message (throws on failure)
        { B::template DoVerify<DsaType::kRsa, DigestSize::k256>(pubkey, data, sv) } -> std::same_as<void>;

        /// DSA signing of a pre-hashed digest
        { B::template DoSignDigest<DsaType::kRsa, DigestSize::k256>(privkey, sv) } -> std::same_as<std::string>;

        /// DSA verification of a pre-hashed digest (throws on failure)
        {
            B::template DoVerifyDigest<DsaType::kRsa, DigestSize::k256>(pubkey, sv, sv)
        } -> std::same_as<void>;

        /// Generic hash computation
        {
            B::template ComputeHash<hash_algo::Sha256>(data, enc)
        } -> std::same_as<std::string>;

        /// Generic HMAC computation
        {
            B::template ComputeHmac<hash_algo::Sha256>(hmac_key, data, enc)
        } -> std::same_as<std::string>;
    };

}  // namespace crypto

USERVER_NAMESPACE_END
