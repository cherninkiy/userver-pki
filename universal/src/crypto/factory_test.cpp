#include <gtest/gtest.h>

#include <userver/crypto/crypto_factory.hpp>
#include <userver/crypto/null_backend.hpp>
#include <userver/crypto/openssl_backend.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {
namespace {

// ---------------------------------------------------------- NullCryptoBackend

TEST(NullCryptoBackend, ConceptSatisfied) {
    // Verified at compile time by the static_assert in null_backend.hpp.
    // This test just ensures the header compiles and the assertion holds at rt.
    SUCCEED();
}

TEST(NullCryptoBackend, InitIsNoOp) {
    // Should not throw
    EXPECT_NO_THROW(NullCryptoBackend::Init());
}

TEST(NullCryptoBackend, DoSignReturnsEmpty) {
    NullKeyHandle key;
    const std::string sig =
        NullCryptoBackend::DoSign<DsaType::kRsa, DigestSize::k256>(&key, {"hello"});
    EXPECT_TRUE(sig.empty());
}

TEST(NullCryptoBackend, DoVerifyIsNoOp) {
    NullKeyHandle key;
    EXPECT_NO_THROW(
        NullCryptoBackend::DoVerify<DsaType::kRsa, DigestSize::k256>(&key, {"hello"}, "sig")
    );
}

TEST(NullCryptoBackend, DoSignDigestReturnsEmpty) {
    NullKeyHandle key;
    const std::string sig =
        NullCryptoBackend::DoSignDigest<DsaType::kRsa, DigestSize::k256>(&key, "digest");
    EXPECT_TRUE(sig.empty());
}

TEST(NullCryptoBackend, ComputeHashReturnsEmpty) {
    const std::string h =
        NullCryptoBackend::ComputeHash<hash_algo::Sha256>({"data"}, hash::OutputEncoding::kBinary);
    EXPECT_TRUE(h.empty());
}

TEST(NullCryptoBackend, ComputeHmacReturnsEmpty) {
    const std::string h = NullCryptoBackend::ComputeHmac<hash_algo::Sha256>(
        "key", {"data"}, hash::OutputEncoding::kBinary
    );
    EXPECT_TRUE(h.empty());
}

// ---------------------------------------------------------- CryptoFactory<Null>

TEST(CryptoFactoryNull, LoadPrivateKeyReturnsStub) {
    // NullCryptoBackend::LoadNativePrivateKey returns a non-null shared_ptr
    auto key = CryptoFactory<NullCryptoBackend>::LoadPrivateKey("fake-pem", "fake-pwd");
    // operator bool is true because the shared_ptr inside is non-null
    EXPECT_TRUE(static_cast<bool>(key));
}

TEST(CryptoFactoryNull, LoadPublicKeyReturnsStub) {
    auto key = CryptoFactory<NullCryptoBackend>::LoadPublicKey("fake-pem");
    EXPECT_TRUE(static_cast<bool>(key));
}

TEST(CryptoFactoryNull, LoadCertificateReturnsStub) {
    auto cert = CryptoFactory<NullCryptoBackend>::LoadCertificate("fake-pem");
    EXPECT_TRUE(static_cast<bool>(cert));
}

TEST(CryptoFactoryNull, ComputeHashReturnsEmpty) {
    const auto h = CryptoFactory<NullCryptoBackend>::ComputeHash<hash_algo::Sha256>(
        {"data"}, hash::OutputEncoding::kBinary
    );
    EXPECT_TRUE(h.empty());
}

TEST(CryptoFactoryNull, MakeSignerSignsEmpty) {
    auto signer =
        CryptoFactory<NullCryptoBackend>::MakeSigner<DsaType::kRsa, DigestSize::k256>("fake-pem");
    const auto sig = signer.Sign({"hello"});
    EXPECT_TRUE(sig.empty());
}

TEST(CryptoFactoryNull, MakeVerifierVerifiesNoOp) {
    auto verifier =
        CryptoFactory<NullCryptoBackend>::MakeVerifier<DsaType::kRsa, DigestSize::k256>("fake-pem");
    EXPECT_NO_THROW(verifier.Verify({"hello"}, "any-signature"));
}

}  // namespace
}  // namespace crypto

USERVER_NAMESPACE_END
