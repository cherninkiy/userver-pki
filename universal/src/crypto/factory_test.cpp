#include <gtest/gtest.h>

#include <userver/crypto/crypto_factory.hpp>
#include <userver/crypto/exception.hpp>
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
    EXPECT_NO_THROW(NullCryptoBackend::Init());
}

TEST(NullCryptoBackend, CleanupIsNoOp) {
    EXPECT_NO_THROW(NullCryptoBackend::Cleanup());
}

TEST(NullCryptoBackend, DoSignReturnsDummySignature) {
    NullKeyHandle key;
    const std::string sig =
        NullCryptoBackend::DoSign<DsaType::kRsa, DigestSize::k256>(&key, {"hello"});
    EXPECT_EQ(sig, "null_signature");
}

TEST(NullCryptoBackend, DoVerifyAcceptsCorrectSignature) {
    NullKeyHandle key;
    EXPECT_NO_THROW(
        NullCryptoBackend::DoVerify<DsaType::kRsa, DigestSize::k256>(&key, {"hello"}, "null_signature")
    );
}

TEST(NullCryptoBackend, DoVerifyRejectsWrongSignature) {
    NullKeyHandle key;
    EXPECT_THROW(
        NullCryptoBackend::DoVerify<DsaType::kRsa, DigestSize::k256>(&key, {"hello"}, "wrong_sig"),
        VerificationError
    );
}

TEST(NullCryptoBackend, DoSignDigestReturnsDummySignature) {
    NullKeyHandle key;
    const std::string sig =
        NullCryptoBackend::DoSignDigest<DsaType::kRsa, DigestSize::k256>(&key, "digest");
    EXPECT_EQ(sig, "null_signature");
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

TEST(NullCryptoBackend, LoadMethodsReturnSameStaticHandle) {
    // All calls with the same key type should return the same shared_ptr address
    auto k1 = NullCryptoBackend::LoadNativePrivateKey("pem", "");
    auto k2 = NullCryptoBackend::LoadNativePrivateKey("other-pem", "pwd");
    EXPECT_EQ(k1.get(), k2.get());
}

// ---------------------------------------------------------- CryptoFactory<Null>

TEST(CryptoFactoryNull, LoadPrivateKeyReturnsStub) {
    // NullCryptoBackend::LoadNativePrivateKey returns a non-null shared_ptr
    auto key = CryptoFactory<NullCryptoBackend>::LoadPrivateKey("fake-pem", "fake-pwd");
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

TEST(CryptoFactoryNull, MakeSignerSignsDummySignature) {
    auto signer =
        CryptoFactory<NullCryptoBackend>::MakeSigner<DsaType::kRsa, DigestSize::k256>("fake-pem");
    const auto sig = signer.Sign({"hello"});
    EXPECT_EQ(sig, "null_signature");
}

TEST(CryptoFactoryNull, MakeVerifierAcceptsNullSignature) {
    auto verifier =
        CryptoFactory<NullCryptoBackend>::MakeVerifier<DsaType::kRsa, DigestSize::k256>("fake-pem");
    EXPECT_NO_THROW(verifier.Verify({"hello"}, "null_signature"));
}

TEST(CryptoFactoryNull, MakeVerifierRejectsWrongSignature) {
    auto verifier =
        CryptoFactory<NullCryptoBackend>::MakeVerifier<DsaType::kRsa, DigestSize::k256>("fake-pem");
    EXPECT_THROW(verifier.Verify({"hello"}, "bad_signature"), VerificationError);
}

}  // namespace
}  // namespace crypto

USERVER_NAMESPACE_END
