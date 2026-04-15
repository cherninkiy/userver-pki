#include <userver/crypto/openssl_backend.hpp>

#include <cstring>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <fmt/compile.h>
#include <fmt/format.h>

#include <cryptopp/dsa.h>

#include <userver/crypto/exception.hpp>
#include <userver/crypto/hash.hpp>
#include <userver/crypto/openssl.hpp>
#include <userver/utils/assert.hpp>
#include <userver/utils/numeric_cast.hpp>
#include <userver/utils/str_icase.hpp>
#include <userver/utils/text_light.hpp>
#include <userver/utils/trivial_map.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {
namespace {

// ============================================================ helpers

// undefined in openssl 1.0.x
#ifndef RSA_PSS_SALTLEN_DIGEST
constexpr int RSA_PSS_SALTLEN_DIGEST = -1;
#endif

std::string FormatSslError(std::string message) {
    bool first = true;
    unsigned long ssl_error = 0;

    while ((ssl_error = ERR_get_error()) != 0) {
        if (first) {
            message += ": ";
            first = false;
        } else {
            message += "; ";
        }

        const char* reason = ERR_reason_error_string(ssl_error);
        if (reason) {
            message += reason;
        } else {
            message += fmt::format(FMT_COMPILE("code {:X}"), ssl_error);
        }
    }
    return message;
}

class EvpMdCtx {
public:
    EvpMdCtx()
        : ctx_(
#if OPENSSL_VERSION_NUMBER >= 0x010100000L
              EVP_MD_CTX_new()
#else
              EVP_MD_CTX_create()
#endif
          )
    {
        if (!ctx_) {
            throw CryptoException(FormatSslError("Failed to create EVP_MD_CTX"));
        }
    }

    ~EvpMdCtx() {
        if (ctx_) {
#if OPENSSL_VERSION_NUMBER >= 0x010100000L
            EVP_MD_CTX_free(ctx_);
#else
            EVP_MD_CTX_destroy(ctx_);
#endif
        }
    }

    EvpMdCtx(const EvpMdCtx&) = delete;
    EvpMdCtx(EvpMdCtx&& other) noexcept : ctx_(std::exchange(other.ctx_, nullptr)) {}

    EVP_MD_CTX* Get() { return ctx_; }

private:
    EVP_MD_CTX* ctx_;
};

const EVP_MD* GetShaMdByEnum(DigestSize bits) {
    switch (bits) {
        case DigestSize::k160:
            return EVP_sha1();
        case DigestSize::k256:
            return EVP_sha256();
        case DigestSize::k384:
            return EVP_sha384();
        case DigestSize::k512:
            return EVP_sha512();
    }
    UINVARIANT(false, "Unexpected DigestSize");
}

constexpr size_t GetDigestLength(DigestSize digest_size) {
    size_t bits = 0;
    switch (digest_size) {
        case DigestSize::k160:
            bits = 160;
            break;
        case DigestSize::k256:
            bits = 256;
            break;
        case DigestSize::k384:
            bits = 384;
            break;
        case DigestSize::k512:
            bits = 512;
            break;
    }
    return (bits + CHAR_BIT - 1) / CHAR_BIT;
}

std::unique_ptr<::BIO, decltype(&::BIO_free_all)> MakeBioString(std::string_view str) {
    return {::BIO_new_mem_buf(str.data(), str.size()), &::BIO_free_all};
}

std::unique_ptr<::BIO, decltype(&::BIO_free_all)> MakeBioMemoryBuffer() {
    return {::BIO_new(BIO_s_mem()), &::BIO_free_all};
}

std::unique_ptr<::BIO, decltype(&::BIO_free_all)> MakeBioSecureMemoryBuffer() {
    return {::BIO_new(BIO_s_secmem()), &::BIO_free_all};
}

void SetupJwaRsaPssPadding(EVP_PKEY_CTX* pkey_ctx, DigestSize bits) {
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        throw CryptoException(FormatSslError("Failed to setup PSS padding: EVP_PKEY_CTX_set_rsa_padding"));
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        throw CryptoException(FormatSslError("Failed to setup PSS padding: EVP_PKEY_CTX_set_rsa_pss_saltlen"));
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, GetShaMdByEnum(bits)) <= 0) {
        throw CryptoException(FormatSslError("Failed to setup PSS padding: EVP_PKEY_CTX_set_rsa_mgf1_md"));
    }
}

int CurveNidByDigestSize(DigestSize bits) {
    switch (bits) {
        case DigestSize::k256:
            return NID_X9_62_prime256v1;
        case DigestSize::k384:
            return NID_secp384r1;
        case DigestSize::k512:
            return NID_secp521r1;
        case DigestSize::k160:
            break;
    }
    UINVARIANT(false, "Unexpected DigestSize");
}

bool IsMatchingKeyCurve(EVP_PKEY* pkey, DigestSize bits) {
    const std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(EVP_PKEY_get1_EC_KEY(pkey), EC_KEY_free);
    return ec_key && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key.get())) == CurveNidByDigestSize(bits);
}

// EC signature conversion helpers
// OpenSSL generates ECDSA signatures in ASN.1/DER format, but RFC7518
// specifies signature as a concatenation of zero-padded big-endian (R, S).
std::string ConvertEcSignatureToP1363(const std::string& der_signature, DigestSize digest_size) {
    size_t siglen = 0;
    switch (digest_size) {
        case DigestSize::k256:
            siglen = 256;
            break;
        case DigestSize::k384:
            siglen = 384;
            break;
        case DigestSize::k512:
            siglen = 521;  // not a typo
            break;
        case DigestSize::k160:
            UINVARIANT(false, "Unexpected DigestSize");
    }
    siglen = ((siglen + CHAR_BIT - 1) / CHAR_BIT) * 2;

    std::string converted(siglen, '\0');
    if (siglen !=
        CryptoPP::DSAConvertSignatureFormat(
            reinterpret_cast<unsigned char*>(converted.data()),
            converted.size(),
            CryptoPP::DSASignatureFormat::DSA_P1363,
            reinterpret_cast<const unsigned char*>(der_signature.data()),
            der_signature.size(),
            CryptoPP::DSASignatureFormat::DSA_DER
        ))
    {
        throw SignError("Failed to sign: signature format conversion failed");
    }
    return converted;
}

std::vector<unsigned char> ConvertEcSignatureToDer(std::string_view raw_signature) {
    constexpr size_t kDerEcdsaSignatureBufferSize = 256;

    std::vector<unsigned char> der(kDerEcdsaSignatureBufferSize, '\0');
    const size_t siglen = CryptoPP::DSAConvertSignatureFormat(
        der.data(),
        der.size(),
        CryptoPP::DSASignatureFormat::DSA_DER,
        reinterpret_cast<const unsigned char*>(raw_signature.data()),
        raw_signature.size(),
        CryptoPP::DSASignatureFormat::DSA_P1363
    );
    if (siglen < 6 || siglen >= der.size()) {
        throw VerificationError("Failed to verify: signature format conversion failed");
    }
    der.resize(siglen);
    return der;
}

// ============================================================ key / cert load helpers

int StringViewPasswordCb(char* buf, int size, int /*rwflag*/, void* str_vptr) {
    if (!str_vptr || !buf || size < 0) {
        return -1;
    }
    const auto* password = static_cast<const std::string_view*>(str_vptr);
    if (password->size() > static_cast<size_t>(size)) {
        return -1;
    }
    std::memcpy(buf, password->data(), password->size());
    return static_cast<int>(password->size());
}

int NoPasswordCb(char* /*buf*/, int /*size*/, int /*rwflag*/, void*) { return 0; }

std::optional<std::string> GetPemStringImpl(EVP_PKEY* key, const EVP_CIPHER* enc, std::string_view password) {
    if (enc && password.empty()) {
        throw SerializationError("Attempt to export private key with an empty password");
    }
    if (!key) {
        return {};
    }
    auto membio = MakeBioSecureMemoryBuffer();
    if (1 !=
        PEM_write_bio_PrivateKey(
            membio.get(),
            key,
            enc,
            nullptr,
            0,
            &StringViewPasswordCb,
            reinterpret_cast<void*>(&password)
        ))
    {
        throw SerializationError(FormatSslError("Error serializing key to PEM"));
    }
    std::string result;
    result.resize(BIO_pending(membio.get()));
    size_t readbytes = 0;
    if (1 != BIO_read_ex(membio.get(), result.data(), result.size(), &readbytes)) {
        throw SerializationError(FormatSslError("Error transferring PEM to string"));
    }
    if (readbytes != result.size()) {
        throw SerializationError("Error transferring PEM to string");
    }
    return result;
}

using Bignum = std::unique_ptr<BIGNUM, decltype(&::BN_clear_free)>;

Bignum LoadBignumFromBigEnd(std::string_view raw) {
    int size = 0;
    try {
        size = utils::numeric_cast<int>(raw.size());
    } catch (const std::runtime_error& ex) {
        throw KeyParseError{ex.what()};
    }
    auto* num = ::BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), size, nullptr);
    if (num == nullptr) {
        throw KeyParseError{FormatSslError("Cannot parse BIGNUM: BN_bin2bn")};
    }
    return {num, &BN_clear_free};
}

std::unique_ptr<RSA, decltype(&::RSA_free)> LoadRsaFromComponents([[maybe_unused]] Bignum n, [[maybe_unused]] Bignum e) {
    std::unique_ptr<RSA, decltype(&::RSA_free)> rsa{::RSA_new(), ::RSA_free};
    if (!rsa) {
        throw KeyParseError{FormatSslError("Cannot create RSA")};
    }
#if OPENSSL_VERSION_NUMBER >= 0x010100000L
    if (::RSA_set0_key(rsa.get(), n.get(), e.get(), nullptr) != 1) {
        throw KeyParseError{FormatSslError("Cannot set RSA public key")};
    }
    [[maybe_unused]] auto* n_unused = n.release();
    [[maybe_unused]] auto* e_unused = e.release();
#else
    rsa->n = n.release();
    rsa->e = e.release();
#endif
    return rsa;
}

constexpr utils::TrivialBiMap kCurveToNid = [](auto selector) {
    return selector().Case("p-256", NID_X9_62_prime256v1).Case("p-384", NID_secp384r1).Case("p-521", NID_secp521r1);
};

int CurveStringToNid(std::string_view curve_str) {
    auto opt_value = kCurveToNid.TryFindICaseByFirst(curve_str);
    if (!opt_value) {
        throw KeyParseError{FormatSslError(fmt::format("Unsupported curve type {}", curve_str))};
    }
    return *opt_value;
}

std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)> LoadEcFromComponents(int curve_type, Bignum x, Bignum y) {
    std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)> ec{EC_KEY_new_by_curve_name(curve_type), EC_KEY_free};
    if (!ec) {
        throw KeyParseError{FormatSslError("Cannot create EC")};
    }
    if (EC_KEY_set_public_key_affine_coordinates(ec.get(), x.get(), y.get()) != 1) {
        throw KeyParseError{FormatSslError("Cannot set EC_KEY public key")};
    }
    return ec;
}

constexpr std::string_view kBeginCertMarker = "-----BEGIN CERTIFICATE-----";

}  // anonymous namespace

// ============================================================ OpenSslBackend

void OpenSslBackend::Init() noexcept {
    Openssl::Init();
}

void OpenSslBackend::SecureClear(std::string& s) noexcept {
    OPENSSL_cleanse(s.data(), s.size());
}

// ------------------------------------------------------------ private key

std::shared_ptr<OpenSslBackend::NativeKeyHandle>
OpenSslBackend::LoadNativePrivateKey(std::string_view pem, std::string_view password) {
    auto bio = MakeBioString(pem);
    std::shared_ptr<EVP_PKEY> key(
        ::PEM_read_bio_PrivateKey(
            bio.get(), nullptr, &StringViewPasswordCb, reinterpret_cast<void*>(&password)
        ),
        ::EVP_PKEY_free
    );
    if (!key) {
        throw KeyParseError(FormatSslError("Failed to load private key"));
    }
    return key;
}

std::optional<std::string> OpenSslBackend::GetPrivateKeyPem(NativeKeyHandle* key, std::string_view password) {
    return GetPemStringImpl(key, EVP_aes_128_cbc(), password);
}

std::optional<std::string> OpenSslBackend::GetPrivateKeyPemUnencrypted(NativeKeyHandle* key) {
    return GetPemStringImpl(key, nullptr, {});
}

// ------------------------------------------------------------ public key

std::shared_ptr<OpenSslBackend::NativeKeyHandle> OpenSslBackend::LoadNativePublicKey(std::string_view pem) {
    if (utils::text::StartsWith(pem, kBeginCertMarker)) {
        auto cert = LoadNativeCertificate(pem);
        return LoadNativePublicKeyFromCertificate(cert.get());
    }
    auto bio = MakeBioString(pem);
    std::shared_ptr<EVP_PKEY> key(::PEM_read_bio_PUBKEY(bio.get(), nullptr, &NoPasswordCb, nullptr), ::EVP_PKEY_free);
    if (!key) {
        throw KeyParseError(FormatSslError("Failed to load public key"));
    }
    return key;
}

std::shared_ptr<OpenSslBackend::NativeKeyHandle>
OpenSslBackend::LoadNativePublicKeyFromCertificate(const NativeCertHandle* cert) {
    std::shared_ptr<EVP_PKEY> key(::X509_get_pubkey(const_cast<X509*>(cert)), ::EVP_PKEY_free);
    if (!key) {
        throw KeyParseError(FormatSslError("Error getting public key from certificate"));
    }
    return key;
}

std::shared_ptr<OpenSslBackend::NativeKeyHandle>
OpenSslBackend::LoadNativeRSAPublicKeyFromComponents(std::string_view modulus, std::string_view exponent) {
    auto n = LoadBignumFromBigEnd(modulus);
    auto e = LoadBignumFromBigEnd(exponent);
    auto rsa = LoadRsaFromComponents(std::move(n), std::move(e));

    std::shared_ptr<EVP_PKEY> pubkey{EVP_PKEY_new(), ::EVP_PKEY_free};
    if (!pubkey) {
        throw KeyParseError{FormatSslError("Cannot create EVP_PKEY")};
    }
    if (!EVP_PKEY_set1_RSA(pubkey.get(), rsa.get())) {
        throw KeyParseError{FormatSslError("Cannot set RSA key to EVP_PKEY")};
    }
    return pubkey;
}

std::shared_ptr<OpenSslBackend::NativeKeyHandle>
OpenSslBackend::LoadNativeECPublicKeyFromComponents(std::string_view curve, std::string_view x, std::string_view y) {
    const int curve_nid = CurveStringToNid(curve);
    auto bx = LoadBignumFromBigEnd(x);
    auto by = LoadBignumFromBigEnd(y);
    auto ec = LoadEcFromComponents(curve_nid, std::move(bx), std::move(by));

    std::shared_ptr<EVP_PKEY> pubkey{EVP_PKEY_new(), ::EVP_PKEY_free};
    if (!pubkey) {
        throw KeyParseError{FormatSslError("Cannot create EVP_PKEY")};
    }
    if (!EVP_PKEY_set1_EC_KEY(pubkey.get(), ec.get())) {
        throw KeyParseError{FormatSslError("Cannot set EC key to EVP_PKEY")};
    }
    return pubkey;
}

// ------------------------------------------------------------ certificate

std::shared_ptr<OpenSslBackend::NativeCertHandle> OpenSslBackend::LoadNativeCertificate(std::string_view pem) {
    if (!utils::text::StartsWith(pem, kBeginCertMarker)) {
        throw KeyParseError(FormatSslError("Not a certificate"));
    }
    auto bio = MakeBioString(pem);
    std::shared_ptr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, &NoPasswordCb, nullptr), X509_free);
    if (!cert) {
        throw KeyParseError(FormatSslError("Error loading cert into memory"));
    }
    return cert;
}

std::shared_ptr<OpenSslBackend::NativeCertHandle>
OpenSslBackend::LoadNativeCertificateSkippingAttributes(std::string_view pem) {
    const auto start = pem.find(kBeginCertMarker);
    if (start == std::string_view::npos) {
        throw KeyParseError(FormatSslError("Not a certificate"));
    }
    return LoadNativeCertificate(pem.substr(start));
}

std::optional<std::string> OpenSslBackend::GetCertificatePem(NativeCertHandle* cert) {
    if (!cert) {
        return {};
    }
    auto membio = MakeBioMemoryBuffer();
    if (1 != PEM_write_bio_X509(membio.get(), cert)) {
        throw SerializationError(FormatSslError("Error serializing cert to PEM"));
    }
    std::string result;
    result.resize(BIO_pending(membio.get()));
    size_t readbytes = 0;
    if (1 != BIO_read_ex(membio.get(), result.data(), result.size(), &readbytes)) {
        throw SerializationError(FormatSslError("Error transferring PEM to string"));
    }
    if (readbytes != result.size()) {
        throw SerializationError("Error transferring PEM to string");
    }
    return result;
}

std::string OpenSslBackend::GetCertificateSubject(NativeCertHandle* cert) {
    if (!cert) {
        throw KeyParseError(FormatSslError("Invalid certificate"));
    }
    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        throw KeyParseError(FormatSslError("Failed to get subject name from certificate"));
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw KeyParseError(FormatSslError("Failed to create BIO"));
    }
    if (X509_NAME_print_ex(bio, subject_name, 0, XN_FLAG_RFC2253) < 0) {
        BIO_free(bio);
        throw KeyParseError(FormatSslError("Failed to print subject name"));
    }
    char* data = nullptr;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// ------------------------------------------------------------ DSA sign

template <DsaType Type, DigestSize Bits>
std::string OpenSslBackend::DoSign(NativeKeyHandle* key, std::initializer_list<std::string_view> data) {
    EvpMdCtx ctx;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    if (1 != EVP_DigestSignInit(ctx.Get(), &pkey_ctx, GetShaMdByEnum(Bits), nullptr, key)) {
        throw SignError(FormatSslError("Failed to sign: EVP_DigestSignInit"));
    }
    if constexpr (Type == DsaType::kRsaPss) {
        SetupJwaRsaPssPadding(pkey_ctx, Bits);
    }
    for (const auto& part : data) {
        if (1 != EVP_DigestSignUpdate(ctx.Get(), part.data(), part.size())) {
            throw SignError(FormatSslError("Failed to sign: EVP_DigestSignUpdate"));
        }
    }
    size_t siglen = 0;
    if (1 != EVP_DigestSignFinal(ctx.Get(), nullptr, &siglen)) {
        throw SignError(FormatSslError("Failed to sign: EVP_DigestSignFinal (size check)"));
    }
    std::string signature(siglen, '\0');
    if (1 != EVP_DigestSignFinal(ctx.Get(), reinterpret_cast<unsigned char*>(signature.data()), &siglen)) {
        throw SignError(FormatSslError("Failed to sign: EVP_DigestSignFinal"));
    }
    signature.resize(siglen);
    if constexpr (Type == DsaType::kEc) {
        return ConvertEcSignatureToP1363(signature, Bits);
    }
    return signature;
}

template <DsaType Type, DigestSize Bits>
std::string OpenSslBackend::DoSignDigest(NativeKeyHandle* key, std::string_view digest) {
    if constexpr (Type == DsaType::kRsaPss) {
        UASSERT_MSG(false, "SignDigest is not available with PSS padding");
        throw CryptoException("SignDigest is not available with PSS padding");
    }
    if (digest.size() != GetDigestLength(Bits)) {
        throw SignError("Invalid digest size");
    }
    const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
        pkey_ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) {
        throw SignError(FormatSslError("Failed to sign digest: EVP_PKEY_CTX_new"));
    }
    if (1 != EVP_PKEY_sign_init(pkey_ctx.get())) {
        throw SignError(FormatSslError("Failed to sign digest: EVP_PKEY_sign_init"));
    }
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), GetShaMdByEnum(Bits)) <= 0) {
        throw SignError(FormatSslError("Failed to sign digest: EVP_PKEY_CTX_set_signature_md"));
    }
    size_t siglen = 0;
    if (1 !=
        EVP_PKEY_sign(
            pkey_ctx.get(),
            nullptr,
            &siglen,
            reinterpret_cast<const unsigned char*>(digest.data()),
            digest.size()
        ))
    {
        throw SignError(FormatSslError("Failed to sign digest: EVP_PKEY_sign (size check)"));
    }
    std::string signature(siglen, '\0');
    if (1 !=
        EVP_PKEY_sign(
            pkey_ctx.get(),
            reinterpret_cast<unsigned char*>(signature.data()),
            &siglen,
            reinterpret_cast<const unsigned char*>(digest.data()),
            digest.size()
        ))
    {
        throw SignError(FormatSslError("Failed to sign digest: EVP_PKEY_sign"));
    }
    signature.resize(siglen);
    if constexpr (Type == DsaType::kEc) {
        return ConvertEcSignatureToP1363(signature, Bits);
    }
    return signature;
}

// ------------------------------------------------------------ DSA verify

template <DsaType Type, DigestSize Bits>
void OpenSslBackend::DoVerify(
    NativeKeyHandle* key,
    std::initializer_list<std::string_view> data,
    std::string_view raw_signature
) {
    EvpMdCtx ctx;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    if (1 != EVP_DigestVerifyInit(ctx.Get(), &pkey_ctx, GetShaMdByEnum(Bits), nullptr, key)) {
        throw VerificationError(FormatSslError("Failed to verify: EVP_DigestVerifyInit"));
    }
    if constexpr (Type == DsaType::kRsaPss) {
        SetupJwaRsaPssPadding(pkey_ctx, Bits);
    }
    for (const auto& part : data) {
        if (1 != EVP_DigestVerifyUpdate(ctx.Get(), part.data(), part.size())) {
            throw VerificationError(FormatSslError("Failed to verify: EVP_DigestVerifyUpdate"));
        }
    }
    int result = -1;
    if constexpr (Type == DsaType::kEc) {
        auto der = ConvertEcSignatureToDer(raw_signature);
        result = EVP_DigestVerifyFinal(ctx.Get(), der.data(), der.size());
    } else {
        result = EVP_DigestVerifyFinal(
            ctx.Get(),
            reinterpret_cast<const unsigned char*>(raw_signature.data()),
            raw_signature.size()
        );
    }
    if (1 != result) {
        throw VerificationError(FormatSslError("Failed to verify: EVP_DigestVerifyFinal"));
    }
}

template <DsaType Type, DigestSize Bits>
void OpenSslBackend::DoVerifyDigest(NativeKeyHandle* key, std::string_view digest, std::string_view raw_signature) {
    if constexpr (Type == DsaType::kRsaPss) {
        UASSERT_MSG(false, "VerifyDigest is not available with PSS padding");
        throw CryptoException("VerifyDigest is not available with PSS padding");
    }
    if (digest.size() != GetDigestLength(Bits)) {
        throw VerificationError("Invalid digest size");
    }
    const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
        pkey_ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) {
        throw VerificationError(FormatSslError("Failed to verify digest: EVP_PKEY_CTX_new"));
    }
    if (1 != EVP_PKEY_verify_init(pkey_ctx.get())) {
        throw VerificationError(FormatSslError("Failed to verify digest: EVP_PKEY_verify_init"));
    }
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), GetShaMdByEnum(Bits)) <= 0) {
        throw VerificationError(FormatSslError("Failed to verify digest: EVP_PKEY_CTX_set_signature_md"));
    }
    int result = -1;
    if constexpr (Type == DsaType::kEc) {
        auto der = ConvertEcSignatureToDer(raw_signature);
        result = EVP_PKEY_verify(
            pkey_ctx.get(),
            der.data(),
            der.size(),
            reinterpret_cast<const unsigned char*>(digest.data()),
            digest.size()
        );
    } else {
        result = EVP_PKEY_verify(
            pkey_ctx.get(),
            reinterpret_cast<const unsigned char*>(raw_signature.data()),
            raw_signature.size(),
            reinterpret_cast<const unsigned char*>(digest.data()),
            digest.size()
        );
    }
    if (1 != result) {
        throw VerificationError(FormatSslError("Failed to verify digest: EVP_PKEY_verify"));
    }
}

// ------------------------------------------------------------ hash / HMAC

template <>
std::string OpenSslBackend::ComputeHash<hash_algo::Sha1>(
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::Sha1(data, enc);
}

template <>
std::string OpenSslBackend::ComputeHash<hash_algo::Sha256>(
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::Sha256(data, enc);
}

template <>
std::string OpenSslBackend::ComputeHash<hash_algo::Sha384>(
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::Sha384(data, enc);
}

template <>
std::string OpenSslBackend::ComputeHash<hash_algo::Sha512>(
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::Sha512(data, enc);
}

template <>
std::string OpenSslBackend::ComputeHmac<hash_algo::Sha1>(
    std::string_view key,
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::HmacSha1(key, data, enc);
}

template <>
std::string OpenSslBackend::ComputeHmac<hash_algo::Sha256>(
    std::string_view key,
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::HmacSha256(key, data, enc);
}

template <>
std::string OpenSslBackend::ComputeHmac<hash_algo::Sha384>(
    std::string_view key,
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::HmacSha384(key, data, enc);
}

template <>
std::string OpenSslBackend::ComputeHmac<hash_algo::Sha512>(
    std::string_view key,
    std::initializer_list<std::string_view> data,
    hash::OutputEncoding enc
) {
    return crypto::hash::HmacSha512(key, data, enc);
}

// ------------------------------------------------------------ key validation

template <DsaType Type, DigestSize Bits>
void OpenSslBackend::ValidateForSigning(NativeKeyHandle* key, const std::string& algo_name) {
    if constexpr (Type == DsaType::kEc) {
        if (EVP_PKEY_base_id(key) != EVP_PKEY_EC) {
            throw SignError("Non-EC key supplied for " + algo_name + " signer");
        }
        if (!IsMatchingKeyCurve(key, Bits)) {
            throw SignError("Key curve mismatch for " + algo_name + " signer");
        }
    } else {
        if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
            throw SignError("Non-RSA key supplied for " + algo_name + " signer");
        }
    }
}

template <DsaType Type, DigestSize Bits>
void OpenSslBackend::ValidateForVerification(NativeKeyHandle* key, const std::string& algo_name) {
    if constexpr (Type == DsaType::kEc) {
        if (EVP_PKEY_base_id(key) != EVP_PKEY_EC) {
            throw VerificationError("Non-EC key supplied for " + algo_name + " verifier");
        }
        if (!IsMatchingKeyCurve(key, Bits)) {
            throw VerificationError("Key curve mismatch for " + algo_name + " verifier");
        }
    } else {
        if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
            throw VerificationError("Non-RSA key supplied for " + algo_name + " verifier");
        }
    }
}

// ============================================================ explicit instantiations

// DoSign
template std::string OpenSslBackend::DoSign<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>);
template std::string OpenSslBackend::DoSign<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>);

// DoSignDigest
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, std::string_view);
template std::string OpenSslBackend::DoSignDigest<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, std::string_view);

// DoVerify
template void OpenSslBackend::DoVerify<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);
template void OpenSslBackend::DoVerify<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, std::initializer_list<std::string_view>, std::string_view);

// DoVerifyDigest
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, std::string_view, std::string_view);
template void OpenSslBackend::DoVerifyDigest<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, std::string_view, std::string_view);

// ValidateForSigning
template void OpenSslBackend::ValidateForSigning<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForSigning<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, const std::string&);

// ValidateForVerification
template void OpenSslBackend::ValidateForVerification<DsaType::kRsa, DigestSize::k160>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsa, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsa, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsa, DigestSize::k512>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kEc, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kEc, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kEc, DigestSize::k512>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsaPss, DigestSize::k160>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsaPss, DigestSize::k256>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsaPss, DigestSize::k384>(NativeKeyHandle*, const std::string&);
template void OpenSslBackend::ValidateForVerification<DsaType::kRsaPss, DigestSize::k512>(NativeKeyHandle*, const std::string&);

}  // namespace crypto

USERVER_NAMESPACE_END
