#include <userver/crypto/verifiers.hpp>

// keep these two headers in this order
#include <openssl/cms.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <userver/crypto/algorithm.hpp>
#include <userver/crypto/openssl.hpp>
#include <userver/utils/assert.hpp>

#include <crypto/helpers.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

Verifier::Verifier(const std::string& name)
    : NamedAlgo(name)
{}
Verifier::~Verifier() = default;

///
/// None
///

VerifierNone::VerifierNone()
    : Verifier("none")
{}
void VerifierNone::Verify(std::initializer_list<std::string_view> /*data*/, std::string_view raw_signature) const {
    if (!raw_signature.empty()) {
        throw VerificationError("Signature is not empty");
    }
}

///
/// HMAC-SHA
///

template <DigestSize Bits, typename Backend>
HmacShaVerifier<Bits, Backend>::HmacShaVerifier(std::string secret)
    : Verifier("HS" + EnumValueToString(Bits)),
      secret_(std::move(secret))
{}

template <DigestSize Bits, typename Backend>
HmacShaVerifier<Bits, Backend>::~HmacShaVerifier() {
    Backend::SecureClear(secret_);
}

template <DigestSize Bits, typename Backend>
void HmacShaVerifier<Bits, Backend>::Verify(
    std::initializer_list<std::string_view> data,
    std::string_view raw_signature
) const {
    const std::string signature = Backend::template ComputeHmac<typename HmacAlgoTag<Bits>::type>(
        secret_, data, hash::OutputEncoding::kBinary
    );
    if (!algorithm::AreStringsEqualConstTime(raw_signature, signature)) {
        throw VerificationError("Invalid signature");
    }
}

template class HmacShaVerifier<DigestSize::k160>;
template class HmacShaVerifier<DigestSize::k256>;
template class HmacShaVerifier<DigestSize::k384>;
template class HmacShaVerifier<DigestSize::k512>;

///
/// *SA
///

template <DsaType Type, DigestSize Bits, typename Backend>
DsaVerifier<Type, Bits, Backend>::DsaVerifier(BasicPublicKey<Backend> pubkey)
    : Verifier(EnumValueToString(Type) + EnumValueToString(Bits)),
      pkey_(std::move(pubkey))
{
    Backend::template ValidateForVerification<Type, Bits>(pkey_.GetNative(), Name());
}

template <DsaType Type, DigestSize Bits, typename Backend>
DsaVerifier<Type, Bits, Backend>::DsaVerifier(std::string_view key)
    : DsaVerifier{BasicPublicKey<Backend>::LoadFromString(key)}
{}

template <DsaType Type, DigestSize Bits, typename Backend>
void DsaVerifier<Type, Bits, Backend>::Verify(
    std::initializer_list<std::string_view> data,
    std::string_view raw_signature
) const {
    Backend::template DoVerify<Type, Bits>(pkey_.GetNative(), data, raw_signature);
}

template <DsaType Type, DigestSize Bits, typename Backend>
void DsaVerifier<Type, Bits, Backend>::VerifyDigest(std::string_view digest, std::string_view raw_signature) const {
    Backend::template DoVerifyDigest<Type, Bits>(pkey_.GetNative(), digest, raw_signature);
}

template class DsaVerifier<DsaType::kRsa, DigestSize::k160>;
template class DsaVerifier<DsaType::kRsa, DigestSize::k256>;
template class DsaVerifier<DsaType::kRsa, DigestSize::k384>;
template class DsaVerifier<DsaType::kRsa, DigestSize::k512>;

template class DsaVerifier<DsaType::kEc, DigestSize::k256>;
template class DsaVerifier<DsaType::kEc, DigestSize::k384>;
template class DsaVerifier<DsaType::kEc, DigestSize::k512>;

template class DsaVerifier<DsaType::kRsaPss, DigestSize::k160>;
template class DsaVerifier<DsaType::kRsaPss, DigestSize::k256>;
template class DsaVerifier<DsaType::kRsaPss, DigestSize::k384>;
template class DsaVerifier<DsaType::kRsaPss, DigestSize::k512>;

///
/// CMS
///

namespace {

int ToNativeCmsFlags(utils::Flags<CmsVerifier::Flags> flags) {
    int native = 0;

    using VerifyFlags = CmsVerifier::Flags;
    if (flags & VerifyFlags::kNoSignerCertVerify) {
        native |= CMS_NO_SIGNER_CERT_VERIFY;
    }

    return native;
}

std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> ReadCmsContent(
    BIO& from,
    CmsVerifier::InForm in_form
) {
    using InForm = CmsVerifier::InForm;

    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms{nullptr, CMS_ContentInfo_free};
    switch (in_form) {
        case InForm::kDer: {
            cms.reset(d2i_CMS_bio(&from, nullptr));
            if (!cms) {
                throw VerificationError{FormatSslError("Failed to verify: d2i_CMS_bio")};
            }
            break;
        }
        case InForm::kPem: {
            cms.reset(PEM_read_bio_CMS(&from, nullptr, nullptr, nullptr));
            if (!cms) {
                throw VerificationError{FormatSslError("Failed to verify: PEM_read_bio_CMS")};
            }
            break;
        }
        case InForm::kSMime: {
            cms.reset(SMIME_read_CMS(&from, nullptr));
            if (!cms) {
                throw VerificationError{FormatSslError("Failed to verify: SMIME_read_CMS")};
            }
            break;
        }
    }

    UASSERT(cms);
    return cms;
}

}  // namespace

CmsVerifier::CmsVerifier(Certificate certificate)
    : NamedAlgo{"CMS"},
      cert_{std::move(certificate)}
{}

CmsVerifier::~CmsVerifier() = default;

void CmsVerifier::Verify(std::initializer_list<std::string_view> data, utils::Flags<Flags> flags, InForm in_form)
    const {
    const auto native_flags = ToNativeCmsFlags(flags);

    const auto data_string = InitListToString(data);
    const auto bio_data = MakeBioString(data_string);
    if (!bio_data) {
        throw VerificationError{FormatSslError("Failed to verify: MakeBioString")};
    }

    const auto cms_content = ReadCmsContent(*bio_data, in_form);

    using CertStack = STACK_OF(X509);
    const auto stack_deleter = [](STACK_OF(X509) * sk) { sk_X509_free(sk); };
    const std::unique_ptr<CertStack, decltype(stack_deleter)> certs{sk_X509_new_reserve(nullptr, 1), stack_deleter};
    if (!certs) {
        throw VerificationError{FormatSslError("Failed to verify: sk_X509_new_reserve")};
    }

    if (sk_X509_push(certs.get(), cert_.GetNative()) != 1) {
        throw VerificationError{FormatSslError("Failed to verify: sk_X509_push")};
    }

    if (1 !=
        CMS_verify(
            cms_content.get(),
            certs.get(),
            nullptr,
            nullptr,
            nullptr,
            native_flags
        ))
    {
        throw VerificationError{FormatSslError("Failed to verify: CMS_verify")};
    }
}

}  // namespace crypto

USERVER_NAMESPACE_END
