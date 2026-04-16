#include <userver/crypto/signers.hpp>

#include <openssl/cms.h>
#include <openssl/evp.h>

#include <userver/crypto/openssl.hpp>
#include <userver/utils/assert.hpp>

#include <crypto/helpers.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

Signer::Signer(const std::string& name)
    : NamedAlgo(name)
{}
Signer::~Signer() = default;

///
/// None
///

SignerNone::SignerNone()
    : Signer("none")
{}
std::string SignerNone::Sign(std::initializer_list<std::string_view> /*data*/) const { return {}; }

///
/// HMAC-SHA
///

template <DigestSize Bits, typename Backend>
HmacShaSigner<Bits, Backend>::HmacShaSigner(std::string secret)
    : Signer("HS" + EnumValueToString(Bits)),
      secret_(std::move(secret))
{}

template <DigestSize Bits, typename Backend>
HmacShaSigner<Bits, Backend>::~HmacShaSigner() {
    Backend::SecureClear(secret_);
}

template <DigestSize Bits, typename Backend>
std::string HmacShaSigner<Bits, Backend>::Sign(std::initializer_list<std::string_view> data) const {
    return Backend::template ComputeHmac<typename HmacAlgoTag<Bits>::type>(
        secret_, data, hash::OutputEncoding::kBinary
    );
}

template class HmacShaSigner<DigestSize::k160>;
template class HmacShaSigner<DigestSize::k256>;
template class HmacShaSigner<DigestSize::k384>;
template class HmacShaSigner<DigestSize::k512>;

///
/// *SA
///

template <DsaType Type, DigestSize Bits, typename Backend>
DsaSigner<Type, Bits, Backend>::DsaSigner(const std::string& key, const std::string& password)
    : Signer(EnumValueToString(Type) + EnumValueToString(Bits)),
      pkey_(BasicPrivateKey<Backend>::LoadFromString(key, password))
{
    Backend::template ValidateForSigning<Type, Bits>(pkey_.GetNative(), Name());
}

template <DsaType Type, DigestSize Bits, typename Backend>
std::string DsaSigner<Type, Bits, Backend>::Sign(std::initializer_list<std::string_view> data) const {
    return Backend::template DoSign<Type, Bits>(pkey_.GetNative(), data);
}

template <DsaType Type, DigestSize Bits, typename Backend>
std::string DsaSigner<Type, Bits, Backend>::SignDigest(std::string_view digest) const {
    return Backend::template DoSignDigest<Type, Bits>(pkey_.GetNative(), digest);
}

template class DsaSigner<DsaType::kRsa, DigestSize::k160>;
template class DsaSigner<DsaType::kRsa, DigestSize::k256>;
template class DsaSigner<DsaType::kRsa, DigestSize::k384>;
template class DsaSigner<DsaType::kRsa, DigestSize::k512>;

template class DsaSigner<DsaType::kEc, DigestSize::k256>;
template class DsaSigner<DsaType::kEc, DigestSize::k384>;
template class DsaSigner<DsaType::kEc, DigestSize::k512>;

template class DsaSigner<DsaType::kRsaPss, DigestSize::k160>;
template class DsaSigner<DsaType::kRsaPss, DigestSize::k256>;
template class DsaSigner<DsaType::kRsaPss, DigestSize::k384>;
template class DsaSigner<DsaType::kRsaPss, DigestSize::k512>;

///
/// CMS
///

namespace {

int ToNativeCmsFlags(utils::Flags<CmsSigner::Flags> flags) {
    int native = 0;

    using SignFlags = CmsSigner::Flags;
    if (flags & SignFlags::kText) {
        native |= CMS_TEXT;
    }
    if (flags & SignFlags::kNoCerts) {
        native |= CMS_NOCERTS;
    }
    if (flags & SignFlags::kDetached) {
        native |= CMS_DETACHED;
    }
    if (flags & SignFlags::kBinary) {
        native |= CMS_BINARY;
    }

    return native;
}

void OutputCmsContent(BIO& to, CMS_ContentInfo& cms, CmsSigner::OutForm out_form) {
    using OutForm = CmsSigner::OutForm;
    switch (out_form) {
        case OutForm::kDer: {
            if (!i2d_CMS_bio(&to, &cms)) {
                throw SignError{FormatSslError("Failed to sign: i2d_CMS_bio")};
            }
            break;
        }
        case OutForm::kPem: {
            if (!PEM_write_bio_CMS_stream(&to, &cms, nullptr, 0)) {
                throw SignError{FormatSslError("Failed to sign: PEM_write_bio_CMS_stream")};
            }
            break;
        }
        case OutForm::kSMime: {
            if (!SMIME_write_CMS(&to, &cms, nullptr, 0)) {
                throw SignError{FormatSslError("Failed to sign: SMIME_write_CMS")};
            }
            break;
        }
    }
}

}  // namespace

CmsSigner::CmsSigner(Certificate certificate, PrivateKey pkey)
    : NamedAlgo{"CMS"},
      cert_{std::move(certificate)},
      pkey_{std::move(pkey)}
{}

CmsSigner::~CmsSigner() = default;

std::string CmsSigner::Sign(std::initializer_list<std::string_view> data, utils::Flags<Flags> flags, OutForm out_form)
    const {
    const auto native_flags = ToNativeCmsFlags(flags);

    const auto data_string = InitListToString(data);
    const auto bio_data = MakeBioString(data_string);
    if (!bio_data) {
        throw SignError{FormatSslError("Failed to sign: MakeBioString")};
    }

    const std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms_content{
        CMS_sign(cert_.GetNative(), pkey_.GetNative(), nullptr, bio_data.get(), native_flags),
        CMS_ContentInfo_free
    };
    if (!cms_content) {
        throw SignError{FormatSslError("Failed to sign: CMS_sign")};
    }

    const std::unique_ptr<BIO, decltype(&BIO_free_all)> bio_output{BIO_new(BIO_s_mem()), BIO_free_all};
    if (!bio_output) {
        throw SignError{FormatSslError("Failed to sign: BIO_new(BIO_s_mem())")};
    }

    OutputCmsContent(*bio_output, *cms_content, out_form);

    char* output_data = nullptr;
    // Some openssl macro with c-style (as expected) casts
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    const auto output_len = BIO_get_mem_data(bio_output.get(), &output_data);
    if (!output_data || output_len < 0) {
        throw SignError{FormatSslError("Failed to sign: BIO_get_mem_data")};
    }

    return std::string(output_data, output_len);
}

}  // namespace crypto

USERVER_NAMESPACE_END
