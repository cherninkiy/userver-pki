// Explicit instantiation of CryptoFactory<OpenSslBackend> so that all factory
// methods are compiled exactly once in the library.

#include <userver/crypto/crypto_factory.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

template struct CryptoFactory<OpenSslBackend>;

}  // namespace crypto

USERVER_NAMESPACE_END
