// All PrivateKey / BasicPrivateKey<OpenSslBackend> method bodies are now
// defined inline in private_key.hpp (calling OpenSslBackend static methods).
// This translation unit serves as the home for the explicit class instantiation
// so that the template is compiled exactly once in the library.

#include <userver/crypto/private_key.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {

template class BasicPrivateKey<OpenSslBackend>;

}  // namespace crypto

USERVER_NAMESPACE_END
