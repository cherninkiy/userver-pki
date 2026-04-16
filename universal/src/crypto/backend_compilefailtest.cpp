// Compile-fail test: verifies that a type which does NOT satisfy CryptoBackend
// is rejected by the concept.
//
// Each FAILNEXTLINE marks a statement that must fail to compile.  The CMake
// target that compiles this file expects these diagnostics.

#include <userver/crypto/backend_traits.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto {
namespace {

/// An intentionally empty struct — satisfies nothing.
struct EmptyBackend {};

// FAILNEXTLINE(EmptyBackend does not satisfy CryptoBackend — missing all type aliases and methods)
static_assert(CryptoBackend<EmptyBackend>);

}  // namespace
}  // namespace crypto

USERVER_NAMESPACE_END
