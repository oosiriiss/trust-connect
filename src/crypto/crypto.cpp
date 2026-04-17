#include "crypto/crypto.hpp"

#include "logzy/logzy.hpp"
#include "openssl.hpp"
#include <expected>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace crypto {

[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string> {

  logzy::trace("Generating random ID for: {}", seed);

  auto randomBytes = openssl::generateRandomBytes<32>();
  if (!randomBytes) {
    return std::unexpected(std::format(
        "generateRandomId :: Generating random 32 bytes failed. Reason {}",
        randomBytes.error()));
  }

  std::string buffer;
  buffer.reserve(64);
  buffer.append(seed);
  buffer.append(
      std::string_view{randomBytes->data.begin(), randomBytes->data.end()});

  return sha256(buffer);
}

} // namespace crypto
