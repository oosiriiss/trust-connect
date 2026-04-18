#include "crypto/crypto.hpp"

#include "crypto/base64.hpp"
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

auto encryptAndEncode(std::string_view data, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string> {
  logzy::debug("Encrypting and encoding");
  logzy::trace("Data: {}", data);

  std::expected<std::string, std::string> encrypted(std::string{});
  logzy::trace("First encrypting");
  if (auto encryptResult = key.encryptPublic(data)) {
    *encrypted = std::move(*encryptResult);
  } else {
    return std::unexpected(
        std::format("Couldnt' encrypt data. {}", encryptResult.error()));
  }

  logzy::trace("Encryption complete. Now encoding with Base64");
  if (auto baseResult = crypto::base64Encode(*encrypted)) {
    *encrypted = std::move(*baseResult);
  } else {
    return std::unexpected(
        std::format("Couldnt' base64 Encode the data. {}", baseResult.error()));
  }
  logzy::debug("Encryption success");
  logzy::trace("Encrypted data: {}", *encrypted);
  return encrypted;
}

auto decodeAndDecrypt(std::string_view encrypted, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string> {
  logzy::debug("Decoding and decryprting");
  logzy::trace("Encoded data: {}", encrypted);

  std::expected<std::string, std::string> decrypted(std::string{});
  logzy::trace("Decoding data");
  if (auto baseResult = crypto::base64Decode(encrypted)) {
    *decrypted = std::move(*baseResult);
  } else {
    return std::unexpected(
        std::format("Couldnt' base64 Decode the data. {}", baseResult.error()));
  }
  logzy::trace("Data decoded. Now decrypting.");
  if (auto decryptResult = key.decryptPrivate(*decrypted)) {
    *decrypted = std::move(*decryptResult);
  } else {
    return std::unexpected(
        std::format("Couldnt' decrypt data. {}", decryptResult.error()));
  }
  logzy::debug("Decryption success");
  logzy::trace("Decrypted data: {}", *decrypted);
  return decrypted;
}

} // namespace crypto
