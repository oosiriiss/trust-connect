#include "crypto/crypto.hpp"

#include "crypto/base64.hpp"
#include "crypto/rsa.hpp"
#include "logzy/logzy.hpp"
#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"
#include "openssl.hpp"
#include <expected>
#include <locale>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <optional>

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

auto encryptAndEncode(std::string_view data, const crypto::Aes256 &key)
    -> std::expected<std::string, std::string> {
  logzy::debug("Encrypting and encoding");
  logzy::trace("Data: {}", data);

  std::expected<std::string, std::string> encrypted(std::string{});
  logzy::trace("First encrypting");
  if (auto encryptResult = key.encrypt(data)) {
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

/**
 * Decodes base64 encoded string and decrypts the content.
 */
auto decodeAndDecrypt(std::string_view encrypted, const crypto::Aes256 &key)
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
  if (auto decryptResult = key.decrypt(*decrypted)) {
    *decrypted = std::move(*decryptResult);
  } else {
    return std::unexpected(
        std::format("Couldnt' decrypt data. {}", decryptResult.error()));
  }
  logzy::debug("Decryption success");
  logzy::trace("Decrypted data: {}", *decrypted);
  return decrypted;
}

auto signPayload(const RsaKeyPair &privateKey, nlohmann::json &payload)
    -> std::optional<std::string> {
  if (payload.contains("signature")) {
    return std::optional{
        std::string{"There is already a signature in the payload."}};
  }

  auto signature = privateKey.sign(payload.dump());
  if (!signature) {
    return std::optional{
        std::format("Couldn't generate a signature. {}", signature.error())};
  }

  if (auto encoded = base64Encode(*signature)) {
    signature = std::move(*encoded);
  } else {
    return std::optional{std::format("Couldn't base64 encode the signature. {}",
                                     encoded.error())};
  }

  payload["signature"] = std::move(*signature);
  return std::nullopt;
}

auto verifyPayload(const RsaKeyPair &publicKey, nlohmann::json &payload)
    -> std::expected<bool, std::string> {
  logzy::debug("Verifying payload's signature");
  std::string signature = payload.value("signature", "");
  logzy::trace("Signature found. '{}'", signature);

  if (signature.empty()) {
    return std::unexpected(std::string{"No signature found in the payload."});
  }

  logzy::trace("Base64Decoding signature");

  if (auto decoded = base64Decode(signature)) {
    signature = std::move(*decoded);
  } else {
    return std::unexpected(
        std::format("couldn't base64 decode signature.", decoded.error()));
  }
  logzy::trace("Decoded signature. {}", signature);

  logzy::trace("removing signature field from the payload");
  if (payload.erase("signature") < 1) {
    return std::unexpected(
        std::string{"Couldn't pop signature key from payload"});
  }

  auto res = publicKey.verify(payload.dump(), signature);
  if (!res) {
    return std::unexpected{std::format(
        "ERror occurred while  verifying signature. {}", res.error())};
  }
  logzy::debug("Verification success");
  return std::expected<bool, std::string>{*res};
}

} // namespace crypto
