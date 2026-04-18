#pragma once

#include "crypto/rsa.hpp"
#include "hash.hpp"
#include <string>

namespace crypto {

/**
 * Generates a new random ID from given name + 32 random bytse
 */
[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string>;

/**
 * Encrypts the data and encodes it with base64
 */
auto encryptAndEncode(std::string_view data, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string>;

/**
 * Decodes base64 encoded string and decrypts the content.
 */
auto decodeAndDecrypt(std::string_view encrypted, const crypto::RsaKeyPair &key)
    -> std::expected<std::string, std::string>;

} // namespace crypto
