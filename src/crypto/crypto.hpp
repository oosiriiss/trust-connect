#pragma once

#include "crypto/aes.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "hash.hpp"
#include "nlohmann/json_fwd.hpp"
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

auto encryptAndEncode(std::string_view data, const crypto::Aes256 &key)
    -> std::expected<std::string, std::string>;

/**
 * Decodes base64 encoded string and decrypts the content.
 */
auto decodeAndDecrypt(std::string_view encrypted, const crypto::Aes256 &key)
    -> std::expected<std::string, std::string>;

auto signPayload(const RsaKeyPair &privateKey, nlohmann::json &payload)
    -> std::optional<std::string>;

auto verifyPayload(const RsaKeyPair &publicKey, nlohmann::json &payload)
    -> std::expected<bool, std::string>;

} // namespace crypto
