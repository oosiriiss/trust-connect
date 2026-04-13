#pragma once

#include <expected>
#include <string>

#include "static_string.hpp"
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace crypto {
using Hash32 = static_string<32>;

[[nodiscard]] auto sha256(std::string_view input) noexcept
    -> std::expected<Hash32, std::string>;

/**
 * Generates a new random ID from given name + 32 random bytse
 */
[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string>;

[[nodiscard]] auto hashToHex(const Hash32 &hash) noexcept -> std::string;

} // namespace crypto
