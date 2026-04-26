#pragma once

#include "static_string.hpp"
#include <expected>

namespace crypto {

/**
 * Type alias for a 32-byte long has
 */
using Hash32 = static_string<32>;

/**
 * @brief Creates a SHA256 hash of the @p input @p
 *
 * @param input The data using which the hash should be calculated
 *
 * @return
 * - Success: Hash32 containing the 32-byte raw binary hash
 * - Error: String error message
 */
[[nodiscard]] auto sha256(std::string_view input) noexcept
    -> std::expected<Hash32, std::string>;

/**
 * @brief Converts a raw binary 32-byte hash into a hexadecimal string.
 *
 * Useful for displaying the hash or sending it using for example JSON, as raw
 * hash may contain unprintable/invalid characters
 *
 * @param hash The raw Hash32 object convert from
 *
 * @return A std::string containing the hexrepresentation of the hash.
 */
[[nodiscard]] auto hashToHex(const Hash32 &hash) noexcept -> std::string;
} // namespace crypto
