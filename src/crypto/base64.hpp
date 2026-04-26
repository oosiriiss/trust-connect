#pragma once

#include <expected>
#include <string_view>
namespace crypto {
/**
 * @brief Encodes raw @p data into a Base64 string.
 *
 * @param data The raw data to encode
 *
 * @return
 * - Success: A std::string containing the Base64 encoded representation of @p
 * data
 * - Error: String error message
 */
[[nodiscard]] auto base64Encode(std::string_view data)
    -> std::expected<std::string, std::string>;

/**
 * @brief Decodes a Base64 string back into plaintext
 *
 * @param encoded The Base64 encoded string to decode
 *
 * @return
 * - Success: A std::string containing the decoded raw data from @p encoded
 * - Error: String error message (if the operation fails)
 */
[[nodiscard]] auto base64Decode(std::string_view encoded)
    -> std::expected<std::string, std::string>;
} // namespace crypto
