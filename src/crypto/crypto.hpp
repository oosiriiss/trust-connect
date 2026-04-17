#pragma once

#include "hash.hpp"
#include <string>

namespace crypto {

/**
 * Generates a new random ID from given name + 32 random bytse
 */
[[nodiscard]] auto generateRandomId(std::string_view seed) noexcept
    -> std::expected<Hash32, std::string>;

} // namespace crypto
