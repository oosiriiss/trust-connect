#pragma once

#include "static_string.hpp"
#include <expected>
#include <string>

namespace crypto::openssl {
[[nodiscard]] auto getError() -> std::string;

/**
 * Allowed byte sizes are: 16, 32, 64
 */
template <std::size_t Bytes>
[[nodiscard]] auto generateRandomBytes() noexcept
    -> std::expected<static_string<Bytes>, std::string>;

} // namespace crypto::openssl
