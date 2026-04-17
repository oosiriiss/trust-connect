#pragma once

#include "static_string.hpp"
#include <expected>

namespace crypto {
using Hash32 = static_string<32>;

[[nodiscard]] auto sha256(std::string_view input) noexcept
    -> std::expected<Hash32, std::string>;

[[nodiscard]] auto hashToHex(const Hash32 &hash) noexcept -> std::string;
} // namespace crypto
