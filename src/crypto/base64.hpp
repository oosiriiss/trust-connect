#pragma once

#include <expected>
#include <string_view>
namespace crypto {
[[nodiscard]] auto base64Encode(std::string_view)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto base64Decode(std::string_view encoded)
    -> std::expected<std::string, std::string>;
} // namespace crypto
