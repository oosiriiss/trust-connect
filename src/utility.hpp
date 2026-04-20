#pragma once

#include <charconv>
#include <optional>
#include <string_view>
struct TransparentStringHash {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view str) const -> size_t {
    return std::hash<std::string_view>{}(str);
  }
};

struct TransparentStringCompare {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view left, std::string_view right) const -> bool {
    return left == right;
  }
};

template <typename IntType>
[[nodiscard]] auto parseInt(std::string_view inputValue)
    -> std::optional<IntType> {

  std::optional<IntType> result{0};
  auto [ptr, ec] = std::from_chars(
      inputValue.data(), inputValue.data() + inputValue.size(), *result);

  if (ec != std::errc() || ptr != inputValue.data() + inputValue.size()) {
    return std::nullopt;
  }

  return result;
}
