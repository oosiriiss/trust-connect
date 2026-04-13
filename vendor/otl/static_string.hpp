#pragma once

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>

template <std::size_t Size> struct static_string {
  constexpr static_string() = default;

  // Assumes str to be valid string of length at least Size
  explicit constexpr static_string(std::string_view sv) : data{} {
    std::ranges::copy(sv, data.begin());
  }
  explicit constexpr static_string(const char (&str)[Size + 1]) : data{} {
    // Without null terminator
    std::ranges::copy_n(str, Size, data.begin());
  }

  constexpr auto begin() { return data.begin(); }
  constexpr auto end() { return data.end(); }
  constexpr auto begin() const { return data.begin(); }
  constexpr auto end() const { return data.end(); }

  constexpr auto view() const noexcept -> std::string_view {
    return std::string_view{data.begin(), data.end()};
  }

  constexpr auto size() const noexcept -> std::size_t { return Size; }

  std::array<char, Size> data;
};

template <std::size_t Size, std::size_t OtherSize>
constexpr auto operator+(const static_string<Size> &first,
                         const static_string<OtherSize> &other) {
  static_string<Size + OtherSize> result;

  std::ranges::copy(first.data, result.data.begin());
  std::ranges::copy(other.data,
                    std::next(result.data.begin(), first.data.size()));

  return result;
}

template <std::size_t Size, std::size_t OtherSize>
constexpr auto operator+(const char (&first)[Size],
                         const static_string<OtherSize> &second) {
  static_string<Size + OtherSize> result; // Removing double null terminator

  std::ranges::copy_n(first, Size, result.data.begin());
  std::ranges::copy(second.data, std::next(result.data.begin(), Size));

  return result;
}

template <std::size_t Size, std::size_t OtherSize>
constexpr auto operator+(const static_string<Size> &first,
                         const char (&second)[OtherSize]) {
  static_string<Size + OtherSize> result; // Removing double null terminator

  std::ranges::copy(first.data, result.data.begin());
  std::ranges::copy_n(second, OtherSize, std::next(result.data.begin(), Size));

  return result;
}

#include <format>
template <std::size_t Size>
struct std::formatter<static_string<Size>> // NOLINT
    : std::formatter<std::string_view> {
  template <typename FormatContext>
  constexpr auto format(const static_string<Size> &str,
                        FormatContext &ctx) const {
    // Delegate the actual formatting to the string_view formatter
    return std::formatter<std::string_view>::format(str.view(), ctx);
  }
};
