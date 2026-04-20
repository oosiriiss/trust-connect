#pragma once

#include <algorithm>
#include <array>
#include <string_view>

namespace rainbow::internal {

  template <std::size_t Size>
  struct static_string {
    constexpr static_string() = default;

    // Assumes str to be valid string of length at least Size
    explicit constexpr static_string(std::string_view sv)
        : data{} {
      std::ranges::copy(sv, data.begin());
    }
    explicit constexpr static_string(const char (&str)[Size + 1])
        : data{} {
      // Without null terminator
      std::ranges::copy_n(str, Size, data.begin());
    }

    constexpr auto view() const noexcept -> std::string_view {
      return std::string_view{data.begin(), data.end()};
    }

    constexpr auto size() const noexcept -> std::size_t { return Size; }

    std::array<char, Size> data;
  };

  template <std::size_t Size>
  static_string(const char (&)[Size]) -> static_string<Size>;

  template <std::size_t Size, std::size_t OtherSize>
  constexpr auto operator+(const static_string<Size>& first,
                           const static_string<OtherSize>& other) {
    static_string<Size + OtherSize> result;

    std::ranges::copy(first.data, result.data.begin());
    std::ranges::copy(other.data,
                      std::next(result.data.begin(), first.data.size()));

    return result;
  }

  template <std::size_t Size, std::size_t OtherSize>
  constexpr auto operator+(const char (&first)[Size],
                           const static_string<OtherSize>& second) {
    static_string<Size + OtherSize> result;  // Removing double null terminator

    std::ranges::copy_n(first, Size, result.data.begin());
    std::ranges::copy(second.data, std::next(result.data.begin(), Size));

    return result;
  }

  template <std::size_t Size, std::size_t OtherSize>
  constexpr auto operator+(const static_string<Size>& first,
                           const char (&second)[OtherSize]) {
    static_string<Size + OtherSize> result;  // Removing double null terminator

    std::ranges::copy(first.data, result.data.begin());
    std::ranges::copy_n(second, OtherSize,
                        std::next(result.data.begin(), Size));

    return result;
  }
}  // namespace rainbow::internal
