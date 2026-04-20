#pragma once
#include <concepts>
#include <cstdint>
#include <string_view>

namespace rainbow::internal {
  template <std::integral T>
  constexpr auto countDigits(T value) -> std::uint8_t {
    uint8_t digits = 1;

    constexpr int radix = 10;
    while (value >= radix) {
      ++digits;
      value = value / radix;
    }

    return digits;
  }

  template <std::integral auto Value>
  constexpr auto toString() -> std::string_view {
    constexpr static std::array arr = []() -> auto {
      constexpr auto digits = countDigits(Value);

      std::array<char, digits> str{};
      constexpr int radix = 10;
      auto value = Value;
      for (int i = digits - 1; i >= 0; --i) {
        auto digit = static_cast<std::uint8_t>((value + radix) % radix);
        value = value / radix;

        // i is always positive and digit is in range 0-9
        str.at(static_cast<std::size_t>(i)) = static_cast<char>('0' + digit);
      }
      return str;
    }();

    return std::string_view{arr.begin(), arr.end()};
  }

  // template <std::integral auto Value>
  // consteval auto toString() -> std::string_view {
  //   constexpr auto digits = countDigits(Value);
  //   constexpr static std::array<char, digits> str{};
  //   constexpr int radix = 10;

  //  auto value = Value;
  //  for (int i = digits - 1; i >= 0; --i) {
  //    auto digit = static_cast<std::uint8_t>((value + radix) % radix);
  //    value = value / radix;

  //    // i is always positive and digit is in range 0-9
  //    str.at(static_cast<std::size_t>(i)) = static_cast<char>('0' + digit);
  //  }

  //  return std::string_view{str.begin(), str.end()};
  //}

}  // namespace rainbow::internal
