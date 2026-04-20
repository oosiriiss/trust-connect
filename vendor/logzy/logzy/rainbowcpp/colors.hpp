#pragma once
#include <cstdint>

namespace rainbow {

  struct Color {
    constexpr Color(std::uint8_t red, std::uint8_t green, std::uint8_t blue)
        : r(red),
          g(green),
          b(blue) {}

    std::uint8_t r;
    std::uint8_t g;
    std::uint8_t b;
  };

  // https:  // en.wikipedia.org/wiki/ANSI_escape_code#8-bit
  namespace colors::bit4 {

    enum class Foreground : std::uint8_t {
      Black = 30,
      Red = 31,
      Green = 32,
      Yellow = 33,
      Blue = 34,
      Magenta = 35,
      Cyan = 36,
      White = 37,
      Default = 39,
      Gray = 90,
      BrightRed = 91,
      BrightGreen = 92,
      BrightYellow = 93,
      BrightBlue = 94,
      BrightMagenta = 95,
      BrightCyan = 96,
      BrightWhite = 97
    };

    enum class Background : std::uint8_t {
      Black = 40,
      Red = 41,
      Green = 42,
      Yellow = 43,
      Blue = 44,
      Magenta = 45,
      Cyan = 46,
      White = 47,
      Default = 49,
      Gray = 100,
      BrightRed = 101,
      BrightGreen = 102,
      BrightYellow = 103,
      BrightBlue = 104,
      BrightMagenta = 105,
      BrightCyan = 106,
      BrightWhite = 107
    };
  }  // namespace colors::bit4
}  // namespace rainbow
