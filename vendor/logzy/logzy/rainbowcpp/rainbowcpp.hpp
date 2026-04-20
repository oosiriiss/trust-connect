#pragma once

#include <concepts>
#include <string_view>
#include <utility>

#include "colors.hpp"
#include "static_str.hpp"
#include "utility.hpp"

// TODO
// - Generating the colored strings at compile time - injecting the start and
// end
//

namespace rainbow {

  namespace internal {

    template <typename T>
    concept Color4Bit = std::same_as<T, colors::bit4::Foreground> ||
                        std::same_as<T, colors::bit4::Background>;
    template <typename T>
    concept ForegroundColor = std::same_as<T, colors::bit4::Foreground> ||
                              std::same_as<T, rainbow::Color>;
    template <typename T>
    concept BackgroundColor = std::same_as<T, colors::bit4::Background> ||
                              std::same_as<T, rainbow::Color>;

    template <Color4Bit auto Clr, bool IsBackground>
    constexpr auto colorFormat()
        -> static_string<internal::toString<std::to_underlying(Clr)>().size()> {
      constexpr auto clrSv = internal::toString<std::to_underlying(Clr)>();
      return static_string<clrSv.size()>(clrSv);
    }

    template <Color Clr, bool IsBackground>
    constexpr auto colorFormat() {
      constexpr auto prefix = []() {
        if constexpr (IsBackground) {
          return static_string("48;2;");
        } else {
          return static_string("38;2;");
        }
      }();

      constexpr std::string_view red = internal::toString<Clr.r>();
      constexpr std::string_view green = internal::toString<Clr.g>();
      constexpr std::string_view blue = internal::toString<Clr.b>();
      return static_string(prefix + static_string<red.size()>(red) + ";" +
                           static_string<green.size()>(green) + ";" +
                           static_string<blue.size()>(blue));
    }
  }  // namespace internal

  template <
      internal::ForegroundColor auto Fg,
      internal::BackgroundColor auto Bg = colors::bit4::Background::Default>
  constexpr auto color() -> std::string_view {
    constexpr internal::static_string fgStr =
        internal::colorFormat<Fg, false>();
    constexpr internal::static_string bgStr = internal::colorFormat<Bg, true>();
    constexpr static internal::static_string result =
        "\033[" + fgStr + ";" + bgStr + "m";

    return result.view();
  }

  constexpr auto reset() -> std::string_view { return "\033[39;49m"; }

}  // namespace rainbow
