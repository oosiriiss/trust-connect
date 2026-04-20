#pragma once

#include <codecvt>
#include <concepts>
#include <cstddef>
#include <filesystem>
#include <format>
#include <optional>
#include <variant>

#ifdef _MSC_VER

#else
#include <cxxabi.h>
#endif

namespace internal {
#ifdef _MSC_VER
  template <typename T>
  constexpr auto typeName() -> std::string {
    return typeid(T).name();
  }
#else
  template <typename T>
  constexpr auto typeName() -> std::string {
    int status = -1;

    char *demangledName =
        abi::__cxa_demangle(typeid(T).name(), nullptr, nullptr, &status);

    std::string outName;

    // Success
    if (status == 0) {
      outName = demangledName;

      // Freeing allocated buffer
      std::free(demangledName);
    }

    return outName;
  }
#endif

}  // namespace internal

// TODO :: Helpful message if formatter is not found?

template <typename T>
concept isFormattable = []() {
  constexpr bool isValid = requires(T &value, std::format_context ctx) {
    std::formatter<std::remove_cvref_t<T>>().format(value, ctx);
  };

  static_assert(isValid, "Not formattable type discovered");

  return isValid;
}();

template <typename T>
  requires isFormattable<T>
struct std::formatter<std::optional<T>>
    : std::formatter<std::string> {  // NOLINT

  constexpr auto parse(std::format_parse_context &ctx) { return ctx.begin(); }

  auto format(const std::optional<T> &opt, std::format_context &ctx) const {
    if (opt) {
      return std::format_to(ctx.out(), "{}", *opt);
    }
    return std::format_to(ctx.out(), "{}", "std::optional(nullopt)");
  }
};

template <typename... Ts>
  requires(isFormattable<Ts> && ...)
struct std::formatter<std::variant<Ts...>>
    : std::formatter<std::string> {  // NOLINT

  auto format(const std::variant<Ts...> &variant,
              std::format_context &ctx) const {
    const auto variantIndex = variant.index();
    return std::visit(
        [&ctx, variantIndex](const auto &entry) {
          using T = std::decay_t<decltype(entry)>;
          return std::format_to(ctx.out(),
                                "std::variant(value={}, idx={}, type={})",
                                entry, variantIndex, internal::typeName<T>());
        },
        variant);
  }
};

template <typename T>
  requires std::convertible_to<T, std::basic_string_view<wchar_t>>
struct std::formatter<T> {
  constexpr auto parse(std::format_parse_context &ctx) { return ctx.begin(); }

  auto format(const T &str, std::format_context &ctx) const {
    return std::format_to(ctx.out(), L"{}",
                          std::basic_string_view<wchar_t>(str));
  }
};

// Path with char value type
template <>
struct std::formatter<std::filesystem::path> {
  constexpr auto parse(std::format_parse_context &ctx) { return ctx.begin(); }

  auto format(const std::filesystem::path &path,
              std::format_context &ctx) const {
    return std::format_to(ctx.out(), "{}", path.string());
  }
};
