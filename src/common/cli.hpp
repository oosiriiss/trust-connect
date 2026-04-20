#pragma once

#include "cppli/option.hpp"
#include "utility.hpp"
#include <cppli/cppli.hpp>
#include <cstdlib>
#include <exception>
#include <expected>
#include <print>

namespace cli {

template <typename> struct extract_key;

template <typename Key> struct extract_key<cppli::OptionContainer<Key>> {
  using type = Key; // NOLINT
};

template <typename T>
using option_key_t = // NOLINT
    typename extract_key<decltype(T::options())>::type;

/**
 * @brief Concept for types that can be constructed from parsed CLI arguments.
 */
template <typename T>
concept ArgContext = requires(T t, cppli::ParseResult<option_key_t<T>> result) {
  { T::options() } -> std::same_as<cppli::OptionContainer<option_key_t<T>>>;
  { T::from(result) } -> std::same_as<std::expected<T, int>>;
};

/**
 * @brief Utility function to strongly-typed commandline arguments parsing.
 *
 * @details User is notified about failures via stdout here , no need to do
 * additional printing.
 *
 * @tparam Key The OptionKey used in cppli.
 * @tparam T The output struct that will load the parsed arguments.
 *
 * @param Options The configure container of desired options.
 * @param argc Program argument count obtained preferrably from main's argc.
 * @param argv Program argument count obtained preferrably from main's argv.
 *
 * @return
 * - expected(T) Parsing was successful.
 * - unexpected(EXIT_SUCCESS) Parsing was successful but user requested a
 * terminal option like --help
 * - unexpected(EXIT_FAILURE) Parsing was not successful
 */
template <ArgContext T>
[[nodiscard]] auto parseCommandlineArgs(const int argc,
                                        char const *const *const argv)
    -> std::expected<T, int> {

  using Key = option_key_t<T>;
  cppli::ParseResult<Key> result;
  try {
    result = cppli::parseArguments(argc, argv, T::options());
  } catch (const std::exception &exc) {
    std::println("Couldn't parse arguments: {}", exc.what());
    return std::unexpected{EXIT_FAILURE};
  }

  return T::from(result);
}

template <std::integral IntType>
inline auto tryParseTo(std::string_view input, IntType &out) -> bool {

  if (auto parsed = parseInt<IntType>(input)) {
    out = *parsed;
    return true;
  }

  std::println("Couldn't parse '{}'. not an integer-only string.", input);
  return false;
}

#define CLI_PARSE_OR_RETURN_FAIL(input, output) /*NOLINT*/                     \
  if (!tryParseTo((input)->second.value.value(), output)) {                    \
    return std::unexpected{EXIT_FAILURE};                                      \
  }

} // namespace cli
