#pragma once

#include <concepts>
#include <cstdint>
#include <print>
#include <source_location>
#include <string>
#include <type_traits>
#include <utility>

#include "logzy/formatters.hpp"
#include "rainbowcpp/colors.hpp"
#include "rainbowcpp/rainbowcpp.hpp"

namespace logzy {
namespace internal {

enum class LogLevel : std::uint8_t {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warning = 3,
  Error = 4,
  Critical = 5
};

constexpr LogLevel
    COMP_MIN_LOG_LEVEL = //  NOLINT(readability-identifier-naming)
#if defined(LOGZY_MIN_TRACE)
    LogLevel::Trace;
#elif defined(LOGZY_MIN_DEBUG)
    LogLevel::Debug;
#elif defined(LOGZY_MIN_INFO)
    LogLevel::Info;
#elif defined(LOGZY_MIN_WARNING)
    LogLevel::Warning;
#elif defined(LOGZY_MIN_ERROR)
    LogLevel::Error;
#elif defined(LOGZY_MIN_CRITICAL)
    LogLevel::Critical;
#else
#define LOGZY_MIN_DEBUG
    LogLevel::Trace;
#endif

constexpr std::string_view toString(const LogLevel level) {
  switch (level) {
  case LogLevel::Trace:
    return "TRACE";
  case LogLevel::Debug:
    return "DEBUG";
  case LogLevel::Info:
    return "INFO";
  case LogLevel::Warning:
    return "WARNING";
  case LogLevel::Error:
    return "ERROR";
  case LogLevel::Critical:
    return "CRITICAL";
  }
  std::unreachable();
}

constexpr std::string_view textColor(const LogLevel level) {
  using Fg = rainbow::colors::bit4::Foreground;
  using Bg = rainbow::colors::bit4::Background;

  switch (level) {
  case LogLevel::Trace:
    return rainbow::color<rainbow::Color(64, 64, 64), // NOLINT
                          Bg::Default>();
  case LogLevel::Debug:
    return rainbow::color<Fg::Gray, Bg::Black>();
  case LogLevel::Info:
    return rainbow::color<Fg::Blue, Bg::Black>();
  case LogLevel::Warning:
    return rainbow::color<Fg::Yellow, Bg::Black>();
  case LogLevel::Error:
    return rainbow::color<Fg::Red, Bg::Black>();
  case LogLevel::Critical:
    return rainbow::color<Fg::Black, Bg::Red>();
  }

  std::unreachable();
}

constexpr std::string formatLogLevel(const LogLevel level) {
  const std::string_view levelStr = toString(level);
  const std::string_view color = textColor(level);
  constexpr std::string_view reset = rainbow::reset();

  return std::format("{}[{}]{}", color, levelStr, reset);
}

template <typename... Args>
inline void log(LogLevel level, const std::source_location sourceLoc,
                std::format_string<Args...> fmt, Args &&...args) {
  auto formattedLevel = formatLogLevel(level);
  auto message = std::format(fmt, std::forward<Args>(args)...);

  // FIXME :: Possible slowdown?
  const auto f = std::string_view(sourceLoc.file_name());
  const auto filename = f.substr(f.find_last_of('/') + 1);

  std::println("{} {}({}:{}) | {}", formattedLevel, filename, sourceLoc.line(),
               sourceLoc.column(), message);
}

template <typename... Args>
struct log_meta { // NOLINT(readability-identifier-naming)
  std::format_string<Args...> fmt;
  std::source_location loc;

  template <typename StringType>
    requires std::is_constructible_v<std::format_string<Args...>,
                                     StringType>
  consteval log_meta( // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
      StringType fmt,
      std::source_location loc = std::source_location::current()) noexcept
      : fmt{fmt}, loc{loc} {}
};

template <LogLevel Level, typename... Args>
constexpr void basicLog(log_meta<Args...> format, Args &&...args) {
  if constexpr (std::to_underlying(Level) >=
                std::to_underlying(COMP_MIN_LOG_LEVEL)) {
    internal::log(Level, format.loc, format.fmt, std::forward<Args>(args)...);
  }
}

} // namespace internal

template <typename... Args>

// NOLINTNEXTLINE(readability-identifier-naming)
using log_format = std::type_identity_t<internal::log_meta<Args...>>;

template <typename... Args>
constexpr void trace(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Trace, Args...>(
      format, std::forward<Args>(args)...);
}

template <typename... Args>
constexpr void debug(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Debug, Args...>(
      format, std::forward<Args>(args)...);
}

template <typename... Args>
constexpr void info(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Info, Args...>(
      format, std::forward<Args>(args)...);
}

template <typename... Args>
constexpr void warn(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Warning, Args...>(
      format, std::forward<Args>(args)...);
}

template <typename... Args>
constexpr void error(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Error, Args...>(
      format, std::forward<Args>(args)...);
}

template <typename... Args>
constexpr void critical(log_format<Args...> format, Args &&...args) {
  internal::basicLog<internal::LogLevel::Critical, Args...>(
      format, std::forward<Args>(args)...);
}
} // namespace logzy
