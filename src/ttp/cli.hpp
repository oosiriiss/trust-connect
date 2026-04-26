#pragma once

#include "common/cli.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/option.hpp"
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <print>

namespace cli::ttp {

/**
 * Enum containing avaialble TTP CLI options
 */
enum class TtpOption : std::uint8_t { Help, BindPort };

/**
 * @brief Holds the parsed CLI data
 *
 * TTP's implementation of the ::cli::ArgContext concept
 */
struct TtpArguments {
  std::uint16_t bindPort = network::DEFAULT_TTP_PORT;

  /**
   * Returns cppli::OptionContainer<TtpOption> containing all the TTP's
   * available CLI options
   */
  [[nodiscard]] static constexpr auto options()
      -> cppli::OptionContainer<TtpOption> {

    cppli::OptionContainer<TtpOption> options;

    options.addOption(
        TtpOption::BindPort,
        cppli::Option{
            .firstName = "-p",
            .secondName = "--port",
            .description =
                "Specifies the port at which the server will listen on",
            .needsValue = true});
    options.addOption(TtpOption::Help,
                      cppli::Option{.firstName = "-h",
                                    .secondName = "--help",
                                    .description = "Displays the help message",
                                    .needsValue = false});

    return options;
  }

  /**
   * @brief Parses the raw CLI results int TtpArguments struct
   */
  [[nodiscard]] static constexpr auto
  from(const cppli::ParseResult<TtpOption> &result)
      -> std::expected<TtpArguments, int> {

    std::expected<TtpArguments, int> args{TtpArguments{}};
    if (result.options.contains(TtpOption::Help)) {
      std::println("{}", cppli::createHelp(options(), "ttp"));
      return std::unexpected{EXIT_FAILURE};
    }

    if (auto port = result.options.find(TtpOption::BindPort);
        port != result.options.end()) {
      CLI_PARSE_OR_RETURN_FAIL(port, args->bindPort);
    }

    return args;
  }
};
} // namespace cli::ttp
