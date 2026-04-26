#pragma once

#include "common/cli.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/option.hpp"
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <print>

namespace cli::server {

/**
 * Enum containing avaialble server CLI options
 */
enum class ServerOption : std::uint_fast8_t {

  BindPort,
  TtpIp,
  TtpPort,
  Help,
  FalsifyCertificate,
};

/**
 * @brief Holds the parsed CLI data
 *
 * Client's implementation of the ::cli::ArgContext concept
 */
struct ServerArguments {
  std::uint16_t bindPort{network::DEFAULT_SERVER_PORT};
  std::string ttpIp{network::DEFAULT_TTP_IP};
  std::uint16_t ttpPort{network::DEFAULT_TTP_PORT};
  bool falsifyCertificate{false};

  /**
   * Returns cppli::OptionContainer<ClientOption> containing all the server's
   * available CLI options
   */
  [[nodiscard]] static constexpr auto options()
      -> cppli::OptionContainer<ServerOption> {
    cppli::OptionContainer<ServerOption> options;

    options.addOption(
        ServerOption::BindPort,
        cppli::Option{
            .firstName = "-p",
            .secondName = "--port",
            .description =
                "Specifies the port at which the server will listen on",
            .needsValue = true});
    options.addOption(
        ServerOption::TtpIp,
        cppli::Option{.firstName = "-S",
                      .secondName = "--ttp-ip",
                      .description = "Specifies ip at which the TTP is located",
                      .needsValue = true});
    options.addOption(
        ServerOption::TtpPort,
        cppli::Option{.firstName = "-P",
                      .secondName = "--ttp-port",
                      .description =
                          "Specifies port at which the TTP is located",
                      .needsValue = true});
    options.addOption(ServerOption::Help,
                      cppli::Option{.firstName = "-h",
                                    .secondName = "--help",
                                    .description = "Displays the help message",
                                    .needsValue = false});
    options.addOption(
        ServerOption::FalsifyCertificate,
        cppli::Option{.firstName = "-f",
                      .secondName = "--falsify-certificate",
                      .description =
                          "Makes the server use it's own certificate that is "
                          "not issued by the TTP.",
                      .needsValue = false});

    return options;
  }

  /**
   * @brief Parses the raw CLI results int ServerArguments structure
   */
  [[nodiscard]] static constexpr auto
  from(const cppli::ParseResult<ServerOption> &result)
      -> std::expected<ServerArguments, int> {

    std::expected<ServerArguments, int> args{ServerArguments{}};

    // Help terminates
    if (result.options.contains(ServerOption::Help)) {
      std::println("{}", cppli::createHelp(options(), "ttp-server"));
      return std::unexpected{EXIT_SUCCESS};
    }
    if (result.options.contains(ServerOption::FalsifyCertificate)) {
      args->falsifyCertificate = true;
    }

    if (auto port = result.options.find(ServerOption::BindPort);
        port != result.options.end()) {
      CLI_PARSE_OR_RETURN_FAIL(port, args->bindPort);
    }
    if (auto ttpIp = result.options.find(ServerOption::TtpIp);
        ttpIp != result.options.end()) {
      args->ttpIp = ttpIp->second.value.value();
    }
    if (auto ttpPort = result.options.find(ServerOption::TtpPort);
        ttpPort != result.options.end()) {
      CLI_PARSE_OR_RETURN_FAIL(ttpPort, args->ttpPort)
    }

    return args;
  }
};
} // namespace cli::server
