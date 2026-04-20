#pragma once

#include "common/cli.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/option.hpp"
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <print>

namespace cli::client {
enum class ClientOption : std::uint_fast8_t {
  ServerIp,
  ServerPort,
  TtpIp,
  TtpPort,
  Help
};

struct ClientArguments {
  std::string serverIp{network::DEFAULT_SERVER_IP};
  std::string ttpIp{network::DEFAULT_TTP_IP};
  std::uint16_t serverPort{network::DEFAULT_SERVER_PORT};
  std::uint16_t ttpPort{network::DEFAULT_TTP_PORT};

  [[nodiscard]] static constexpr auto options()
      -> cppli::OptionContainer<ClientOption> {
    cppli::OptionContainer<ClientOption> options;

    options.addOption(
        ClientOption::ServerIp,
        cppli::Option{.firstName = "-s",
                      .secondName = "--server-ip",
                      .description =
                          "Specifies ip at which the server is located",
                      .needsValue = true});
    options.addOption(
        ClientOption::ServerPort,
        cppli::Option{.firstName = "-p",
                      .secondName = "--server-port",
                      .description =
                          "Specifies port at which the TTP is located",
                      .needsValue = true});
    options.addOption(
        ClientOption::TtpIp,
        cppli::Option{.firstName = "-S",
                      .secondName = "--ttp-ip",
                      .description = "Specifies ip at which the TTP is located",
                      .needsValue = true});
    options.addOption(
        ClientOption::TtpPort,
        cppli::Option{.firstName = "-P",
                      .secondName = "--ttp-port",
                      .description =
                          "Specifies port at which the TTP is located",
                      .needsValue = true});
    options.addOption(ClientOption::Help,
                      cppli::Option{.firstName = "-h",
                                    .secondName = "--help",
                                    .description = "Displays the help message",
                                    .needsValue = false});

    return options;
  }

  [[nodiscard]] static constexpr auto
  from(const cppli::ParseResult<ClientOption> &result)
      -> std::expected<ClientArguments, int> {

    std::expected<ClientArguments, int> args{};

    // Help terminates
    if (result.options.contains(ClientOption::Help)) {
      std::println("{}", cppli::createHelp(options(), "ttp-client"));
      return std::unexpected{EXIT_SUCCESS};
    }

    if (auto serverIp = result.options.find(ClientOption::ServerIp);
        serverIp != result.options.end()) {
      args->serverIp = serverIp->second.value.value();
    }
    if (auto serverPort = result.options.find(ClientOption::ServerPort);
        serverPort != result.options.end()) {
      CLI_PARSE_OR_RETURN_FAIL(serverPort, args->serverPort)
    }

    if (auto ttpIp = result.options.find(ClientOption::TtpIp);
        ttpIp != result.options.end()) {
      args->ttpIp = ttpIp->second.value.value();
    }
    if (auto ttpPort = result.options.find(ClientOption::TtpPort);
        ttpPort != result.options.end()) {
      CLI_PARSE_OR_RETURN_FAIL(ttpPort, args->ttpPort);
    }

    return args;
  }
};
} // namespace cli::client
