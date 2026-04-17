#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <cstdlib>
#include <unistd.h>

namespace {

struct AppContext {
  crypto::Hash32 id{};
  std::uint16_t bindPort{network::DEFAULT_SERVER_PORT};
  std::string ttpIp{network::DEFAULT_TTP_IP};
  std::uint16_t ttpPort{network::DEFAULT_TTP_PORT};
};

enum class OptionKey {
  BindPort,
  TtpIp,
  TtpPort,
  Help,
};

auto getOptions() {
  cppli::OptionContainer<OptionKey> options;

  options.addOption(
      OptionKey::BindPort,
      cppli::Option{.firstName = "-p",
                    .secondName = "--port",
                    .description =
                        "Specifies the port at which the server will listen on",
                    .needsValue = true});
  options.addOption(
      OptionKey::TtpIp,
      cppli::Option{.firstName = "-S",
                    .secondName = "--ttp-ip",
                    .description = "Specifies ip at which the TTP is located",
                    .needsValue = true});
  options.addOption(
      OptionKey::TtpPort,
      cppli::Option{.firstName = "-P",
                    .secondName = "--ttp-port",
                    .description = "Specifies port at which the TTP is located",
                    .needsValue = true});
  options.addOption(OptionKey::Help,
                    cppli::Option{.firstName = "-h",
                                  .secondName = "--help",
                                  .description = "Displays the help message",
                                  .needsValue = false});

  return options;
}

auto parseCommandlineArgs(AppContext &ctx, int argc,
                          char const *const *const argv) -> bool {

  cppli::OptionContainer<OptionKey> options = getOptions();
  cppli::ParseResult<OptionKey> result;
  try {
    result = cppli::parseArguments(argc, argv, options);
  } catch (const std::exception &exc) {
    std::println("Couldn't parse arguments: {}", exc.what());
    return true;
  }

  // Help terminates
  if (result.options.contains(OptionKey::Help)) {
    std::println("{}", cppli::createHelp(options, "ttp-server"));
    return true;
  }

  if (auto port = result.options.find(OptionKey::BindPort);
      port != result.options.end()) {
    ctx.bindPort = std::stoi(std::string(port->second.value.value()));
  }
  if (auto ttpIp = result.options.find(OptionKey::TtpIp);
      ttpIp != result.options.end()) {
    ctx.ttpIp = ttpIp->second.value.value();
  }
  if (auto ttpPort = result.options.find(OptionKey::TtpPort);
      ttpPort != result.options.end()) {
    ctx.ttpPort = std::stoi(std::string(ttpPort->second.value.value()));
  }

  return false;
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  std::uint16_t port = network::DEFAULT_SERVER_PORT;
  AppContext ctx{};

  if (parseCommandlineArgs(port, argc, argv)) {
  if (parseCommandlineArgs(ctx, argc, argv)) {
    return EXIT_SUCCESS;
  }

  crypto::Hash32 id{};

  logzy::info("Generating server id");
  if (auto idExp = crypto::generateRandomId("Server")) {
    id = *idExp;
    ctx.id = *idExp;
  } else {
    logzy::critical("Couldn't generate ID for client. Reason: {}",
                    idExp.error());
    return EXIT_FAILURE;
  }
  logzy::info("ID generated: {}", crypto::hashToHex(id));
  logzy::info("ID generated: {}", crypto::hashToHex(ctx.id));

  logzy::info("Binding to port {}", port);
  logzy::info("Binding to port {}", ctx.bindPort);
  network::TcpServer server;
  if (auto err = server.listen(port)) {
  if (auto err = server.listen(ctx.bindPort)) {
    logzy::critical("Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  logzy::info("Bound");

  logzy::info("Waiting for 1 client to connect");
  auto client = server.accept();
  logzy::info("Client connected");

  while (true) {
    if (!client) {
      logzy::error("Accepting client failed: {}", client.error());
      continue;
    }
    logzy::info("Client connected!");

    if (auto received = client->receive()) {
      logzy::info("Received: {}", *received);

      if (received->type == network::PacketType::CloseConnection) {
        break;
      }

      nlohmann::json payload;
      payload["value_response"] = received->payload["value"];
      auto packet =
          network::Packet{.type = network::PacketType::RegisterResponse,
                          .payload = std::move(payload)};

      // Echo
      if (auto err = client->send(packet)) {
        logzy::error("Couldn't send send echo messge to client. {}", *err);
      }
    } else {
      logzy::error("Couldn't receive message from client: {}",
                   received.error());
    }
  }

  return EXIT_SUCCESS;
}
