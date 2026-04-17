#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "crypto/crypto.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <cstdlib>
#include <unistd.h>

namespace {

enum class OptionKey {
  Port,
  Help,
};

auto getOptions() {
  cppli::OptionContainer<OptionKey> options;

  options.addOption(
      OptionKey::Port,
      cppli::Option{.firstName = "-p",
                    .secondName = "--port",
                    .description =
                        "Specifies the port at which the server will listen on",
                    .needsValue = true});
  options.addOption(OptionKey::Help,
                    cppli::Option{.firstName = "-h",
                                  .secondName = "--help",
                                  .description = "Displays the help message",
                                  .needsValue = false});

  return options;
}

auto parseCommandlineArgs(std::uint16_t &ctx, int argc,
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

  if (auto port = result.options.find(OptionKey::Port);
      port != result.options.end()) {
    ctx = std::stoi(std::string(port->second.value.value()));
  }

  return false;
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  std::uint16_t port = network::DEFAULT_SERVER_PORT;

  if (parseCommandlineArgs(port, argc, argv)) {
    return EXIT_SUCCESS;
  }

  crypto::Hash32 id{};

  logzy::info("Generating server id");
  if (auto idExp = crypto::generateRandomId("Server")) {
    id = *idExp;
  } else {
    logzy::critical("Couldn't generate ID for client. Reason: {}",
                    idExp.error());
    return EXIT_FAILURE;
  }
  logzy::info("ID generated: {}", crypto::hashToHex(id));

  logzy::info("Binding to port {}", port);
  network::TcpServer server;
  if (auto err = server.listen(port)) {
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
