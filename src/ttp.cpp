#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "logzy/logzy.hpp"
#include "network/socket.hpp"
#include <print>

namespace {

enum class OptionKey {
  BindPort,
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
    std::println("{}", cppli::createHelp(options, "ttp"));
    return true;
  }

  if (auto port = result.options.find(OptionKey::BindPort);
      port != result.options.end()) {
    ctx = std::stoi(std::string(port->second.value.value()));
  }

  return false;
}

auto receiveClient(network::TcpSocket &client, std::string_view clientName)
    -> bool {

  logzy::trace("Waiting for client {} to send data", clientName);

  if (auto received = client.receive()) {
    logzy::info("Received: {}", *received);

    if (received->type == network::PacketType::CloseConnection) {
      return false;
    }

    nlohmann::json payload;
    payload["value_response"] = received->payload["id"];
    auto packet = network::Packet{.type = network::PacketType::RegisterResponse,
                                  .payload = std::move(payload)};

    logzy::trace("Sending echo message to: {}", clientName);
    // Echo
    if (auto err = client.send(packet)) {
      logzy::error("Couldn't send send echo messge to client. {}", *err);
      return false;
    }
    logzy::trace("Sent");

  } else {
    logzy::error("Couldn't receive message from client {}: {}", clientName,
                 received.error());
    return false;
  }

  return true;
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  std::uint16_t bindPort = network::DEFAULT_TTP_PORT;

  if (parseCommandlineArgs(bindPort, argc, argv)) {
    return EXIT_SUCCESS;
  }

  network::TcpServer server;
  if (auto err = server.listen(bindPort)) {
    logzy::critical("TTP Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  logzy::info("Waiting for first client to connect");
  network::TcpSocket client1;
  network::TcpSocket client2;

  if (auto connectedClient = server.accept()) {
    logzy::info("First client connected");
    client1 = std::move(*connectedClient);
  } else {
    logzy::error("First Client connection failed: {}", connectedClient.error());
  }

  if (auto connectedClient = server.accept()) {
    logzy::info("Second client connected");
    client2 = std::move(*connectedClient);
  } else {
    logzy::error("Second Client connection failed: {}",
                 connectedClient.error());
  }
  logzy::info("Clients connected");

  while (true) {
    if (!receiveClient(client1, "Client 1")) {
      break;
    }
    if (!receiveClient(client2, "Client 2")) {
      break;
    }
  }

  return 0;
}
