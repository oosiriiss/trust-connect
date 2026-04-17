#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/vendor/debug_utils.hpp"
#include "crypto/base64.hpp"
#include "crypto/rsa.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <print>
#include <string_view>
#include <unordered_map>

namespace {

enum class OptionKey {
  BindPort,
  Help,
};

struct StringHash {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view str) const -> size_t {
    return std::hash<std::string_view>{}(str);
  }
};

struct StringCompare {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view left, std::string_view right) const -> bool {
    return left == right;
  }
};

struct TtpState {
  std::unordered_map<std::string, crypto::RsaKeyPair, StringHash, StringCompare>
      clientsPublicKeys;
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

auto handleTradePublicKeys(TtpState &state, network::TcpSocket &client,
                           std::string_view clientName,
                           const crypto::RsaKeyPair &ttpKey,
                           const nlohmann::json &payload) -> bool {

  logzy::trace("Received TradePublicKeysWithTtp packet from {}", clientName);
  logzy::trace("Looking for 'public_key_pem' in the payload");

  auto clientPublicKeyPem =
      payload.value("public_key_pem", std::string_view{""});

  if (clientPublicKeyPem.empty()) {
    logzy::error("Client didn't send object with 'public_key_pem' json field "
                 "for TradePublicKeysWithTtp packet. Payload:\n{}",
                 payload.dump());
    return false;
  }

  crypto::RsaKeyPair clientKeyPair;
  logzy::trace("creating RSA Key from {}'s public key PEM", clientName);

  if (auto keyResult = crypto::RsaKeyPair::fromPublicPem(clientPublicKeyPem)) {
    clientKeyPair = std::move(*keyResult);
  } else {
    logzy::error("Couldn't create RSA key from {}'s public Key. key PEM:\n{}",
                 clientName, clientPublicKeyPem);
    return false;
  }

  // TODO :: Save the clietnKeyPair somewhere

  DEBUG_ASSERT(!state.clientsPublicKeys.contains(clientName));
  state.clientsPublicKeys.emplace(clientName, std::move(clientKeyPair));

  logzy::trace("Sending TTP's public key PEM to the {}", clientName);

  std::string ttpPublicKeyPem;
  if (auto publicKeyResult = ttpKey.publicKeyPem()) {
    ttpPublicKeyPem = std::move(*publicKeyResult);
  } else {
    logzy::error("Couldn't create PEM from TTP's public key.");
    return false;
  }

  if (auto err = client.send(network::Packet{
          .type = network::PacketType::TradePublicKeysWithTtpResponse,
          .payload = {
              {"public_key_pem", std::move(ttpPublicKeyPem)},
          }})) {
    logzy::error("Couldn't send TTP's public key pem to the {}", clientName);
    return false;
  }

  return true;
}

auto handleRegister(TtpState &state, network::TcpSocket &client,
                    std::string_view clientName,
                    const crypto::RsaKeyPair &ttpKey,
                    const nlohmann::json &payload) -> bool {

  auto encryptedId = payload.value("id", std::string_view{""});
  if (encryptedId.empty()) {
    logzy::error("Payload must include 'id' field");
    return false;
  }

  std::string id;

  logzy::trace("Base64 encoded ID: {}", encryptedId);

  if (auto baseResult = crypto::base64Decode(encryptedId)) {
    id = std::move(*baseResult);
  } else {
    logzy::error("Couldnt base64 decode id. {}", baseResult.error());
    return false;
  }

  logzy::trace("Encrypted ID: {}", id);
  if (auto idResult = ttpKey.decryptPrivate(id)) {
    id = std::move(*idResult);
  } else {
    logzy::error("Couldn't decrypt ID. {}", idResult.error());
    return false;
  }
  logzy::trace("Decrypted ID: {}", id);

  auto it = state.clientsPublicKeys.find(clientName);
  if (it == state.clientsPublicKeys.end()) {
    logzy::error("{} tried to register without trading public keys",
                 clientName);
    return false;
  }

  return true;
}

auto receiveClient(TtpState &state, network::TcpSocket &client,
                   std::string_view clientName,
                   const crypto::RsaKeyPair &ttpKey) -> bool {

  logzy::trace("Waiting for {} to send data", clientName);

  if (auto received = client.receive()) {
    logzy::info("Received packet with type: {}", received->type);
    logzy::trace("Payload:\n{}", received->payload.dump());

    switch (received->type) {
    case network::PacketType::TradePublicKeysWithTtpRequest:
      return handleTradePublicKeys(state, client, clientName, ttpKey,
                                   received->payload);
    case network::PacketType::RegisterRequest:
      return handleRegister(state, client, clientName, ttpKey,
                            received->payload);
      break;
    case network::PacketType::CloseConnection:
      return false;
    case network::PacketType::__SizeGuard:
      [[fallthrough]];
    case network::PacketType::RegisterResponse:
      [[fallthrough]];
    case network::PacketType::TradePublicKeysWithTtpResponse:
      logzy::error("Invalid packet received: {}", received->type);
      return false;
      break;
    }
  }
  return true;
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  std::uint16_t bindPort = network::DEFAULT_TTP_PORT;

  if (parseCommandlineArgs(bindPort, argc, argv)) {
    return EXIT_SUCCESS;
  }

  crypto::RsaKeyPair ttpRsaKey;
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    ttpRsaKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate TTP's RSA key pair");
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

  // if (auto connectedClient = server.accept()) {
  //   logzy::info("Second client connected");
  //   client2 = std::move(*connectedClient);
  // } else {
  //   logzy::error("Second Client connection failed: {}",
  //                connectedClient.error());
  // }

  TtpState state{};

  logzy::info("Clients connected");

  while (true) {
    if (!receiveClient(state, client1, "Client 1", ttpRsaKey)) {
      break;
    }
    // if (!receiveClient(client2, "Client 2")) {
    //   break;
    // }
  }

  return 0;
}
