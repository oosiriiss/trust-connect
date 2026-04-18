#include "common.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
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

void estabilishConnection(network::TcpSocket &clientSocket,
                          network::TcpSocket &ttpSocket,
                          const nlohmann::json &requestPayload,
                          const crypto::Hash32 &serverID,
                          const crypto::RsaKeyPair &ttpKey) {
  // Service request sent

  logzy::debug("estabilishConnection");
  const auto userEncryptedId = requestPayload.value("id", "");
  if (userEncryptedId.empty()) {
    logzy::error("Client' didnt supply id with ServiceRequest");
    return;
  }

  logzy::trace("Encrypted user ID: {}", userEncryptedId);
  logzy::trace("Encrypting server id");

  std::string encryptedServerID;
  if (auto encryptedServerIDResult =
          ttpKey.encryptPublic(crypto::hashToHex(serverID))) {

    logzy::trace("Encrypted server ID: {}", *encryptedServerIDResult);
    logzy::trace("Base64 encoding encrypte dserver id");
    if (auto basedServerID = crypto::base64Encode(*encryptedServerIDResult)) {
      logzy::trace("Base64 Encoded '{}'", *basedServerID);
      encryptedServerID = std::move(*basedServerID);
    } else {
      logzy::error("Couldn't Base64 server ID. {}", basedServerID.error());
      return;
    }

  } else {
    logzy::error("Coulndt' encrypt server id with ttp's public key. {}",
                 encryptedServerIDResult.error());
    return;
  }

  if (auto err = ttpSocket.send(network::Packet{
          .type = network::PacketType::ServerAuthRequest,
          .payload =
              {
                  {"user_id", userEncryptedId},
                  {"server_id", encryptedServerID},
              },
      })) {
    logzy::error("Couldn't send verification data to TTP server. {}", *err);
  }

  if (auto ttpVerificationResult = ttpSocket.receive()) {
    if (ttpVerificationResult->type != network::PacketType::ServerAuthOk) {
      logzy::error("TTP sent wrong auth packet: {}. Expected ServerAuthOk",
                   ttpVerificationResult->type);
      return;
    }

    // passing to user
    if (auto err = clientSocket.send(*ttpVerificationResult)) {
      logzy::error("Couldnt' pass ServerAuthOk to client", *err);
    }
  } else {
    logzy::error("Couldn't receive TTP's verification packet. {}",
                 ttpVerificationResult.error());
  }

  // WATITIGN for User auth ok from ttp
  // WATITIGN for User auth ok from ttp
  // WATITIGN for User auth ok from ttp
  // WATITIGN for User auth ok from ttp
  // WATITIGN for User auth ok from ttp
  // WATITIGN for User auth ok from ttp
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  AppContext ctx{};

  if (parseCommandlineArgs(ctx, argc, argv)) {
    return EXIT_SUCCESS;
  }

  logzy::info("Generating server id");
  if (auto idExp = crypto::generateRandomId("Server")) {
    ctx.id = *idExp;
  } else {
    logzy::critical("Couldn't generate ID for client. Reason: {}",
                    idExp.error());
    return EXIT_FAILURE;
  }
  logzy::info("ID generated: {}", crypto::hashToHex(ctx.id));

  network::TcpSocket ttpSocket;
  if (!connectTo(ttpSocket, ctx.ttpIp, ctx.ttpPort, "Trusted third party")) {
    return EXIT_FAILURE;
  }

  crypto::RsaKeyPair serverKey;
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    serverKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate servers RSA key pair");
    return EXIT_FAILURE;
  }

  std::string publicKeyPem;
  if (auto pemResult = serverKey.publicKeyPem()) {
    publicKeyPem = std::move(*pemResult);
  } else {
    logzy::critical("Couldn't generate servers RSA public PEM");
    return EXIT_FAILURE;
  }

  crypto::RsaKeyPair ttpPublicKey;

  if (auto ttpKeyResult = registerWithTtp(ttpSocket, ctx.id, publicKeyPem)) {
    ttpPublicKey = std::move(*ttpKeyResult);
  } else {
    return EXIT_FAILURE;
  }

  logzy::info("Binding to port {}", ctx.bindPort);
  network::TcpServer server;
  if (auto err = server.listen(ctx.bindPort)) {
    return EXIT_FAILURE;
  }

  logzy::info("Bound");

  logzy::info("Waiting for 1 client to connect");
  auto clientSocket = server.accept();
  logzy::info("Client connected");

  while (true) {
    if (!clientSocket) {
      logzy::error("Accepting client failed: {}", clientSocket.error());
      continue;
    }
    logzy::info("Client connected!");

    if (auto received = clientSocket->receive()) {
      logzy::info("Received: {}", *received);

      if (received->type == network::PacketType::CloseConnection) {
        break;
      }

      if (received->type == network::PacketType::ServiceRequest) {
        estabilishConnection(*clientSocket, ttpSocket, received->payload,
                             ctx.id, ttpPublicKey);
      }

    } else {
      logzy::error("Couldn't receive message from client: {}",
                   received.error());
    }
  }

  return EXIT_SUCCESS;
}
