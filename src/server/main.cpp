#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "server/cli.hpp"
#include <cstdlib>
#include <ios>
#include <unistd.h>

namespace {

struct AppContext {
  crypto::Hash32 id{};
  crypto::X509Certificate serverCertificate;
  protocol::TtpData ttpData;
};

void handleDataRequest(network::TcpSocket &clientSocket,
                       nlohmann::json &payload, crypto::Aes256 &sessionKey) {

  logzy::debug("Handling data request.");
  const auto data = payload.value("data", std::string_view{""});

  if (data.empty()) {
    logzy::error("Client didn't send data.");
    return;
  }

  logzy::debug("Decrypting user data.");
  std::string message;
  if (auto decResult = crypto::decodeAndDecrypt(data, sessionKey)) {
    message = std::move(*decResult);
  } else {
    logzy::error("Couldn't decrypt client's message. {}", *decResult);
    return;
  }
  logzy::debug("Decrypted");
  logzy::trace("Decrypted data = {}", message);

  message += " Hello, bonus from server";

  logzy::debug("Encrypting the return message.");
  logzy::trace("Return message = {}", message);
  if (auto encResult = crypto::encryptAndEncode(message, sessionKey)) {
    message = std::move(*encResult);
  } else {
    logzy::error("Couldn't encryprt message. {}", encResult.error());
    return;
  }

  if (auto err = clientSocket.send(
          network::Packet{.type = network::PacketType::DataResponse,
                          .payload = {{"data", message}}})) {
    logzy::error("Couldn't respond to the client. {}", *err);
    return;
  }

  logzy::info("Data request handled.");
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  auto args =
      cli::parseCommandlineArgs<cli::server::ServerArguments>(argc, argv);
  if (!args) {
    return args.error();
  }
  AppContext ctx{};

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
  if (!protocol::connectTo(ttpSocket, args->ttpIp, args->ttpPort,
                           "Trusted third party")) {
    return EXIT_FAILURE;
  }

  crypto::RsaKeyPair serverKey;
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    serverKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate servers RSA key pair");
    return EXIT_FAILURE;
  }

  if (auto cert = crypto::X509Certificate::fromFile(crypto::TTP_CERT_PATH)) {
    ctx.ttpData.certificate = std::move(*cert);
    logzy::info("Loaded certificate with CN={}",
                ctx.ttpData.certificate.getCommonNameSafe());
  } else {
    logzy::critical("Couldn't load ttp certifiacte. {}", cert.error());
    return EXIT_FAILURE;
  }

  if (auto key = ctx.ttpData.certificate.getPublicKey()) {
    ctx.ttpData.publicKey = std::move(*key);
  } else {
    logzy::critical("Couldn't load ttp' public key  {}", key.error());
    return EXIT_FAILURE;
  }

  crypto::RsaKeyPair ttpPublicKey;

  if (auto cert =
          protocol::registerWithTtp(ttpSocket, ctx.id, serverKey, ctx.ttpData,
                                    protocol::ClientRole::Service)) {
    ctx.serverCertificate = std::move(*cert);
  } else {
    logzy::error("Couldn't obtian certificate.");
    return EXIT_FAILURE;
  }

  logzy::info("Binding to port {}", args->bindPort);
  network::TcpServer server;
  if (auto err = server.listen(args->bindPort)) {
    return EXIT_FAILURE;
  }

  logzy::info("Bound");

  logzy::info("Waiting for 1 client to connect");
  auto clientSocket = server.accept();
  logzy::info("Client connected");

  crypto::Aes256 sessionKey;

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
        if (auto sessKey = protocol::serverHandshake(
                *clientSocket, ttpSocket, received->payload, ctx.id, serverKey,
                ttpPublicKey, ctx.serverCertificate)) {
          sessionKey = std::move(*sessKey);
        } else {
          logzy::error("Couldn't estaiblsih connection. {}", sessKey.error());
        }
      }
      if (received->type == network::PacketType::DataRequest) {
        handleDataRequest(*clientSocket, received->payload, sessionKey);
      }

    } else {
      logzy::error("Couldn't receive message from client: {}",
                   received.error());
    }
  }

  return EXIT_SUCCESS;
}
