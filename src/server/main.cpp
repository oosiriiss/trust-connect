#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "crypto/aes.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/network.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "server/cli.hpp"
#include <cstdlib>
#include <unistd.h>

namespace {

struct AppContext {
  crypto::Hash32 id{};
  crypto::X509Certificate serverCertificate;
  crypto::RsaKeyPair serverKey;
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

auto registerAndGetCertificate(network::TcpSocket &ttpSocket, AppContext &ctx,
                               protocol::TtpData &ttpData,
                               bool falsifyCertificate) -> bool {

  if (auto cert = protocol::obtainCertificate(
          ttpSocket, crypto::hashToHex(ctx.id), ctx.serverKey, ttpData)) {
    ctx.serverCertificate = std::move(*cert);
  } else {
    logzy::error("Couldn't obtain certificate. {}", cert.error());
    if (!falsifyCertificate) {
      return false;
    }
    logzy::info("False certificate is enabled. Trying to recover by creating "
                "self-signed fake certificate.");
  }

  if (!falsifyCertificate) {
    return true;
  }

  logzy::info("Overwriting ttp's certificate with own forged certificate.");
  if (auto cert = crypto::X509Certificate::createSelfSignedCA(
          "Server's fake certificate", ctx.serverKey)) {
    ctx.serverCertificate = std::move(cert).value();
  } else {
    logzy::critical(
        "There was an  error when generating server's fake certificate. {}",
        cert.error());
    return false;
  }

  return true;
}

void clientSession(network::TcpSocket &clientSocket,
                   crypto::Aes256 &sessionKey) {

  while (true) {
    auto packet = clientSocket.receive();
    if (!packet) {
      logzy::error("Couldn't receive. {}", packet.error());
      break;
    }

    if (packet->type == network::PacketType::CloseConnection) {
      break;
    }

    if (packet->type != network::PacketType::DataRequest) {
      logzy::error("Wrong packet received. {}", packet->type);
      continue;
    }

    handleDataRequest(clientSocket, packet->payload, sessionKey);
  }
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

  auto ttpSocket = network::connectTo(args->ttpIp, args->ttpPort, "TTP");
  if (!ttpSocket) {
    logzy::critical("Couldn't connect to TTP. {}", ttpSocket.error());
    return EXIT_FAILURE;
  }

  auto ttpData = protocol::loadTtpData();
  if (!ttpData) {
    logzy::critical("Couldn't load TTP data. {}", ttpData.error());
    return EXIT_FAILURE;
  }
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    ctx.serverKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate servers RSA key pair");
    return EXIT_FAILURE;
  }

  if (!registerAndGetCertificate(*ttpSocket, ctx, *ttpData,
                                 args->falsifyCertificate)) {
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

    auto payload = clientSocket->receive();
    if (!payload) {
      logzy::error("Couldn't ceveive. {}", payload.error());
    }

    ttpSocket =
        network::connectTo(args->ttpIp, args->ttpPort, "Trusted third party");
    if (!ttpSocket) {
      logzy::error("Connecting to TTP failed. {}", ttpSocket.error());
      break;
    }

    if (auto err = protocol::initiateAuthentication(
            *ttpSocket, ctx.serverCertificate, protocol::ClientRole::Service)) {
      logzy::error("Couldn't initiate atuhentication with TTP. {}", *err);
      break;
    }

    if (auto sessKey =
            protocol::serverHandshake(*ttpSocket, payload->payload,
                                      ctx.serverKey, ctx.serverCertificate)) {
      sessionKey = std::move(sessKey).value();
    } else {
      network::sendError(*clientSocket, "Server authentication failed");
      logzy::error("Couldn't estaiblsih connection. {}", sessKey.error());
      continue;
    }

    clientSession(*clientSocket, sessionKey);
  }

  return EXIT_SUCCESS;
}
