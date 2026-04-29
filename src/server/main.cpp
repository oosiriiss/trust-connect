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
#include <thread>
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

  logzy::info("Received data request with encrypted content: {}", data);
  logzy::debug("Decrypting user data.");
  std::string message;
  if (auto decResult = crypto::decodeAndDecrypt(data, sessionKey)) {
    message = std::move(*decResult);
  } else {
    logzy::error("Couldn't decrypt client's message. {}", *decResult);
    return;
  }
  logzy::debug("Decrypted");
  logzy::info("Decrypted data = {}", message);

  message += " Hello, bonus from server";

  logzy::debug("Encrypting the return message.");
  logzy::trace("Return message = {}", message);
  if (auto encResult = crypto::encryptAndEncode(message, sessionKey)) {
    message = std::move(*encResult);
  } else {
    logzy::error("Couldn't encryprt message. {}", encResult.error());
    return;
  }
  logzy::info("Replying with: {}", message);

  if (auto err = clientSocket.send(
          network::Packet{.type = network::PacketType::DataResponse,
                          .payload = {{"data", message}}})) {
    logzy::error("Couldn't respond to the client. {}", *err);
    return;
  }
  logzy::info("Reply success");
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

void clientSession(network::TcpSocket clientSocket, crypto::Aes256 sessionKey) {

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

void handleConnection(network::TcpSocket &&clientSocket,
                      const std::string &ttpHostname,
                      const std::uint16_t ttpPort,
                      const crypto::RsaKeyPair &serverPrivateKey,
                      const crypto::X509Certificate &serverCertificate) {

  logzy::info("Waiting for client to request service");

  auto payload =
      network::expectPacket(clientSocket, network::PacketType::ServiceRequest);
  if (!payload) {
    logzy::error("Couldn't ceveive. {}", payload.error());
    return;
  }

  logzy::info("Client sent packet. Connecting to TTP");

  auto ttpSocket =
      network::connectTo(ttpHostname, ttpPort, "Trusted third party");
  if (!ttpSocket) {
    network::sendError(clientSocket, "Server couldn't connect to TTP");
    logzy::error("Connecting to TTP failed. {}", ttpSocket.error());
    return;
  }
  logzy::info("Initiating authentication with TTP");

  if (auto err = protocol::initiateAuthentication(
          *ttpSocket, serverCertificate, protocol::ClientRole::Service)) {
    network::sendError(clientSocket,
                       "Server couldn't initiate authentication with TTP");
    logzy::error("Couldn't initiate atuhentication with TTP. {}", *err);
    return;
  }

  logzy::info("Performing server handshake");

  auto sessionKey = protocol::serverHandshake(
      *ttpSocket, *payload, serverPrivateKey, serverCertificate);
  if (!sessionKey) {
    network::sendError(clientSocket, "Server authentication failed");
    logzy::error("Couldn't estaiblsih connection. {}", sessionKey.error());
    return;
  }

  logzy::info("Handshake complete. Secure session established.");
  clientSession(std::move(clientSocket), std::move(sessionKey).value());
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

  while (true) {

    logzy::info("Waiting for client to connect");
    auto clientSocket = server.accept();
    logzy::info("Client connected");

    if (!clientSocket) {
      logzy::error("Accepting client connection failed. {}",
                   clientSocket.error());
      continue;
    }

    std::thread(handleConnection, std::move(clientSocket).value(),
                std::cref(args->ttpIp), args->ttpPort, std::cref(ctx.serverKey),
                std::cref(ctx.serverCertificate))
        .detach();
  }

  return EXIT_SUCCESS;
}
