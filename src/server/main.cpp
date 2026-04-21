#include "common.hpp"
#include "common/cli.hpp"
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
  TtpData ttpData;
};

void estabilishConnection(network::TcpSocket &clientSocket,
                          network::TcpSocket &ttpSocket,
                          crypto::Aes256 &sessionKey,
                          const nlohmann::json &requestPayload,
                          const crypto::Hash32 &serverID,
                          const crypto::RsaKeyPair &serverKey,
                          const crypto::RsaKeyPair &ttpKey,
                          const crypto::X509Certificate &serverCertificate) {
  // Service request sent

  logzy::debug("estabilishConnection");
  const auto userCertPem = requestPayload.value("user_cert_pem", "");
  if (userCertPem.empty()) {
    logzy::error("Client' didnt supply 'user_cert_pem' (user certificate) with "
                 "ServiceRequest");
    return;
  }

  logzy::trace("user certificate PEM:\n{}", userCertPem);

  std::string serverCertPem;

  if (auto res = serverCertificate.toPem()) {
    serverCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert server's certifiacte to PEM");
    return;
  }

  if (auto err = ttpSocket.send(network::Packet{
          .type = network::PacketType::ServerAuthRequest,
          .payload =
              {
                  {"user_certificate_pem", userCertPem},
                  {"server_certificate_pem", serverCertPem},
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

    logzy::trace("Passing ServerAuthOk to client.");

    // passing to user

    if (auto err = clientSocket.send(*ttpVerificationResult)) {
      logzy::error("Couldnt' pass ServerAuthOk to client", *err);
      return;
    }
  } else {
    logzy::error("Couldn't receive TTP's verification packet. {}",
                 ttpVerificationResult.error());
    return;
  }

  logzy::trace("Waiting for client's auth");
  if (auto clientAuthResult = ttpSocket.receive()) {
    if (clientAuthResult->type != network::PacketType::UserAuthOk) {
      logzy::error("Authenticating user failed. Received wrong packet with "
                   "type {}. Expected UserAuthOk",
                   clientAuthResult->type);
      return;
    }

    const auto serverSessionKey = clientAuthResult->payload.value(
        "server_session_key", std::string_view{""});
    const auto clientSessionKey = clientAuthResult->payload.value(
        "client_session_key", std::string_view{""});

    if (serverSessionKey.empty() || clientSessionKey.empty()) {
      logzy::error("USerAuthOk packet sohould have server_session_key and "
                   "client_session_key json fields.");
      return;
    }

    if (auto err = clientSocket.send(*clientAuthResult)) {
      logzy::error("Couldn't forward clientAuthResult packet to the client. {}",
                   *err);
    }

    // TODO :: Store them somewhere
    if (auto keyString =
            crypto::decodeAndDecrypt(serverSessionKey, serverKey)) {

      if (auto aes = crypto::Aes256::fromKey(*keyString)) {
        sessionKey = std::move(*aes);
        logzy::info("Sesssion estalbiflsbifs");
      } else {
        logzy::error("Couldnt create AES 256 GCM form key '{}'. {}", *keyString,
                     aes.error());
        return;
      }
    } else {
      logzy::error("Couldn't decode and decrypt aes key. {}",
                   keyString.error());
      return;
    }

    logzy::info("Session key: {}", sessionKey.getRawKey());

    logzy::info("Auth success. Received session data.");

    logzy::info("Encrypted 'test' = '{}'", *sessionKey.encrypt("test"));

    // SESSION KEY lalalallal blablablabla

  } else {
    logzy::error("Couldn't receive TTP's user verification packet. {}",
                 clientAuthResult.error());
  }
}

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
  if (!connectTo(ttpSocket, args->ttpIp, args->ttpPort,
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

  if (!registerWithTtp(ttpSocket, ctx.id, serverKey, ctx.ttpData,
                       ctx.serverCertificate)) {
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
        estabilishConnection(*clientSocket, ttpSocket, sessionKey,
                             received->payload, ctx.id, serverKey, ttpPublicKey,
                             ctx.serverCertificate);
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
