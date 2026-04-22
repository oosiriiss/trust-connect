#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/vendor/debug_utils.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/openssl.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "ttp/cli.hpp"
#include "utility.hpp"
#include <cstdlib>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

struct ClientInfo {
  std::weak_ptr<network::TcpSocket> socket;
};

struct SessionAuthData {
  // std::string requesterId;
  // std::string serviceId;
  crypto::RsaKeyPair servicePublicKey;
  std::weak_ptr<network::TcpSocket> serviceSocket;
};

std::mutex clientRegistryMutex;

struct TtpState {
  crypto::X509Certificate ttpCertificate;

  std::unordered_map<std::string, ClientInfo, TransparentStringHash,
                     TransparentStringCompare>
      loggedClients;

  std::unordered_map<std::string, SessionAuthData, TransparentStringHash,
                     TransparentStringCompare>
      pendingSessions;
};

auto handleRequestCaCertificate(TtpState &state,
                                std::shared_ptr<network::TcpSocket> &client,
                                const crypto::RsaKeyPair &ttpKey,
                                nlohmann::json &payload) -> bool {

  logzy::trace("Received TradePublicKeysWithTtp packet from");

  auto publicKeyPem = payload.value("public_key_pem", std::string_view{""});
  std::string clientID = payload.value("id", "");

  if (clientID.empty()) {
    logzy::error("id is empty");
    return false;
  }

  if (auto res = crypto::decodeAndDecrypt(clientID, ttpKey)) {
    clientID = std::move(*res);
  } else {
    logzy::error("Couldn't decrypt user's id. {}", res.error());
    return false;
  }

  crypto::RsaKeyPair clientPublicKey;

  if (auto res = crypto::RsaKeyPair::fromPublicPem(publicKeyPem)) {
    clientPublicKey = std::move(*res);
  } else {
    logzy::error("Couldn't parse client's public key pem. {}", res.error());
    return false;
  }

  crypto::X509Certificate userCert;
  if (auto certRes =
          state.ttpCertificate.issue(clientPublicKey, clientID, ttpKey)) {
    userCert = std::move(*certRes);
  } else {
    logzy::error("Couldn't create user's certificate.{}", certRes.error());
  }
  logzy::trace("Created user certificate for CN '{}'",
               userCert.getCommonNameSafe());

  logzy::trace("Sending client it's certificate");

  std::string userCertPem;

  if (auto res = userCert.toPem()) {
    userCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert usercertificate to PEM");
    return false;
  }

  nlohmann::json responsePayload = {
      {"certificate_pem", std::move(userCertPem)},
  };

  // Saving client state
  {
    auto publicKey = userCert.getPublicKey();
    if (!publicKey) {
      logzy::error("Couldn't extract user's public key from certificate. {}",
                   publicKey.error());
      return false;
    }

    ClientInfo info{.socket = std::weak_ptr{client}};

    auto userCertCn = userCert.getCommonName();
    if (!userCertCn) {
      logzy::error("Couldn't get common name from user's certificate. {}",
                   userCertCn.error());
      return false;
    }
    std::lock_guard lock{clientRegistryMutex};
    state.loggedClients.emplace(std::move(*userCertCn), std::move(info));
  }

  // RESPONSE
  if (auto err = client->send(
          network::Packet{.type = network::PacketType::CertificateResponse,
                          .payload = std::move(responsePayload)})) {
    logzy::error("error while sending. {}", *err);
    return false;
  }

  logzy::info("sent certificate.");

  return true;
}

auto createSessionTicketPayload(std::string_view clientCn,
                                std::string_view serverCn,
                                const crypto::RsaKeyPair &ttpKey)
    -> std::expected<nlohmann::json, std::string> {

  protocol::SessionTicket ticket{.clientCn = std::string{clientCn},
                                 .serverCn = std::string{serverCn}};

  if (auto res = crypto::openssl::generateRandomBytes<32>()) {
    ticket.sessionId = crypto::hashToHex(*res);
  } else {
    return std::unexpected{
        std::format("Couldn't genreate session id. {}", res.error())};
  }

  auto payload = ticket.toJson();

  if (auto err = crypto::signPayload(ttpKey, payload)) {
    return std::unexpected(
        std::format("Couldn't sign session ticket. {}", *err));
  }
  return payload;
}

auto handleServerAuthRequest(
    TtpState &state, const std::shared_ptr<network::TcpSocket> &serverSocket,
    const network::Packet &packet, std::string_view clientName,
    const crypto::RsaKeyPair &ttpKey) -> bool {
  logzy::trace("{} Authenticating server", clientName);

  // TODO :: client validation will happen later maybe validating the client
  // here is redundant

  std::string userCertPem = packet.payload.value("user_certificate_pem", "");
  std::string serverCertPem =
      packet.payload.value("server_certificate_pem", "");

  if (userCertPem.empty()) {
    logzy::error("user_certificate_pem was not provided as payload json key");
    return false;
  }
  if (serverCertPem.empty()) {
    logzy::error("server_certificate_pem was not provided as payload json key");
    return false;
  }

  crypto::X509Certificate userCert;
  if (auto cert = crypto::X509Certificate::fromPem(userCertPem)) {
    userCert = std::move(*cert);
  } else {
    logzy::error("couldnt' decrypt user certificate. {}", cert.error());
    return false;
  }
  logzy::trace("Decrypted user CA:{}", userCert.getCommonNameSafe());

  crypto::X509Certificate serverCert;
  if (auto cert = crypto::X509Certificate::fromPem(serverCertPem)) {
    serverCert = std::move(*cert);
  } else {
    logzy::error("couldnt' decrypt user certificate. {}", cert.error());
    return false;
  }

  if (auto res = state.ttpCertificate.verify(userCert)) {
    if (!res) {
      logzy::error("Couldn't validate user's certificate!");
      return false;
    }
    logzy::info("User's certificate verified");
  } else {
    logzy::error("Error occurred when validating user's certificate. {}",
                 res.error());
    return false;
  }

  if (auto res = state.ttpCertificate.verify(serverCert)) {
    if (!res) {
      logzy::error("Couldn't validate user's certificate!");
      return false;
    }
    logzy::info("server's certificate verified");
  } else {
    logzy::error("Error occurred when validating user's certificate. {}",
                 res.error());
    return false;
  }

  logzy::trace("Decrypted server CA:{}", serverCert.getCommonNameSafe());
  logzy::debug("Checking if users are verified");
  logzy::debug("Verifying user certificate");
  if (auto res = state.ttpCertificate.verify(userCert)) {
    if (!*res) {
      logzy::error("User provided invalid ceritficate");
      return false;
    }
  } else {
    logzy::error("there was an error when verifying user certificate. {}",
                 res.error());
    return false;
  }

  logzy::debug("Verifying server certificate");
  if (auto res = state.ttpCertificate.verify(serverCert)) {
    if (!*res) {
      logzy::error("User provided invalid ceritficate");
      return false;
    }
  } else {
    logzy::error("there was an error when verifying user certificate. {}",
                 res.error());
    return false;
  }

  if (auto err = serverSocket->send(network::Packet{
          .type = network::PacketType::ServerAuthOk,
          .payload = {}, // Serer gets empty payload
      })) {
    logzy::error("Couldn't send data to client {}. {}", clientName, *err);
    return false;
  }

  nlohmann::json serverAuthOkPayload;
  if (auto res =
          createSessionTicketPayload(userCert.getCommonNameSafe(),
                                     serverCert.getCommonNameSafe(), ttpKey)) {
    serverAuthOkPayload = std::move(*res);
  } else {
    logzy::error("couldnt' create server auth packet payload. {}", res.error());
    return false;
  }

  std::string userCn;
  if (auto res = userCert.getCommonName()) {
    userCn = std::move(*res);
  } else {
    logzy::error("Couldn't get user common name. {}", res.error());
    return false;
  }

  auto iter = state.loggedClients.find(userCn);
  if (iter == state.loggedClients.end()) {
    logzy::error("User not connected");
    return false;
  }

  if (auto clientSocket = iter->second.socket.lock()) {
    if (auto err = clientSocket->send(
            network::Packet{.type = network::PacketType::ServerAuthOk,
                            .payload = std::move(serverAuthOkPayload)})) {
      logzy::error("Couldn't send to client. {}", *err);
      return false;
    }
    logzy::info("Client notified with session ticket.");

    if (auto err = clientSocket->send(network::Packet{
            .type = network::PacketType::UserAuthRedirect, .payload = {}})) {
      logzy::error("Couldn't send to client. {}", *err);
      return false;
    }
  } else {
    logzy::error("Client with id {} disconnected", userCertPem);
    return false;
  }

  logzy::trace("{} Server authenticated", userCn);
  logzy::trace("Server is waiting for client's authentication");

  if (state.pendingSessions.contains(userCn)) {
    logzy::error("There is already a server waiting for id {}", userCn);
    return false;
  }

  {

    auto serverKey = serverCert.getPublicKey();
    if (!serverKey) {
      logzy::error("couldnt' extract server key from server cert. {}",
                   serverKey.error());
      return false;
    }

    std::lock_guard lock{clientRegistryMutex};
    logzy::trace("Inserted waiting for user {}", userCn);
    SessionAuthData data{.servicePublicKey = std::move(*serverKey),
                         .serviceSocket = std::weak_ptr{serverSocket}};
    state.pendingSessions.emplace(std::move(userCn), std::move(data));
  }

  return true;
}

auto handleUserAuthDataSubmit(TtpState &state,
                              const std::shared_ptr<network::TcpSocket> &client,
                              const network::Packet &packet,
                              std::string_view clientName,
                              const crypto::RsaKeyPair &ttpKey) -> bool {

  std::string userCertPem = packet.payload.value("user_cert_pem", "");
  if (userCertPem.empty()) {
    logzy::error("User {} didn't user crt pem", clientName);
    return false;
  }

  crypto::X509Certificate userCert;
  if (auto res = crypto::X509Certificate::fromPem(userCertPem)) {
    userCert = std::move(*res);
  } else {
    logzy::error("Couldn't decrypt user's {} id {}. {}", clientName,
                 userCertPem, res.error());
    return false;
  }

  crypto::RsaKeyPair userPublicKey;
  if (auto res = userCert.getPublicKey()) {
    userPublicKey = std::move(*res);
  } else {
    logzy::error("Coulnd't etarctpuiblic key. {}", res.error());
    return false;
  }

  if (auto res = state.ttpCertificate.verify(userCert)) {
    if (!res) {
      logzy::error("Couldn't validate user's certificate!");
      return false;
    }
    logzy::info("user's certificate verified");
  } else {
    logzy::error("Error occurred when validating user's certificate. {}",
                 res.error());
    return false;
  }

  std::string userCn;
  if (auto res = userCert.getCommonName()) {
    userCn = *res;
  } else {
    logzy::error("Coulnd't get serial number. {}", res.error());
    return false;
  }

  auto waitingServer = state.pendingSessions.find(userCn);
  if (waitingServer == state.pendingSessions.end()) {
    logzy::error("No server is waiting for user with id {} authentication",
                 userCn);
    return false;
  }

  std::string sessionKey;
  sessionKey.reserve(32);

  if (auto bytes = crypto::openssl::generateRandomBytes<32>()) {
    sessionKey.append(std::string_view{bytes->data.begin(), bytes->size()});
  } else {
    logzy::error("Couldn't generate session key. {}", bytes.error());
  }

  logzy::trace("Session key. {}", sessionKey);

  std::string encryptedServerSessionKey;
  std::string encryptedClientSessionKey;

  if (auto encSessKey = crypto::encryptAndEncode(sessionKey, userPublicKey)) {
    encryptedClientSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt clients's session key. {}",
                 encSessKey.error());
    return false;
  }

  if (auto encSessKey = crypto::encryptAndEncode(
          sessionKey, waitingServer->second.servicePublicKey)) {
    encryptedServerSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt server's session key. {}",
                 encSessKey.error());
    return false;
  }

  // Server should notify the client about success and pass the session key
  if (auto server = waitingServer->second.serviceSocket.lock()) {
    if (auto err = server->send(network::Packet{
            .type = network::PacketType::UserAuthOk,
            .payload = {
                {"server_session_key", std::move(encryptedServerSessionKey)},
            }})) {
      logzy::error("Couldn't notify the server that user has "
                   "authenticated with TTP. {}",
                   *err);
      return false;
    }
    // server->close();
  } else {
    logzy::error(
        "Server that was waiting for authentication closed connection.");
    return false;
  }

  if (auto err = client->send(network::Packet{
          .type = network::PacketType::UserAuthOk,
          .payload = {
              {"client_session_key", std::move(encryptedClientSessionKey)},
          }})) {
    logzy::error("Couldn't notify the server that user has "
                 "authenticated with TTP. {}",
                 *err);
    return false;
    client->close();
  }
  return true;
}

auto handlePacket(TtpState &state, network::Packet &packet,
                  std::shared_ptr<network::TcpSocket> &client,
                  std::string_view clientName, const crypto::RsaKeyPair &ttpKey)
    -> bool {

  switch (packet.type) {
  case network::PacketType::CertificateRequest:
    return handleRequestCaCertificate(state, client, ttpKey, packet.payload);
  case network::PacketType::ServerAuthRequest:
    return handleServerAuthRequest(state, client, packet, clientName, ttpKey);
  case network::PacketType::CloseConnection:
    return false;
  case network::PacketType::UserAuthDataSubmit:
    return handleUserAuthDataSubmit(state, client, packet, clientName, ttpKey);
  case network::PacketType::DataResponse:
    [[fallthrough]];
  case network::PacketType::UserAuthOk:
    [[fallthrough]];
  case network::PacketType::UserAuthRedirect:
    [[fallthrough]];
  case network::PacketType::ServiceRequest:
    [[fallthrough]];
  case network::PacketType::ServerAuthOk:
    [[fallthrough]];
  case network::PacketType::DataRequest:
    [[fallthrough]];
  case network::PacketType::__SizeGuard:
    [[fallthrough]];
  case network::PacketType::CertificateResponse:
    logzy::error("Invalid packet received: {}", packet.type);
    return false;
  }
  return true;
}

void handleClientConnection(network::TcpSocket clientSocketRaw,
                            std::string_view clientName, TtpState &state,
                            const crypto::RsaKeyPair &ttpKey) {

  auto clientSocket =
      std::make_shared<network::TcpSocket>(std::move(clientSocketRaw));

  logzy::trace("{} socket fd: {}", clientName, clientSocket->getFd());

  while (true) {
    auto res = clientSocket->receive();
    if (!res) {
      logzy::error("Couldn't receive from client. {}", res.error());
      break;
    }

    if (res->type == network::PacketType::CloseConnection) {
      break;
    }

    logzy::info("Received packet with type: {}", res->type);
    logzy::trace("Payload:\n{}", res->payload.dump());

    auto result = handlePacket(state, *res, clientSocket, clientName, ttpKey);
    if (res->type == network::PacketType::UserAuthDataSubmit && result) {
      logzy::info("TTP's role is finished. cleaning up");
      break;
    }

    logzy::debug("Handled.");
  }
  logzy::trace("Connection with {} ended", clientName);
  logzy::trace("state.pendingSessions.size() = {}",
               state.pendingSessions.size());
  logzy::trace("state.loggedClients.size() = {}", state.loggedClients.size());
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  auto programArgs =
      cli::parseCommandlineArgs<cli::ttp::TtpArguments>(argc, argv);
  if (!programArgs) {
    return programArgs.error();
  }

  TtpState state{};

  crypto::RsaKeyPair ttpRsaKey;
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    ttpRsaKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate TTP's RSA key pair");
    return EXIT_FAILURE;
  }

  if (auto x509Result = crypto::X509Certificate::createSelfSignedCA(
          "Trusted Third Party", ttpRsaKey)) {
    state.ttpCertificate = std::move(*x509Result);
  } else {
    logzy::error("Couldn't create Self signed X509 certificate. {}",
                 x509Result.error());
    return EXIT_FAILURE;
  }

  // udmping cert to file

  if (auto err = state.ttpCertificate.saveToFile(crypto::TTP_CERT_PATH)) {
    logzy::error("{}", *err);
    return EXIT_FAILURE;
  }

  network::TcpServer server;
  if (auto err = server.listen(programArgs->bindPort)) {
    logzy::critical("TTP Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  std::vector<std::jthread> threadHandles;
  int clientCounter = 0;
  while (true) {
    logzy::info("Waiting for connection");

    if (auto client = server.accept()) {

      std::string clientName = "Client " + std::to_string(++clientCounter);
      threadHandles.emplace_back(handleClientConnection, std::move(*client),
                                 clientName, std::ref(state),
                                 std::cref(ttpRsaKey));

    } else {
      logzy::error("Couldn't accept client's connection");
    }
  }

  return 0;
}
