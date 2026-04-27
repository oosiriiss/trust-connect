#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/network.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "ttp/cli.hpp"
#include "utility.hpp"
#include <cstdlib>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

struct ClientData {
  protocol::ClientInfo info;
  std::weak_ptr<network::TcpSocket> clientSocket;
};
struct PendingSession {
  protocol::SessionInfo info;
  std::shared_ptr<network::TcpSocket> serviceSocket;
};

struct TtpState {
  /**
   * Private key and CA certificate
   */
  protocol::TtpData data;

  std::unordered_map<std::string, ClientData, TransparentStringHash,
                     TransparentStringCompare>
      connectedClients;

  std::unordered_map<std::string, PendingSession, TransparentStringHash,
                     TransparentStringCompare>
      pendingSessions;

  std::mutex mutex;
};

#define FAIL_CLIENTSIDE_AUTH(clientSocket, state, clientCommonName, errorMsg,  \
                             errorDetails)                                     \
  do {                                                                         \
    if (clientSocket) {                                                        \
      network::sendError(*(clientSocket), errorMsg);                           \
      logzy::debug("Client notified of error.");                               \
    } else {                                                                   \
      logzy::error(                                                            \
          "Couldn't lock client's socket when failing at client auth.");       \
    }                                                                          \
    logzy::error("{}. {}", errorMsg, errorDetails);                            \
    auto serverSockPtr = (state).pendingSessions.find(clientCommonName);       \
    if (serverSockPtr == (state).pendingSessions.end()) {                      \
      logzy::error("No server connected with client '{}' found.",              \
                   clientCommonName);                                          \
      break;                                                                   \
    }                                                                          \
    auto sock = serverSockPtr->second.serviceSocket;                           \
    network::sendError(*sock.get(), errorMsg);                                 \
    logzy::debug("Notified the server.");                                      \
  } while (0)

void failServersideAuth(network::TcpSocket &serverSocket,
                        std::string_view errorMsg,
                        std::string_view errorDetails) {}

void certificateRequest(std::shared_ptr<network::TcpSocket> &clientSocket,
                        nlohmann::json &payload, protocol::TtpData &ttpData) {

  logzy::info("Recevied certificate request.");

  if (auto err = protocol::handleObtainCertificate(*clientSocket.get(), payload,
                                                   ttpData)) {
    network::sendError(*clientSocket.get(), "Couldn't issue certificate.");
    logzy::critical("Issueing certificate failed. {}", *err);
    return;
  }
  logzy::info("Certificate issued");
}

auto initiateAuth(std::shared_ptr<network::TcpSocket> &clientSocket,
                  nlohmann::json &payload, TtpState &state)
    -> std::optional<std::pair<protocol::ClientRole, std::string>> {
  logzy::info("Initiating authentication");

  auto clientInfo = protocol::handleInitiateAuthentication(*clientSocket.get(),
                                                           payload, state.data);
  if (!clientInfo) {
    network::sendError(*clientSocket,
                       std::format("Initiating authentication failed. {}",
                                   clientInfo.error()));
    logzy::error("Initiating authentication failed");
    return std::nullopt;
  }

  logzy::info("Client {} authenticated.", clientInfo->commonName);

  auto commonName = clientInfo->commonName;

  ClientData data{.info = std::move(clientInfo).value(),
                  .clientSocket = clientSocket};
  logzy::info("Saving connection");
  {
    std::lock_guard lock{state.mutex};
    state.connectedClients.emplace(commonName, std::move(data));
  }
  logzy::info("Connection saved. Ready for authentication");
  return std::optional{std::make_pair(data.info.role, std::move(commonName))};
}

auto waitForSessionData(TtpState &state, const std::string &commonName,
                        network::TcpSocket &clientSocket)
    -> std::optional<std::pair<ClientData, PendingSession>> {

  logzy::info("Waiting for client's correlated server");

  auto startTime = std::chrono::steady_clock::now();
  auto timeout = std::chrono::seconds(5);

  while (std::chrono::steady_clock::now() - startTime < timeout) {
    {
      std::lock_guard lock{state.mutex};

      auto serverDataIter = state.pendingSessions.find(commonName);
      auto clientDataIter = state.connectedClients.find(commonName);

      if (serverDataIter != state.pendingSessions.end() &&
          clientDataIter != state.connectedClients.end()) {

        auto clientNode = state.connectedClients.extract(clientDataIter);
        auto serverNode = state.pendingSessions.extract(serverDataIter);

        return std::make_pair(std::move(clientNode.mapped()),
                              std::move(serverNode.mapped()));
      }
    }

    if (!clientSocket.isHealthy()) {
      logzy::warn("Client disconnected while waiting for server.");
      return std::nullopt;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  return std::nullopt;
}

void requesterAuthenticate(std::shared_ptr<network::TcpSocket> &clientSocket,
                           TtpState &state, const std::string &commonName) {
  logzy::info("Authenticating client.");
  if (auto err =
          protocol::authenticateClient(state.data.certificate, *clientSocket)) {
    FAIL_CLIENTSIDE_AUTH(clientSocket, state, commonName,
                         "Could not authenticate client.", *err);
    return;
  }

  logzy::info("Finding current client's data.");
  auto sessData = waitForSessionData(state, commonName, *clientSocket);
  if (!sessData) {
    FAIL_CLIENTSIDE_AUTH(clientSocket, state, commonName,
                         "Couldn't match client and server", "");
    return;
  }

  logzy::info("Could match client and server");
  auto &[clientData, serverData] = *sessData;

  auto serverPublicKey = serverData.info.serviceCertificate.getPublicKey();
  if (!serverPublicKey) {
    FAIL_CLIENTSIDE_AUTH(clientSocket, state, commonName,
                         "Couldn't parse server's certificate.",
                         serverPublicKey.error());
    return;
  }

  auto clientPublicKey = clientData.info.publicCertificate.getPublicKey();
  if (!clientPublicKey) {
    FAIL_CLIENTSIDE_AUTH(clientSocket, state, commonName,
                         "Couldn't parse client's certificate.",
                         clientPublicKey.error());
    return;
  }

  auto clientSocketShared = clientData.clientSocket.lock();
  if (!clientSocketShared) {
    logzy::error("Couldn't lock client's socket");
    return;
  }

  logzy::info("Finalizing the handshake");
  if (auto err = protocol::finalizeHandshake(
          *clientSocketShared, *serverData.serviceSocket, *clientPublicKey,
          *serverPublicKey)) {

    FAIL_CLIENTSIDE_AUTH(clientSocket, state, commonName,
                         "Couldn't finalize handshake.", *err);
    return;
  }
  logzy::info("Handshake done. Session established.");
}

void serviceAuthenticate(std::shared_ptr<network::TcpSocket> &clientSocket,
                         TtpState &state, std::string_view serviceName) {
  logzy::info("Authenticating service {}", serviceName);

  if (!clientSocket->isHealthy()) {
    logzy::error("Service's socket is in invalid state. Couldn't authenticate");
    return;
  }

  auto sessionInfo = protocol::authenticateService(state.data.certificate,
                                                   *clientSocket.get());
  if (!sessionInfo) {
    network::sendError(*clientSocket.get(), "Could not authenticate server");
    logzy::error("Authentcation of server failed. {}", sessionInfo.error());
    return;
  }

  logzy::info("Service certificates validated.");

  auto clientCn = sessionInfo->clientCertificate.getCommonName();

  if (!clientCn) {
    network::sendError(*clientSocket.get(),
                       "Could not create session - extraction of common "
                       "name from client's certificate failed");
    logzy::error("No common name in client. {}", clientCn.error());
    return;
  }

  {
    std::lock_guard lock{state.mutex};

    PendingSession sess{.info = std::move(sessionInfo).value(),
                        .serviceSocket = clientSocket};

    state.pendingSessions.emplace(*clientCn, std::move(sess));
  }

  logzy::info("Notifying user to proceed with authentication");

  auto userSocket = state.connectedClients.find(*clientCn);
  if (userSocket == state.connectedClients.end()) {
    network::sendError(*clientSocket.get(), "Client is not connected to TTP");
    logzy::error("Client not connected to ttp.");
    return;
  }

  if (auto sock = userSocket->second.clientSocket.lock()) {
    if (auto err = protocol::notifyClient(*sock, state.data.key, *clientCn,
                                          serviceName)) {
      network::sendError(*clientSocket, "Couldn't notify client");
      logzy::error("Couldn't notify client");
      return;
    }
  } else {
    network::sendError(*clientSocket, "Client disconnected");
    logzy::error("Couldn't notify client");
  }

  logzy::info("Service authenticated");
}

void handleClientConnection(network::TcpSocket clientSocketRaw,
                            std::string_view clientName, TtpState &state) {
  auto clientSocket =
      std::make_shared<network::TcpSocket>(std::move(clientSocketRaw));
  logzy::trace("{} socket fd: {}", clientName, clientSocket->getFd());

  std::string commonName;
  protocol::ClientRole role = protocol::ClientRole::Requester;

  while (true) {
    logzy::info(
        "Waiting for client to request certificate or begin authentication");

    auto packet = clientSocket->receive();
    if (!packet) {
      logzy::error("Erro when  receving packet");
      return;
    }
    if (packet->type == network::PacketType::CloseConnection) {
      logzy::warn("Client closed connection");
      return;
    }

    if (packet->type == network::PacketType::CertificateRequest) {
      certificateRequest(clientSocket, packet->payload, state.data);
      // Certificate request temrinates the connection, for verification client
      // should connect second time
      return;
    }
    if (packet->type == network::PacketType::InitiateAuth) {
      auto res = initiateAuth(clientSocket, packet->payload, state);
      if (!res) {
        return;
      }
      role = res->first;
      commonName = std::move(res->second);
      break;
    }
  }

  std::string_view roleString =
      (role == protocol::ClientRole::Requester) ? "Requester" : "Service";
  logzy::info("Authenticating {} with client: '{}'", roleString, commonName);

  switch (role) {
  case protocol::ClientRole::Requester:
    requesterAuthenticate(clientSocket, state, commonName);
    break;
  case protocol::ClientRole::Service:
    serviceAuthenticate(clientSocket, state, commonName);
    break;
  }

  // Cleanup
  switch (role) {
  case protocol::ClientRole::Requester:
    logzy::info("Cleaning client's connection");
    if (state.connectedClients.erase(commonName) == 0) {
      logzy::warn("No connected client with name {} found", commonName);
    }
    logzy::info("Cleaning session");
    if (state.pendingSessions.erase(commonName) == 0) {
      logzy::warn("No pending session for client {} found", commonName);
    }
    break;
  case protocol::ClientRole::Service:
    logzy::info("Cleaning server connection");
    if (state.connectedClients.erase(commonName) == 0) {
      logzy::warn("No connected server with name {} found", commonName);
    }
    break;
  }

  logzy::info("Connection with {} terminated", commonName);
  logzy::debug("Pending session left: {}", state.pendingSessions.size());
  logzy::trace("Connected clients left: {}", state.connectedClients.size());
}

} // namespace

auto main(int argc, const char *const *const argv) -> int {

  auto programArgs =
      cli::parseCommandlineArgs<cli::ttp::TtpArguments>(argc, argv);
  if (!programArgs) {
    return programArgs.error();
  }

  TtpState state{};

  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    state.data.key = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate TTP's RSA key pair");
    return EXIT_FAILURE;
  }

  if (auto x509Result = crypto::X509Certificate::createSelfSignedCA(
          "Trusted Third Party", state.data.key)) {
    state.data.certificate = std::move(*x509Result);
  } else {
    logzy::error("Couldn't create Self signed X509 certificate. {}",
                 x509Result.error());
    return EXIT_FAILURE;
  }

  // udmping cert to file

  if (auto err = state.data.certificate.saveToFile(protocol::TTP_CERT_PATH)) {
    logzy::error("{}", *err);
    return EXIT_FAILURE;
  }

  network::TcpServer server;
  if (auto err = server.listen(programArgs->bindPort)) {
    logzy::critical("TTP Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  int clientCounter = 0;
  while (true) {
    logzy::info("Waiting for connection");

    if (auto client = server.accept()) {

      std::string clientName = "Client " + std::to_string(++clientCounter);
      std::thread(handleClientConnection, std::move(*client), clientName,
                  std::ref(state))
          .detach();

    } else {
      logzy::error("Couldn't accept client's connection");
    }
  }

  return 0;
}
