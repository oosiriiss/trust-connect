#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "constants.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/network.hpp"
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

struct ClientData {
  protocol::ClientInfo info;
  std::weak_ptr<network::TcpSocket> clientSocket;
};
struct PendingSession {
  protocol::SessionInfo info;
  std::weak_ptr<network::TcpSocket> serviceSocket;
};

struct TtpState {
  crypto::X509Certificate ttpCertificate;
  crypto::RsaKeyPair ttpPrivateKey;

  std::unordered_map<std::string, ClientData, TransparentStringHash,
                     TransparentStringCompare>
      connectedClients;

  std::unordered_map<std::string, PendingSession, TransparentStringHash,
                     TransparentStringCompare>
      pendingSessions;

  std::mutex mutex;
};

void failClientsideAuth(network::TcpSocket &clientSocket, TtpState &state,
                        std::string_view clientCommonName,
                        std::string_view errorMsg,
                        std::string_view errorDetails) {
  logzy::error("{}. {}", errorMsg, errorDetails);

  network::sendError(clientSocket, errorMsg);
  logzy::debug("Client notified of error.");

  auto serverSockPtr = state.pendingSessions.find(clientCommonName);
  if (serverSockPtr == state.pendingSessions.end()) {
    logzy::error("No server connected with client '{}' found.",
                 clientCommonName);
    return;
  }

  if (auto sock = serverSockPtr->second.serviceSocket.lock()) {
    network::sendError(*sock.get(), errorMsg);
  }

  logzy::debug("Notified the server.");
}

void failServersideAuth(network::TcpSocket &serverSocket,
                        std::string_view errorMsg,
                        std::string_view errorDetails) {}

void handleClientConnection(network::TcpSocket clientSocketRaw,
                            std::string_view clientName, TtpState &state) {
  auto clientSocket =
      std::make_shared<network::TcpSocket>(std::move(clientSocketRaw));
  logzy::trace("{} socket fd: {}", clientName, clientSocket->getFd());

  std::string commonName;
  protocol::ClientRole role = protocol::ClientRole::Requester;

  if (auto info = protocol::handleRegister(
          state.ttpCertificate, *clientSocket.get(), state.ttpPrivateKey)) {

    ClientData data{.info = std::move(*info),
                    .clientSocket = std::weak_ptr{clientSocket}};
    commonName = data.info.commonName;
    role = data.info.role;
    state.connectedClients.emplace(data.info.commonName, std::move(data));
  } else {
    logzy::error("Couldn't register with ttp");
    return;
  }

  if (role == protocol::ClientRole::Requester) {
    if (auto err = protocol::authenticateClient(state.ttpCertificate,
                                                *clientSocket.get())) {
      failClientsideAuth(*clientSocket.get(), state, commonName,
                         "Could not authenticate client.", *err);
      return;
    }

    logzy::trace("Getting client ot finalize");
    ClientData &clientData = state.connectedClients.at(commonName);

    logzy::trace("Getting server for client ot finalize");
    PendingSession &serverData = state.pendingSessions.at(commonName);

    auto serverPublicKey = serverData.info.serviceCertificate.getPublicKey();
    if (!serverPublicKey) {
      failClientsideAuth(*clientSocket.get(), state, commonName,
                         "Couldn't parse server's certificate.",
                         serverPublicKey.error());
      return;
    }

    auto clientPublicKey = clientData.info.publicCertificate.getPublicKey();
    if (!clientPublicKey) {
      failClientsideAuth(*clientSocket.get(), state, commonName,
                         "Couldn't parse client's certificate.",
                         clientPublicKey.error());
      return;
    }

    if (auto err =
            protocol::finalizeHandshake(*clientData.clientSocket.lock().get(),
                                        *serverData.serviceSocket.lock().get(),
                                        *clientPublicKey, *serverPublicKey)) {

      failClientsideAuth(*clientSocket.get(), state, commonName,
                         "Couldn't finalize handshake.", *err);
      return;
    }
    logzy::info("Handshake done.");
  } else {
    while (true) {

      if (!clientSocket->isHealthy()) {
        break;
      }

      auto sessionInfo = protocol::authenticateService(state.ttpCertificate,
                                                       *clientSocket.get());
      if (!sessionInfo) {
        network::sendError(*clientSocket.get(),
                           "Could not authenticate server");
        logzy::error("Authentcation of server failed. {}", sessionInfo.error());
        continue;
      }

      auto clientCn = sessionInfo->clientCertificate.getCommonName();

      if (!clientCn) {
        network::sendError(*clientSocket.get(),
                           "Could not create session - extraction of common "
                           "name from client's certificate failed");
        logzy::error("No common name in client. {}", clientCn.error());
        continue;
      }

      {
        std::lock_guard lock{state.mutex};

        PendingSession sess{.info = std::move(sessionInfo).value(),
                            .serviceSocket = std::weak_ptr{clientSocket}};

        state.pendingSessions.emplace(*clientCn, std::move(sess));
      }

      auto userSocket = state.connectedClients.find(*clientCn);
      if (userSocket == state.connectedClients.end()) {
        network::sendError(*clientSocket.get(),
                           "Client is not connected to TTP");
        logzy::error("Client not connected to ttp.");
        continue;
      }

      if (auto sock = userSocket->second.clientSocket.lock()) {
        if (auto err = protocol::notifyClient(*sock.get(), state.ttpPrivateKey,
                                              *clientCn, commonName)) {
          network::sendError(*clientSocket.get(), "Couldn't notify client");
          logzy::error("Couldn't notify client");
          continue;
        }
      }
    }
  }

  logzy::trace("Connection with {} ended", clientName);
  logzy::trace("state.pendingSessions.size() = {}",
               state.pendingSessions.size());
  logzy::trace("state.loggedClients.size() = {}",
               state.connectedClients.size());
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
    state.ttpPrivateKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate TTP's RSA key pair");
    return EXIT_FAILURE;
  }

  if (auto x509Result = crypto::X509Certificate::createSelfSignedCA(
          "Trusted Third Party", state.ttpPrivateKey)) {
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
                                 clientName, std::ref(state));

    } else {
      logzy::error("Couldn't accept client's connection");
    }
  }

  return 0;
}
