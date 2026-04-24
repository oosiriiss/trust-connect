#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "constants.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
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

struct TtpState {
  crypto::X509Certificate ttpCertificate;
  crypto::RsaKeyPair ttpPrivateKey;

  std::unordered_map<std::string, ClientData, TransparentStringHash,
                     TransparentStringCompare>
      connectedClients;

  std::unordered_map<std::string, protocol::PendingSession,
                     TransparentStringHash, TransparentStringCompare>
      pendingSessions;

  std::mutex mutex;
};

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
    if (protocol::authenticateClient(state.ttpCertificate,
                                     *clientSocket.get())) {

      logzy::trace("Getting client ot finalize");
      ClientData &clientData = state.connectedClients.at(commonName);

      logzy::trace("Getting server for client ot finalize");
      protocol::PendingSession &serverData =
          state.pendingSessions.at(commonName);

      auto serverPublicKey = serverData.serviceCertificate.getPublicKey();
      if (!serverPublicKey) {
        logzy::error("Couldn't extarct public key from cert. {}",
                     serverPublicKey.error());
        return;
      }

      auto clientPublicKey = clientData.info.publicCertificate.getPublicKey();
      if (!clientPublicKey) {
        logzy::error("Couldn't extarct public key from cert. {}",
                     clientPublicKey.error());
        return;
      }

      if (protocol::finalizeHandshake(*clientData.clientSocket.lock().get(),
                                      *serverData.serviceSocket.lock().get(),
                                      *clientPublicKey, *serverPublicKey)) {
        logzy::info("Handshake done.");
        return;
      }
      logzy::error("Couldn't finalize handshake.");
      return;
    }
  } else {
    while (true) {
      auto pendingSession = protocol::authenticateService(
          state.ttpCertificate, clientSocket, clientName);
      if (!pendingSession) {
        logzy::error("err. {}", pendingSession.error());
        return;
      }

      auto clientCn = pendingSession->clientCertificate.getCommonName();

      if (!clientCn) {
        logzy::error("no cn. {}", clientCn.error());
        return;
      }
      {
        std::lock_guard lock{state.mutex};

        state.pendingSessions.emplace(*clientCn, std::move(*pendingSession));
      }

      auto userSocket = state.connectedClients.find(*clientCn);
      if (userSocket == state.connectedClients.end()) {
        logzy::error("no client. ");
        return;
      }

      if (auto sock = userSocket->second.clientSocket.lock()) {
        if (auto err = protocol::notifyUser(*sock.get(), state.ttpPrivateKey,
                                            *clientCn, commonName)) {
          logzy::error("cdnt notfiy client. {}", *err);
          return;
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
