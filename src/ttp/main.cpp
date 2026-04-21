#include "common/cli.hpp"
#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/vendor/debug_utils.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
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

std::mutex clientRegistryMutex;

struct TtpState {

  crypto::X509Certificate ttpCertificate;
  // TODO :: Client public keys could be deleted, and just sent with every
  // packet needed.
  std::unordered_map<std::string, crypto::RsaKeyPair, TransparentStringHash,
                     TransparentStringCompare>
      clientsPublicKeys;
  std::unordered_map<std::string, std::weak_ptr<network::TcpSocket>,
                     TransparentStringHash, TransparentStringCompare>
      pendingAuthentications;
  std::unordered_map<std::string, std::weak_ptr<network::TcpSocket>,
                     TransparentStringHash, TransparentStringCompare>
      connectedClients;
};

auto handleRequestCaCertificate(TtpState &state,
                                std::shared_ptr<network::TcpSocket> &client,
                                std::string_view clientName,
                                const crypto::RsaKeyPair &ttpKey,
                                nlohmann::json &payload) -> bool {

  logzy::trace("Received TradePublicKeysWithTtp packet from {}", clientName);

  // Verifying the sent data
  if (payload.value("common_name", "").empty()) {
    logzy::error("no common name");
    return false;
  }
  if (payload.value("public_key_pem", "").empty()) {
    logzy::error("no pubkey name");
    return false;
  }
  if (payload.value("signature", "").empty()) {
    logzy::error("no signature name");
    return false;
  }

  auto commonName = payload.value("common_name", std::string_view{""});
  auto publicKeyPem = payload.value("public_key_pem", std::string_view{""});
  std::string signature = payload.value("signature", "");

  // removing signature to verify integrity
  payload.erase("signature");
  crypto::RsaKeyPair clientKeyPair;

  if (auto res = crypto::RsaKeyPair::fromPublicPem(publicKeyPem)) {
    clientKeyPair = std::move(*res);
  } else {
    logzy::error("Couldn't parse client's public key pem. {}", res.error());
    return false;
  }

  logzy::trace("Veirfying signature");
  if (auto res = clientKeyPair.verify(payload.dump(), signature)) {
    if (!res) {
      logzy::error("Verification failed. invalid siganture. {}", signature);
      return false;
    }
  } else {
    logzy::error("Couldnt' verify signautre. error. {}", res.error());
    return false;
  }

  crypto::X509Certificate userCert;
  if (auto certRes =
          state.ttpCertificate.issue(clientKeyPair, clientName, ttpKey)) {
    userCert = std::move(*certRes);
  } else {
    logzy::error("Couldn't create user's certificate.{}", certRes.error());
  }
  logzy::trace("Created user certificate for CN '{}'",
               userCert.getCommonNameSafe());

  logzy::trace("Sending client it's certificate");

  std::string userCertPem;
  std::string ttpCertPem;

  if (auto res = userCert.toPem()) {
    userCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert usercertificate to PEM");
    return false;
  }

  if (auto res = state.ttpCertificate.toPem()) {
    ttpCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert ttp certificate to PEM");
    return false;
  }

  nlohmann::json responsePayload = {
      {"certificate_pem", std::move(userCertPem)},
      {"ttp_ca_certificate_pem", std::move(ttpCertPem)}};

  if (auto signature = ttpKey.sign(responsePayload.dump())) {
    logzy::trace("Signed. {}", *signature);
    responsePayload["signature"] = std::move(*signature);
  } else {
    logzy::error("Couldn't sign the payload. {}", signature.error());
    return false;
  }

  if (auto err = client->send(
          network::Packet{.type = network::PacketType::RegisterResponse,
                          .payload = std::move(payload)})) {
    logzy::error("error while sending. {}", *err);
    return false;
  }

  return true;
}

auto handleRegister(TtpState &state,
                    std::shared_ptr<network::TcpSocket> &client,
                    std::string_view clientName,
                    const crypto::RsaKeyPair &ttpKey,
                    const nlohmann::json &payload) -> bool {

  auto publicName = payload.value("name", std::string_view{""});
  auto encryptedId = payload.value("id", std::string_view{""});
  if (encryptedId.empty()) {
    logzy::error("Payload must include 'id' field");
    return false;
  }

  if (publicName.empty()) {
    logzy::error("Paylod must include unencrypted name");
    return false;
  }

  std::string id;
  logzy::trace("Base64 encoded ID: {}", encryptedId);

  if (auto result = crypto::decodeAndDecrypt(encryptedId, ttpKey)) {
    id = std::move(*result);
  } else {
    logzy::error("Couldnt decrypt {} ID: {}", clientName, result.error());
    return false;
  }
  logzy::trace("Decrypted ID: {}", id);

  logzy::debug("Client '{}' found. Replacing it's clientName key with it's ID",
               clientName);
  auto it = state.clientsPublicKeys.find(clientName);
  if (it == state.clientsPublicKeys.end()) {
    logzy::error("{} tried to register without trading public keys",
                 clientName);
    return false;
  }

  logzy::trace("Generting certificate for user");

  crypto::X509Certificate userCert;
  if (auto certRes =
          state.ttpCertificate.issue(it->second, publicName, ttpKey)) {
    userCert = std::move(*certRes);
  } else {
    logzy::error("Couldn't create user's certificate.{}", certRes.error());
  }
  logzy::trace("Created user certificate for CN '{}'",
               userCert.getCommonNameSafe());

  logzy::trace("Sending client it's certificate");

  std::string userCertPem;
  std::string ttpCertPem;

  if (auto res = userCert.toPem()) {
    userCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert usercertificate to PEM");
    return false;
  }

  if (auto res = state.ttpCertificate.toPem()) {
    ttpCertPem = std::move(*res);
  } else {
    logzy::error("Couldn't convert ttp certificate to PEM");
    return false;
  }

  if (auto err = client->send(network::Packet{
          .type = network::PacketType::RegisterResponse,
          .payload = {{"certificate_pem", std::move(userCertPem)},
                      {"ttp_ca_certificate_pem", std::move(ttpCertPem)}}})) {
    logzy::error("error while sending. {}", *err);
    return false;
  }

  logzy::trace("Saving client socket to map");

  std::string userCertSerial;
  if (auto serial = userCert.getSerialNumberHex()) {
    userCertSerial = std::move(*serial);
  } else {
    logzy::error("Coulnd't  get user's certificate serila number");
    return false;
  }
  {
    std::lock_guard lock{clientRegistryMutex};

    state.connectedClients.insert({userCertSerial, std::weak_ptr{client}});
  }

  logzy::debug("Replacing internal key clientName for it's id");

  {
    std::lock_guard lock{clientRegistryMutex};
    logzy::trace("Finding if node with given id already exists.");
    if (state.clientsPublicKeys.contains(id)) {
      logzy::error("Entry with key {} already exists!", id);
      return false;
    }
    logzy::trace(
        "Key with id is not taken. Extracting the old node with key {}",
        clientName);
    auto node = state.clientsPublicKeys.extract(std::string{clientName});
    if (node.empty()) {
      logzy::error("Couldn't find node with key {}", clientName);
      return false;
    }
    logzy::trace("Extracted. Switching keys from {} to {}", clientName,
                 userCertSerial);
    node.key() = std::move(userCertSerial);
    logzy::trace("Inserting the node back");

    state.clientsPublicKeys.insert(std::move(node));
    logzy::trace("Done.");
  }

  return true;
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
          .type = network::PacketType::ServerAuthOk, .payload = {}})) {
    logzy::error("Couldn't send data to client {}. {}", clientName, *err);
    return false;
  }

  std::string userCertSerial;
  if (auto userCertSer = userCert.getSerialNumberHex()) {
    userCertSerial = std::move(*userCertSer);
  } else {
    logzy::error("Couldn't get userCertSerial. {}", userCertSer.error());
    return false;
  }

  auto iter = state.connectedClients.find(userCertSerial);

  if (iter == state.connectedClients.end()) {
    logzy::error("User not connected");
    return false;
  }

  if (auto clientSocket = iter->second.lock()) {
    if (auto err = clientSocket->send(network::Packet{
            .type = network::PacketType::UserAuthRedirect, .payload = {}})) {
      logzy::error("Couldn't send to client. {}", *err);
    }

  } else {
    logzy::error("Client with id {} disconnected", userCertPem);
    return false;
  }

  logzy::trace("{} Server authenticated", clientName);
  logzy::trace("Server is waiting for client's authentication");

  if (state.pendingAuthentications.contains(userCertPem)) {
    logzy::error("There is already a server waiting for id {}", userCertPem);
    return false;
  }

  {
    std::lock_guard lock{clientRegistryMutex};
    logzy::trace("Inserted waiting for user {}", userCertPem);

    if (auto userCertSerial = userCert.getSerialNumberHex()) {
      state.pendingAuthentications.insert(
          {*userCertSerial, std::weak_ptr{serverSocket}});
    } else {
      logzy::error("Couldn't get user cert serial. {}", userCertSerial.error());
      return false;
    }
  }

  return true;
}

auto encryptClientSessionKey(const TtpState &state,
                             std::string_view userCertSerial,
                             std::string_view sessionKey)
    -> std::expected<std::string, std::string> {

  const crypto::RsaKeyPair *clientPublicKey{nullptr};
  {
    auto iter = state.clientsPublicKeys.find(userCertSerial);
    if (iter == state.clientsPublicKeys.end()) {
      return std::unexpected(std::format(
          "Couldn't find user's id='{}' session key", userCertSerial));
    }
    clientPublicKey = &iter->second;
  }

  std::expected<std::string, std::string> encryptedClientKey{std::string{}};
  if (auto encKey = clientPublicKey->encryptPublic(sessionKey)) {
    *encryptedClientKey = std::move(*encKey);
  } else {
    return encKey;
  }

  if (auto based = crypto::base64Encode(*encryptedClientKey)) {
    *encryptedClientKey = std::move(*based);
  } else {
    return based;
  }

  return encryptedClientKey;
}

auto findServerId(const TtpState &state, std::string_view clientSerial)
    -> std::expected<std::string_view, std::string> {

  std::lock_guard lock{clientRegistryMutex};

  const network::TcpSocket *serverSocket{nullptr};

  // Finding socket that waits for curerent user to authenticate
  for (const auto &[userSerial, sock] : state.pendingAuthentications) {
    if (userSerial == clientSerial) {
      if (auto sockPtr = sock.lock()) {
        serverSocket = sockPtr.get();
      }
    }
  }

  if (serverSocket == nullptr) {
    return std::unexpected("No server is waiting for client with id {} and "
                           "findServerId cannot finish properly.");
  }

  for (const auto &[serverCertSerial, sock] : state.connectedClients) {
    if (auto sockPtr = sock.lock()) {
      if (serverSocket == sockPtr.get()) {
        return serverCertSerial;
      }
    }
  }

  return std::unexpected("Couldn't find server in connected Clients. Maybe "
                         "the server disconnected");
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

  std::string userCertSerial;
  if (auto res = userCert.getSerialNumberHex()) {
    userCertSerial = std::move(*res);
  } else {
    logzy::error("Coulnd't get serial number. {}", res.error());
    return false;
  }

  auto waitingServer = state.pendingAuthentications.find(userCertSerial);
  if (waitingServer == state.pendingAuthentications.end()) {
    logzy::error("No server is waiting for user with id {} authentication",
                 userCertPem);
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

  std::string_view serverId;

  if (auto serverCertSerial = findServerId(state, userCertSerial)) {
    serverId = *serverCertSerial;
  }

  logzy::trace("Server id: {}", serverId);

  std::string encryptedServerSessionKey;
  std::string encryptedClientSessionKey;

  if (auto encSessKey =
          encryptClientSessionKey(state, userCertSerial, sessionKey)) {
    encryptedClientSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt clients's session key. {}",
                 encSessKey.error());
    return false;
  }

  if (auto encSessKey = encryptClientSessionKey(state, serverId, sessionKey)) {
    encryptedServerSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt server's session key. {}",
                 encSessKey.error());
    return false;
  }

  // Server should notify the client about success and pass the session key
  if (auto server = waitingServer->second.lock()) {
    if (auto err = server->send(network::Packet{
            .type = network::PacketType::UserAuthOk,
            .payload = {
                {"server_session_key", std::move(encryptedServerSessionKey)},
                {"client_session_key", std::move(encryptedClientSessionKey)},
            }})) {
      logzy::error("Couldn't notify the server that user has "
                   "authenticated with TTP. {}",
                   *err);
      return false;
    }

    logzy::trace("Closing server and client");
    server->close();
    client->close();

    // logzy::trace("Removing clients public keys");
    // state.clientsPublicKeys.erase(state.clientsPublicKeys.find(userCertSerial));
    // state.clientsPublicKeys.erase(state.clientsPublicKeys.find(server));

    // logzy::trace("Removing connected clients");
    // state.connectedClients.erase(state.connectedClients.find(serverId));
    // state.connectedClients.erase(state.connectedClients.find(userCertPem));

    // logzy::trace("Removing pedning authentications");
    // state.pendingAuthentications.erase(userCertPem);
  } else {
    logzy::error(
        "Server that was waiting for authentication closed connection.");
    return false;
  }

  return true;
}

auto handlePacket(TtpState &state, const network::Packet &packet,
                  std::shared_ptr<network::TcpSocket> &client,
                  std::string_view clientName, const crypto::RsaKeyPair &ttpKey)
    -> bool {

  switch (packet.type) {
  case network::PacketType::TradePublicKeysWithTtpRequest:
    return handleTradePublicKeys(state, client, clientName, ttpKey,
                                 packet.payload);
  case network::PacketType::RegisterRequest:
    return handleRegister(state, client, clientName, ttpKey, packet.payload);
  case network::PacketType::ServerAuthRequest:
    return handleServerAuthRequest(state, client, packet, clientName, ttpKey);
  case network::PacketType::CloseConnection:
    return false;
  case network::PacketType::UserAuthDataSubmit:
    return handleUserAuthDataSubmit(state, client, packet, clientName, ttpKey);
  case network::PacketType::UserAuthOk:
    [[fallthrough]];
  case network::PacketType::UserAuthRedirect:
    [[fallthrough]];
  case network::PacketType::ServiceRequest:
    [[fallthrough]];
  case network::PacketType::ServerAuthOk:
    [[fallthrough]];
  case network::PacketType::__SizeGuard:
    [[fallthrough]];
  case network::PacketType::RegisterResponse:
    [[fallthrough]];
  case network::PacketType::TradePublicKeysWithTtpResponse:
    logzy::error("Invalid packet received: {}", packet.type);
    return false;
    break;
    break;
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
  logzy::trace("state.clientsPublicKeys.size() = {}",
               state.clientsPublicKeys.size());
  logzy::trace("state.pendingAuthentications.size() = {}",
               state.pendingAuthentications.size());
  logzy::trace("state.connectedClients.size() = {}",
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
