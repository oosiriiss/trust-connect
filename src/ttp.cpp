#include "constants.hpp"
#include "cppli/cppli.hpp"
#include "cppli/vendor/debug_utils.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/openssl.hpp"
#include "crypto/rsa.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <chrono>
#include <expected>
#include <memory>
#include <print>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

std::mutex clientRegistryMutex;

enum class OptionKey {
  BindPort,
  Help,
};

struct StringHash {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view str) const -> size_t {
    return std::hash<std::string_view>{}(str);
  }
};

struct StringCompare {
  using is_transparent = void; // NOLINT
  auto operator()(std::string_view left, std::string_view right) const -> bool {
    return left == right;
  }
};

struct TtpState {
  std::unordered_map<std::string, crypto::RsaKeyPair, StringHash, StringCompare>
      clientsPublicKeys;
  std::unordered_map<std::string, std::weak_ptr<network::TcpSocket>, StringHash,
                     StringCompare>
      pendingAuthentications;
  std::unordered_map<std::string, std::weak_ptr<network::TcpSocket>, StringHash,
                     StringCompare>
      connectedClients;
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
  options.addOption(OptionKey::Help,
                    cppli::Option{.firstName = "-h",
                                  .secondName = "--help",
                                  .description = "Displays the help message",
                                  .needsValue = false});

  return options;
}

auto parseCommandlineArgs(std::uint16_t &ctx, int argc,
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
    std::println("{}", cppli::createHelp(options, "ttp"));
    return true;
  }

  if (auto port = result.options.find(OptionKey::BindPort);
      port != result.options.end()) {
    ctx = std::stoi(std::string(port->second.value.value()));
  }

  return false;
}

auto handleTradePublicKeys(TtpState &state,
                           std::shared_ptr<network::TcpSocket> &client,
                           std::string_view clientName,
                           const crypto::RsaKeyPair &ttpKey,
                           const nlohmann::json &payload) -> bool {

  logzy::trace("Received TradePublicKeysWithTtp packet from {}", clientName);
  logzy::trace("Looking for 'public_key_pem' in the payload");

  auto clientPublicKeyPem =
      payload.value("public_key_pem", std::string_view{""});

  if (clientPublicKeyPem.empty()) {
    logzy::error("Client didn't send object with 'public_key_pem' json field "
                 "for TradePublicKeysWithTtp packet. Payload:\n{}",
                 payload.dump());
    return false;
  }

  crypto::RsaKeyPair clientKeyPair;
  logzy::trace("creating RSA Key from {}'s public key PEM", clientName);

  if (auto keyResult = crypto::RsaKeyPair::fromPublicPem(clientPublicKeyPem)) {
    clientKeyPair = std::move(*keyResult);
  } else {
    logzy::error("Couldn't create RSA key from {}'s public Key. key PEM:\n{}",
                 clientName, clientPublicKeyPem);
    return false;
  }

  {
    std::lock_guard lock{clientRegistryMutex};
    DEBUG_ASSERT(!state.clientsPublicKeys.contains(clientName));
    state.clientsPublicKeys.emplace(clientName, std::move(clientKeyPair));
  }

  std::string ttpPublicKeyPem;
  if (auto publicKeyResult = ttpKey.publicKeyPem()) {
    ttpPublicKeyPem = std::move(*publicKeyResult);
  } else {
    logzy::error("Couldn't create PEM from TTP's public key.");
    return false;
  }

  logzy::trace("Sending TTP's public key PEM to the {}.PEM:\n{}", clientName,
               ttpPublicKeyPem);

  if (auto err = client->send(network::Packet{
          .type = network::PacketType::TradePublicKeysWithTtpResponse,
          .payload = {
              {"public_key_pem", std::move(ttpPublicKeyPem)},
          }})) {
    logzy::error("Couldn't send TTP's public key pem to the {}. {}", clientName,
                 *err);
    return false;
  }

  return true;
}

auto handleRegister(TtpState &state,
                    std::shared_ptr<network::TcpSocket> &client,
                    std::string_view clientName,
                    const crypto::RsaKeyPair &ttpKey,
                    const nlohmann::json &payload) -> bool {

  auto encryptedId = payload.value("id", std::string_view{""});
  if (encryptedId.empty()) {
    logzy::error("Payload must include 'id' field");
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

  logzy::trace("Saving client socket to map");
  {
    std::lock_guard lock{clientRegistryMutex};
    state.connectedClients.insert({id, std::weak_ptr{client}});
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
    logzy::trace("Extracted. Switching keys from {} to {}", clientName, id);
    node.key() = std::move(id);
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

  std::string userId = packet.payload.value("user_id", "");
  std::string serverId = packet.payload.value("server_id", "");

  if (userId.empty()) {
    logzy::error("user_id was not provided as payload json key");
    return false;
  }
  if (serverId.empty()) {
    logzy::error("server_id was not provided as payload json key");
    return false;
  }

  if (auto decryptedUser = crypto::decodeAndDecrypt(userId, ttpKey)) {
    userId = std::move(*decryptedUser);
  } else {
    logzy::error("couldnt' decrypt user ID. {}", decryptedUser.error());
    return false;
  }

  logzy::trace("Decrypted user id:{}", userId);

  if (auto decryptedServer = crypto::decodeAndDecrypt(serverId, ttpKey)) {
    serverId = std::move(*decryptedServer);
  } else {
    logzy::error("couldnt' decrypt user ID. {}", decryptedServer.error());
    return false;
  }

  logzy::trace("Decrypted server id:{}", serverId);
  logzy::debug("Checking if users are registered");

  if (!state.clientsPublicKeys.contains(userId)) {
    logzy::error("user with id {} is not registered to the ttp", userId);
    return false;
  }

  if (!state.clientsPublicKeys.contains(serverId)) {
    logzy::error("server with id {} is not registered to the ttp", serverId);
    return false;
  }

  auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();

  std::string message = std::format("TTPChallenge:{}", timestamp);
  std::string messageSignature;
  if (auto signResult = ttpKey.sign(message)) {
    messageSignature = std::move(*signResult);
  } else {
    logzy::error("Couldn't create a signature for TTP message. {}",
                 signResult.error());
    return false;
  }

  if (auto encodeResult = crypto::base64Encode(messageSignature)) {
    messageSignature = std::move(*encodeResult);
  } else {
    logzy::error("Couldn't base64 encode the message {}", messageSignature);
    return false;
  }

  if (auto err = serverSocket->send(network::Packet{
          .type = network::PacketType::ServerAuthOk,
          .payload = {{"message", std::move(message)},
                      {"signature", std::move(messageSignature)}}})) {
    logzy::error("Couldn't send data to client {}. {}", clientName, *err);
    return false;
  }

  auto iter = state.connectedClients.find(userId);
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
    logzy::error("Client with id {} disconnected", userId);
    return false;
  }

  logzy::trace("{} Server authenticated", clientName);
  logzy::trace("Server is waiting for client's authentication");

  if (state.pendingAuthentications.contains(userId)) {
    logzy::error("There is already a server waiting for id {}", userId);
    return false;
  }

  {
    std::lock_guard lock{clientRegistryMutex};
    logzy::trace("Inserted waiting for user {}", userId);
    state.pendingAuthentications.insert({userId, std::weak_ptr{serverSocket}});
  }

  return true;
}

auto encryptClientSessionKey(const TtpState &state, std::string_view clientId,
                             std::string_view sessionKey)
    -> std::expected<std::string, std::string> {

  const crypto::RsaKeyPair *clientPublicKey{nullptr};
  {
    auto iter = state.clientsPublicKeys.find(clientId);
    if (iter == state.clientsPublicKeys.end()) {
      return std::unexpected(
          std::format("Couldn't find user's id='{}' session key", clientId));
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

auto findServerId(const TtpState &state, std::string_view clientId)
    -> std::expected<std::string_view, std::string> {

  std::lock_guard lock{clientRegistryMutex};

  const network::TcpSocket *serverSocket{nullptr};

  // Finding socket that waits for curerent user to authenticate
  for (const auto &[userId, sock] : state.pendingAuthentications) {
    if (userId == clientId) {
      if (auto sockPtr = sock.lock()) {
        serverSocket = sockPtr.get();
      }
    }
  }

  if (serverSocket == nullptr) {
    return std::unexpected("No server is waiting for client with id {} and "
                           "findServerId cannot finish properly.");
  }

  for (const auto &[id, sock] : state.connectedClients) {
    if (auto sockPtr = sock.lock()) {
      if (serverSocket == sockPtr.get()) {
        return id;
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

  std::string id = packet.payload.value("id", "");
  if (id.empty()) {
    logzy::error("User {} didn't send id key", clientName);
    return false;
  }

  if (auto idResult = crypto::decodeAndDecrypt(id, ttpKey)) {
    id = std::move(*idResult);
  } else {
    logzy::error("Couldn't decrypt user's {} id {}. {}", clientName, id,
                 idResult.error());
    return false;
  }

  if (!state.clientsPublicKeys.contains(id)) {
    logzy::error("User with id: {} is not registered to the TTP", id);
    return false;
  }

  auto waitingServer = state.pendingAuthentications.find(id);
  if (waitingServer == state.pendingAuthentications.end()) {
    logzy::error("No server is waiting for user with id {} authentication", id);
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

  if (auto serverIdResult = findServerId(state, id)) {
    serverId = *serverIdResult;
  }

  logzy::trace("Server id: {}", serverId);

  std::string encryptedServerSessionKey;
  std::string encryptedClientSessionKey;

  if (auto encSessKey = encryptClientSessionKey(state, id, sessionKey)) {
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

    logzy::trace("Removing clients public keys");
    state.clientsPublicKeys.erase(state.clientsPublicKeys.find(serverId));
    state.clientsPublicKeys.erase(state.clientsPublicKeys.find(id));

    logzy::trace("Removing connected clients");
    state.connectedClients.erase(state.connectedClients.find(serverId));
    state.connectedClients.erase(state.connectedClients.find(id));

    logzy::trace("Removing pedning authentications");
    state.pendingAuthentications.erase(id);
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

  std::uint16_t bindPort = network::DEFAULT_TTP_PORT;

  if (parseCommandlineArgs(bindPort, argc, argv)) {
    return EXIT_SUCCESS;
  }

  crypto::RsaKeyPair ttpRsaKey;
  if (auto keyResult = crypto::RsaKeyPair::generate()) {
    ttpRsaKey = std::move(*keyResult);
  } else {
    logzy::critical("Couldn't generate TTP's RSA key pair");
  }

  network::TcpServer server;
  if (auto err = server.listen(bindPort)) {
    logzy::critical("TTP Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  TtpState state{};
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
