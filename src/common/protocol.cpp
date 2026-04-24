#include "protocol.hpp"
#include "crypto/aes.hpp"
#include "crypto/crypto.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/network.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <expected>
#include <optional>
#include <utility>

namespace protocol {

// auto TtpData::fromFile(std::string_view path);

auto SessionTicket::toJson() -> nlohmann::json {
  return nlohmann::json{{keys::SessionId, sessionId},
                        {keys::ClientCommonName, clientCn},
                        {keys::ServerCommonName, serverCn}};
}

auto SessionTicket::fromJson(const nlohmann::json &json)
    -> std::expected<SessionTicket, std::string> {
  std::expected<SessionTicket, std::string> ticket{SessionTicket{}};
  logzy::debug("loading session ticket from json.");

  const auto sessionId = json.value(keys::SessionId, std ::string_view{""});
  const auto clientCn =
      json.value(keys::ClientCommonName, std ::string_view{""});
  const auto serverCn =
      json.value(keys::ServerCommonName, std ::string_view{""});

  if (sessionId.empty()) {
    return std::unexpected("session_id was empty");
  }
  if (clientCn.empty()) {
    return std::unexpected("client_cn was empty");
  }
  if (serverCn.empty()) {
    return std::unexpected("server_cn was empty");
  }

  ticket->sessionId = sessionId;
  ticket->clientCn = clientCn;
  ticket->serverCn = serverCn;

  logzy::debug("Session loaded.");
  return ticket;
}

static inline auto receiveSessionKey(network::TcpSocket &ttpSocket,
                                     const crypto::RsaKeyPair &privateKey)
    -> std::expected<crypto::Aes256, std::string> {
  logzy::debug("Waiting for client's  verification to finish");

  auto payload =
      network::expectPacket(ttpSocket, network::PacketType::UserAuthOk);

  if (!payload) {
    return std::unexpected(std::move(payload.error()));
  }

  logzy::debug("Checking received json's fields.");
  const auto sessionKey = payload->value("session_key", std::string_view{""});

  if (sessionKey.empty()) {
    return std::unexpected{"Server didn't send AES 256 GCM session key with "
                           "UserAuthOk packet."};
  }

  auto keyString = crypto::decodeAndDecrypt(sessionKey, privateKey);
  if (!keyString) {
    return std::unexpected{std::format(
        "Couldn't decode and decrypt aes key. {}", keyString.error())};
  }
  logzy::debug("Session key decrypted and decoded. Parsing it");
  auto aes = crypto::Aes256::fromKey(*keyString);
  if (!aes) {
    return std::unexpected{
        std::format("Couldn't create AES 256 GCM from key '{}'. {}", *keyString,
                    aes.error())};
  }
  logzy::debug("Session key successfully parsed.");

  return aes;
}

auto verifyAndParseSessionTicket(nlohmann::json &payload,
                                 const crypto::RsaKeyPair &ttpKey)
    -> std::expected<SessionTicket, std::string> {

  if (auto res = crypto::verifyPayload(ttpKey, payload)) {
    if (!*res) {
      return std::unexpected(
          "Couldn't verify the payload's signature. It was invalid");
    }
  } else {
    return std::unexpected(std::format(
        "Couldn't verify the payload's signature. Error {}", res.error()));
  }

  return SessionTicket::fromJson(payload);
}

auto clientHandshake(network::TcpSocket &serverSocket,
                     network::TcpSocket &ttpSocket,
                     crypto::X509Certificate &clientCert,
                     const crypto::RsaKeyPair &clientKey,
                     const crypto::RsaKeyPair &ttpKey)
    -> std::expected<crypto::Aes256, std::string> {

  logzy::debug("Requesting service from server");
  logzy::trace("Encrypting user id with ttp's public key");

  auto userCertPem = clientCert.toPem();
  if (!userCertPem) {
    return std::unexpected{
        std::format("Couldn't convert client's certificate to PEM format. {}",
                    userCertPem.error())};
  }

  // TODO :: Service request should contian a nonce or stiemstamp signde with
  // private key to prevent reply attacks

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::ServiceRequest,
                          .payload = {
                              {keys::UserCertPem, std::move(*userCertPem)},
                          }})) {

    return std::unexpected{std::format("ServiceRequest failed. {}", *err)};
  }

  logzy::debug("Waiting for ServerAuthOk from TTP.");

  auto payload =
      network::expectPacket(ttpSocket, network::PacketType::ServerAuthOk);
  if (!payload) {
    return std::unexpected(std::move(payload.error()));
  }

  logzy::debug("Parsing session ticket.");

  auto sessionTicket = verifyAndParseSessionTicket(*payload, ttpKey);
  if (!sessionTicket) {
    return std::unexpected(std::format(
        "There was an error with session ticket. {}", sessionTicket.error()));
  }
  logzy::trace("Session: {}", sessionTicket->sessionId);
  // User  auth redirect happens here

  logzy::debug("Waiting for UserAuthRedirect packet");
  if (auto res = network::expectPacket(ttpSocket,
                                       network::PacketType::UserAuthRedirect);
      !res) {
    return std::unexpected(std::move(res.error()));
  }

  logzy::debug("Sending user auth data to TTP");
  if (auto err = ttpSocket.send(
          network::Packet{.type = network::PacketType::UserAuthDataSubmit,
                          .payload = {
                              {keys::UserCertPem, *userCertPem},
                              {keys::SessionId, sessionTicket->sessionId},
                          }})) {
    return std::unexpected{
        std::format("Couldn't send user auth data to TTP. {}", *err)};
  }

  logzy::debug("User auth data sent.");
  return receiveSessionKey(ttpSocket, clientKey);
}

auto serverHandshake(network::TcpSocket &clientSocket,
                     network::TcpSocket &ttpSocket,
                     const nlohmann::json &requestPayload,
                     const crypto::Hash32 &serverID,
                     const crypto::RsaKeyPair &serverKey,
                     const crypto::RsaKeyPair &ttpKey,
                     const crypto::X509Certificate &serverCertificate)
    -> std::expected<crypto::Aes256, std::string> {
  // Service request sent
  logzy::debug("Server handshake begin...");

  const auto userCertPem =
      requestPayload.value("user_cert_pem", std::string_view{""});
  if (userCertPem.empty()) {
    return std::unexpected{
        "Client didnt supply 'user_cert_pem' key with ServiceRequest "};
  }

  logzy::trace("user certificate PEM:\n{}", userCertPem);

  auto serverCertPem = serverCertificate.toPem();
  if (!serverCertPem) {
    return std::unexpected{
        std::format("Couldn't convert server's certifiacte to PEM. {}",
                    serverCertPem.error())};
  }

  if (auto err = ttpSocket.send(network::Packet{
          .type = network::PacketType::ServerAuthRequest,
          .payload =
              {
                  {keys::UserCertPem, userCertPem},
                  {keys::ServerCertPem, *serverCertPem},
              },
      })) {
    return std::unexpected{
        std::format("Couldn't send verification data to TTP server. {}", *err)};
  }

  logzy::debug("Waiting from TTP's validation of user and self.");

  if (auto res =
          network::expectPacket(ttpSocket, network::PacketType::ServerAuthOk);
      !res) {
    return std::unexpected(std::move(res).error());
  }
  logzy::debug(
      "Validated. Waiting for client to finish authentication with TTP.");

  return receiveSessionKey(ttpSocket, serverKey);
}

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool {

  logzy::info("Connecting to {} at {}:{}", targetName, host, port);

  auto socketRes = network::TcpSocket::connect(host, port);
  if (!socketRes) {

    logzy::error("Couldn't connect to {}. Reason: {}", targetName,
                 socketRes.error());
    // As of now failure in connection is just
    // ommited, and is not considered and error
    return true;
  }

  logzy::info("successfully connected to: {}", targetName);
  socket = std::move(*socketRes);
  return true;
}

static inline auto
parseAndVerifyCertificate(std::string_view certificatePem,
                          const crypto::X509Certificate &ttpCertificate)
    -> std::expected<crypto::X509Certificate, std::string> {
  logzy::debug("Parsig the certificate.");

  auto certificate = crypto::X509Certificate::fromPem(certificatePem);
  if (!certificate) {
    return std::unexpected{
        std::format("Couldn't read  certificate from PEM. Error {}.\nPEM:\n{}",
                    certificate.error(), certificatePem)};
  }

  logzy::debug("Certificate parsed, validating.");
  if (auto result = ttpCertificate.verify(*certificate)) {
    if (!*result) {
      return std::unexpected{"User sent and invalid certificate"};
    }
    logzy::debug("User's ceritficate positively verified.");
  } else {
    return std::unexpected{
        std::format("Error occurred when validating user's certificate. {}",
                    result.error())};
  }

  logzy::debug("Ceritficate positively verified.");
  return certificate;
}

[[nodiscard]] auto registerWithTtp(network::TcpSocket &socket,
                                   const crypto::Hash32 &id,
                                   const crypto::RsaKeyPair &clientKey,
                                   const TtpData &ttpData, ClientRole role)
    -> std::expected<crypto::X509Certificate, std::string> {

  std::string publicKeyPem;
  if (auto res = clientKey.publicKeyPem()) {
    publicKeyPem = std::move(*res);
  } else {
    return std::unexpected{
        std::format("Couldnt' create public key pem. {}", res.error())};
  }

  std::string encryptedId;
  if (auto res =
          crypto::encryptAndEncode(crypto::hashToHex(id), ttpData.publicKey)) {
    encryptedId = std::move(*res);
  } else {
    return std::unexpected{std::format("Couldn't encrypt id. {}", res.error())};
  }

  logzy::info("Registering with TTP");
  logzy::trace("Requesting TTP's certificate.");
  if (auto err = socket.send({.type = network::PacketType::CertificateRequest,
                              .payload = {
                                  {keys::Id, encryptedId},
                                  {keys::PublicKeyPem, std::move(publicKeyPem)},
                                  {keys::Role, std::to_underlying(role)},
                              }})) {
    return std::unexpected{
        std::format("Couldn't send packet to TTP: {}", *err)};
  }

  logzy::trace("Requested. Waiting for response");

  auto payload =
      network::expectPacket(socket, network::PacketType::CertificateResponse);
  if (!payload) {
    return std::unexpected{std::move(payload).error()};
  }

  auto receivedCertPem =
      payload->value(keys::CertificatePem, std::string_view{""});

  if (receivedCertPem.empty()) {
    return std::unexpected{"No certificate in response."};
  }

  logzy::debug("Received certificate from TTP.");
  return parseAndVerifyCertificate(receivedCertPem, ttpData.certificate);
}

namespace {
struct RegisterPayload {
  std::string clientId;
  ClientRole role;
  crypto::RsaKeyPair publicKey;
};

auto parseRegisterPayload(const nlohmann::json &payload,
                          const crypto::RsaKeyPair &ttpKey)
    -> std::expected<RegisterPayload, std::string> {
  logzy::debug("Parsing register payload.");
  std::expected<RegisterPayload, std::string> parsed{RegisterPayload{}};

  const auto publicKeyPem =
      payload.value(keys::PublicKeyPem, std::string_view{""});
  const auto roleRaw = payload.value(keys::Role, -1);
  const auto clientID = payload.value(keys::Id, std::string_view{""});

  if (clientID.empty()) {
    return std::unexpected(std::format("no {} found", keys::Id));
  }

  if (auto res = crypto::decodeAndDecrypt(clientID, ttpKey)) {
    parsed->clientId = std::move(*res);
  } else {
    return std::unexpected(
        std::format("Couldn't decrypt user's id. {}", res.error()));
  }

  ClientRole role = ClientRole::Requester;
  if (roleRaw == -1) {
    logzy::warn("Role is empty. defaulting to ClientRole::Requester");
  } else {
    if (roleRaw != std::to_underlying(ClientRole::Requester) &&
        roleRaw != std::to_underlying(ClientRole::Service)) {
      return std::unexpected(std::format("Invalid role. {}", roleRaw));
    }
    parsed->role = static_cast<ClientRole>(roleRaw);
  }

  if (auto res = crypto::RsaKeyPair::fromPublicPem(publicKeyPem)) {
    parsed->publicKey = std::move(*res);
  } else {
    return std::unexpected(
        std::format("Couldn't parse client's public key pem. {}", res.error()));
  }

  return parsed;
}

auto extractClientInfo(crypto::X509Certificate &&clientCertificate,
                       ClientRole role)
    -> std::expected<ClientInfo, std::string> {
  logzy::debug("Extracting Common name from client's certificate.");

  auto userCertCn = clientCertificate.getCommonName();
  if (!userCertCn) {
    return std::unexpected(
        std::format("Couldn't get common name from client's certificate. {}",
                    userCertCn.error()));
  }
  logzy::trace("Extracted: {}", *userCertCn);

  return std::expected<ClientInfo, std::string>{
      ClientInfo{.commonName = std::move(*userCertCn),
                 .publicCertificate = std::move(clientCertificate),
                 .role = role}};
}
} // namespace

auto handleRegister(crypto::X509Certificate &ttpCertificate,
                    network::TcpSocket &client,
                    const crypto::RsaKeyPair &ttpKey)
    -> std::expected<ClientInfo, std::string> {
  logzy::debug("Registering user. Waiting for certificate request packet");

  auto parsedPayload =
      network::expectPacket(client, network::PacketType::CertificateRequest)
          .and_then([&ttpKey](const nlohmann::json &payload)
                        -> std::expected<RegisterPayload, std::string> {
            return parseRegisterPayload(payload, ttpKey);
          });
  if (!parsedPayload) {
    return std::unexpected(std::format("Couldn't parse register payload. {}",
                                       parsedPayload.error()));
  }

  auto clientCertificate = ttpCertificate.issue(
      parsedPayload->publicKey, parsedPayload->clientId, ttpKey);
  if (!clientCertificate) {

    return std::unexpected(std::format("Couldn't create user's certificate.{}",
                                       clientCertificate.error()));
  }

  logzy::trace("Created user certificate for CN '{}'",
               clientCertificate->getCommonNameSafe());

  logzy::trace("Sending client it's certificate");

  auto userCertPem = clientCertificate->toPem();
  if (!userCertPem) {
    return std::unexpected(std::format(
        "Couldn't convert usercertificate to PEM. {}", userCertPem.error()));
  }

  if (auto err = client.send(network::Packet{
          .type = network::PacketType::CertificateResponse,
          .payload = {
              {keys::CertificatePem, std::move(userCertPem).value()},
          }})) {
    return std::unexpected(
        std::format("Error while sending CertificateResponse. {}", *err));
  }

  return extractClientInfo(std::move(clientCertificate).value(),
                           parsedPayload->role);
}

namespace {
inline auto generateSessionKey() -> std::expected<std::string, std::string> {

  return crypto::openssl::generateRandomBytes<32>()
      .transform([](const auto &bytes) -> std::string {
        return std::string{std::string_view{bytes.data.begin(), bytes.size()}};
      })
      .transform_error([](const auto &errMessage) -> auto {
        return std::format(
            "Couldn't generate random bytes for the session key. {}",
            errMessage);
      });
}

inline auto sendSessionKey(network::TcpSocket &target,
                           const crypto::RsaKeyPair &targetPublicKey,
                           std::string_view sessionKey)
    -> std::optional<std::string> {
  logzy::debug("Sending session key.");

  auto encryptedSessionKey =
      crypto::encryptAndEncode(sessionKey, targetPublicKey);
  if (!encryptedSessionKey) {
    return std::optional{
        std::format("Encrypting and encoding the session key failed. {}",
                    encryptedSessionKey.error())};
  }
  logzy::debug("Encrypted and encoded the session key. Sending it.");
  auto packet =
      network::Packet{.type = network::PacketType::UserAuthOk,
                      .payload = {
                          {keys::SessionKey, std::move(*encryptedSessionKey)},
                      }};
  if (auto err = target.send(packet)) {
    return std::optional{std::format("Couldn't send the data. {}", *err)};
  }

  logzy::debug("Session key sent.");
  return std::nullopt;
}
} // namespace

auto finalizeHandshake(network::TcpSocket &clientSocket,
                       network::TcpSocket &serverSocket,
                       const crypto::RsaKeyPair &clientPublicKey,
                       const crypto::RsaKeyPair &serverPublicKey)
    -> std::optional<std::string> {

  logzy::debug("Generating session key.");

  auto sessionKey = generateSessionKey();
  if (!sessionKey) {
    return std::optional{
        std::format("Couldn't generate session key. {}", sessionKey.error())};
  }
  logzy::debug("Session key generated. Sending them to the client and server.");
  logzy::trace("Session key bytes (first 4 bytes): '{}'",
               sessionKey->substr(0, 4));

  if (auto err = sendSessionKey(clientSocket, clientPublicKey, *sessionKey)) {
    return std::optional{
        std::format("Couldn't send the session key to the client. {}", *err)};
  }

  if (auto err = sendSessionKey(serverSocket, serverPublicKey, *sessionKey)) {
    return std::optional{
        std::format("Couldn't send the session key to the server. {}", *err)};
  }

  logzy::debug("Session keys distributed.");

  return std::nullopt;
}

auto authenticateClient(crypto::X509Certificate &ttpCertificate,
                        network::TcpSocket &clientSocket)
    -> std::optional<std::string> {
  logzy::debug("Authenticating client.");

  auto payload = network::expectPacket(clientSocket,
                                       network::PacketType::UserAuthDataSubmit);
  if (!payload) {
    return std::optional{std::move(payload.error())};
  }
  logzy::debug("Received UserAuthDataSubmit packet");

  std::string userCertPem = payload->value(keys::UserCertPem, "");
  if (userCertPem.empty()) {
    return std::optional{std::format("The client didn't include '{}'in the "
                                     "paylod JSON object.",
                                     keys::UserCertPem)};
  }

  logzy::debug("Parsing the PEM format certificate");

  auto result = parseAndVerifyCertificate(userCertPem, ttpCertificate);
  if (!result) {
    return std::optional{std::move(result.error())};
  }

  logzy::debug("Client authentication success.");
  return std::nullopt;
}

namespace {

struct ServerAuthPayload {
  std::string userCertPem;
  std::string serverCertPem;
};

auto parseServerAuthPayload(const nlohmann::json &payload)
    -> std::expected<ServerAuthPayload, std::string> {
  logzy::debug("Parsing ServerAuthRequest payload");

  std::string userCertPem = payload.value(keys::UserCertPem, "");
  std::string serverCertPem = payload.value(keys::ServerCertPem, "");

  if (userCertPem.empty()) {
    return std::unexpected(std::format(
        "{} was not provided as payload json key", keys::UserCertPem));
  }
  if (serverCertPem.empty()) {
    return std::unexpected(std::format(
        "{} was not provided as payload json key", keys::ServerCertPem));
  }
  std::expected<ServerAuthPayload, std::string> parsed{ServerAuthPayload{}};

  return std::expected<ServerAuthPayload, std::string>{ServerAuthPayload{
      .userCertPem = std::move(userCertPem),
      .serverCertPem = std::move(serverCertPem),
  }};
}

} // namespace

auto authenticateService(const crypto::X509Certificate &ttpCertificate,
                         network::TcpSocket &serverSocket)
    -> std::expected<SessionInfo, std::string> {

  logzy::debug("Authenticating server");
  auto payload =
      network::expectPacket(serverSocket,
                            network::PacketType::ServerAuthRequest)
          .and_then([](const nlohmann::json &payload)
                        -> std::expected<ServerAuthPayload, std::string> {
            return parseServerAuthPayload(payload);
          });
  if (!payload) {
    return std::unexpected{std::move(payload).error()};
  }

  logzy::debug("Checking the payload's fields.");

  auto userCert =
      parseAndVerifyCertificate(payload->userCertPem, ttpCertificate);
  if (!userCert) {
    return std::unexpected(std::format(
        "There was an error with client's certificate. {}", userCert.error()));
  }
  logzy::trace("client's certificate common name: '{}'",
               userCert->getCommonNameSafe());

  auto serverCert =
      parseAndVerifyCertificate(payload->serverCertPem, ttpCertificate);
  if (!serverCert) {
    return std::unexpected(
        std::format("There was an error with server's certificate. {}",
                    serverCert.error()));
  }

  logzy::trace("Server's certificate common name: '{}'",
               serverCert->getCommonNameSafe());

  logzy::debug("Server authenticated.");
  if (auto err = serverSocket.send(network::Packet{
          .type = network::PacketType::ServerAuthOk,
          .payload = {}, // Serer gets empty payload
      })) {
    return std::unexpected(
        std::format("Couldn't send data to server. {}", *err));
  }

  return std::expected<SessionInfo, std::string>{
      SessionInfo{.serviceCertificate = std::move(*serverCert),
                  .clientCertificate = std::move(*userCert)}};
}

static auto createSessionTicketPayload(std::string_view clientCn,
                                       std::string_view serverCn,
                                       const crypto::RsaKeyPair &ttpKey)
    -> std::expected<nlohmann::json, std::string> {

  SessionTicket ticket{.clientCn = std::string{clientCn},
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

auto notifyClient(network::TcpSocket &clientSocket,
                  const crypto::RsaKeyPair &ttpPrivateKey,
                  std::string_view clientCommonName,
                  std::string_view serverCommonName)
    -> std::optional<std::string> {
  logzy::debug("Notifying user");

  auto serverAuthOkPayload = createSessionTicketPayload(
      clientCommonName, serverCommonName, ttpPrivateKey);
  if (!serverAuthOkPayload) {
    return std::optional(std::format("Couldn't create ServerAuthOk payload. {}",
                                     serverAuthOkPayload.error()));
  }

  if (auto err = clientSocket.send(
          network::Packet{.type = network::PacketType::ServerAuthOk,
                          .payload = std::move(*serverAuthOkPayload)})) {
    return std::optional(std::format("Couldn't send to client. {}", *err));
  }
  logzy::debug("Client notified with session ticket. Redirecting user to "
               "authentication.");

  if (auto err = clientSocket.send(network::Packet{
          .type = network::PacketType::UserAuthRedirect, .payload = {}})) {
    return std::optional(std::format("Couldn't send to client. {}", *err));
  }

  logzy::debug("User redirected.");
  return std::nullopt;
}

} // namespace protocol
