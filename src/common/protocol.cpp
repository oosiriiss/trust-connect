#include "protocol.hpp"
#include "crypto/aes.hpp"
#include "crypto/crypto.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <expected>

namespace protocol {

// auto TtpData::fromFile(std::string_view path);

auto SessionTicket::toJson() -> nlohmann::json {
  return nlohmann::json{{"session_id", sessionId},
                        {"client_cn", clientCn},
                        {"server_cn", serverCn}};
}

auto SessionTicket::fromJson(const nlohmann::json &json)
    -> std::expected<SessionTicket, std::string> {
  std::expected<SessionTicket, std::string> ticket{SessionTicket{}};
  logzy::debug("loading session ticket from json.");

  const auto sessionId = json.value("session_id", std ::string_view{""});
  const auto clientCn = json.value("client_cn", std ::string_view{""});
  const auto serverCn = json.value("server_cn", std ::string_view{""});
  if (sessionId.empty()) {
    return std::unexpected("session id was empty");
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

  logzy::debug("session loadded.");
  return ticket;
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

  std::string userCertPem;
  if (auto certResult = clientCert.toPem()) {
    userCertPem = std::move(*certResult);
  } else {
    return std::unexpected{
        std::format("Couldn't encrypt user's id. {}", certResult.error())};
  }

  // TODO :: Service request should contian a nonce or stiemstamp signde with
  // private key to prevent reply attacks

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::ServiceRequest,
                          .payload = {
                              {"user_cert_pem", userCertPem},
                          }})) {

    return std::unexpected{std::format("ServiceRequest failed. {}", *err)};
  }

  logzy::debug("Waiting for TTP response forwarded by server.");

  SessionTicket ticket;
  if (auto packet = ttpSocket.receive()) {
    if (packet->type != network::PacketType::ServerAuthOk) {
      logzy::error(
          "Received wrong type of packet. {} and expected ServerAuthResponse",
          packet->type);
    }
    logzy::trace("Recevied ServerAuthOk. {}", packet->payload.dump());

    // Verifying server certificate

    if (auto res = verifyAndParseSessionTicket(packet->payload, ttpKey)) {
      ticket = std::move(*res);
    } else {
      return std::unexpected{
          std::format("Couldn't veriy payload integrity. {}", res.error())};
    }

  } else {
    return std::unexpected{std::format("Receiving failed. {}", packet.error())};
  }
  logzy::info("Session: {}", ticket.sessionId);

  // User  auth redirect happens here
  if (auto packet = ttpSocket.receive()) {
    if (packet->type != network::PacketType::UserAuthRedirect) {
      return std::unexpected{std::format(
          "Received wrong type of packet. {} and expected UserAuthRedirect",
          packet->type)};
    }

  } else {
    return std::unexpected{std::format("Receving failed. {}", packet.error())};
  }

  logzy::trace("Sending user auth data to TTP");

  if (auto err = ttpSocket.send(
          network::Packet{.type = network::PacketType::UserAuthDataSubmit,
                          .payload = {
                              {"user_cert_pem", userCertPem},
                              {"session_id", ticket.sessionId},
                          }})) {
    return std::unexpected{
        std::format("Couldn't send user auth data to TTP. {}", *err)};
  }

  // Server should notify the client that its ok and pass the sssion key

  auto authResult = ttpSocket.receive();
  if (authResult) {
    if (authResult->type != network::PacketType::UserAuthOk) {
      return std::unexpected{
          std::format("User auth failed. expected UserAuthOk packet but got {}",
                      authResult->type)};
    }

    const auto clientSessionKey =
        authResult->payload.value("client_session_key", std::string_view{""});

    if (clientSessionKey.empty()) {
      return std::unexpected{
          std::format("Server didn't send AES 256 GCM session key with "
                      "UserAuthOk packet.")};
    }

    auto keyString = crypto::decodeAndDecrypt(clientSessionKey, clientKey);
    if (keyString) {

      auto aes = crypto::Aes256::fromKey(*keyString);
      if (aes) {
        return std::expected<crypto::Aes256, std::string>{std::move(*aes)};
      }
      return std::unexpected{
          std::format("Couldnt create AES 256 GCM form key '{}'. {}",
                      *keyString, aes.error())};
    }
    return std::unexpected{std::format(
        "Couldn't decode and decrypt aes key. {}", keyString.error())};
  }
  return std::unexpected{
      std::format("Receiving from clietn failed. {}", authResult.error())};
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

  logzy::debug("estabilishConnection");
  const auto userCertPem = requestPayload.value("user_cert_pem", "");
  if (userCertPem.empty()) {
    return std::unexpected{std::format(
        "Client' didnt supply 'user_cert_pem' (user certificate) with "
        "ServiceRequest")};
  }

  logzy::trace("user certificate PEM:\n{}", userCertPem);

  std::string serverCertPem;

  if (auto res = serverCertificate.toPem()) {
    serverCertPem = std::move(*res);
  } else {
    return std::unexpected{
        std::format("Couldn't convert server's certifiacte to PEM")};
  }

  if (auto err = ttpSocket.send(network::Packet{
          .type = network::PacketType::ServerAuthRequest,
          .payload =
              {
                  {"user_certificate_pem", userCertPem},
                  {"server_certificate_pem", serverCertPem},
              },
      })) {
    return std::unexpected{
        std::format("Couldn't send verification data to TTP server. {}", *err)};
  }

  if (auto ttpVerificationResult = ttpSocket.receive()) {
    if (ttpVerificationResult->type != network::PacketType::ServerAuthOk) {
      return std::unexpected{
          std::format("TTP sent wrong auth packet: {}. Expected ServerAuthOk",
                      ttpVerificationResult->type)};
    }

    logzy::trace("Passing ServerAuthOk to client.");
    // passing to user
  } else {
    return std::unexpected{
        std::format("Couldn't receive TTP's verification packet. {}",
                    ttpVerificationResult.error())};
  }

  logzy::trace("Waiting for client's auth");
  auto clientAuthResult = ttpSocket.receive();
  if (clientAuthResult) {
    if (clientAuthResult->type != network::PacketType::UserAuthOk) {
      return std::unexpected{
          std::format("Authenticating user failed. Received wrong packet with "
                      "type {}. Expected UserAuthOk",
                      clientAuthResult->type)};
    }

    const auto serverSessionKey = clientAuthResult->payload.value(
        "server_session_key", std::string_view{""});

    if (serverSessionKey.empty()) {
      return std::unexpected{
          std::format("USerAuthOk packet sohould have server_session_key")};
    }

    auto keyString = crypto::decodeAndDecrypt(serverSessionKey, serverKey);
    if (keyString) {

      auto aes = crypto::Aes256::fromKey(*keyString);
      if (aes) {
        return std::expected<crypto::Aes256, std::string>{std::move(*aes)};
        logzy::info("Sesssion estalbiflsbifs");
      }
      return std::unexpected{
          std::format("Couldnt create AES 256 GCM form key '{}'. {}",
                      *keyString, aes.error())};
    }
    return std::unexpected{std::format(
        "Couldn't decode and decrypt aes key. {}", keyString.error())};

    // logzy::info("Session key: {}", sessionKey.getRawKey());
    // logzy::info("Auth success. Received session data.");
    // logzy::info("Encrypted 'test' = '{}'", *sessionKey.encrypt("test"));

    // SESSION KEY lalalallal blablablabla
  }
  return std::unexpected{
      std::format("Couldn't receive TTP's user verification packet. {}",
                  clientAuthResult.error())};
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

[[nodiscard]] auto
registerWithTtp(network::TcpSocket &socket, const crypto::Hash32 &id,
                const crypto::RsaKeyPair &clientKey, const TtpData &ttpData)
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
    return std::unexpected{
        std::format("Couldn't encrypte id. {}", res.error())};
  }

  nlohmann::json payload = {
      {"id", encryptedId},
      {"public_key_pem", std::move(publicKeyPem)},
  };

  logzy::info("Registering with TTP");
  logzy::trace("Requesting TTP's certificate.");
  if (auto err = socket.send({.type = network::PacketType::CertificateRequest,
                              .payload = std::move(payload)})) {
    return std::unexpected{
        std::format("Couldn't send packet to TTP: {}", *err)};
  }

  logzy::trace("Requested. Waiting for response");
  auto received = socket.receive();
  if (!received) {
    return std::unexpected{std::format("There was an error when "
                                       "received packet from TTP. {}",
                                       received.error())};
  }

  if (received->type != network::PacketType::CertificateResponse) {
    return std::unexpected{std::format("TTP Sent wrong packet when "
                                       "registering. {}",
                                       *received)};
  }

  auto receivedCertPem =
      received->payload.value("certificate_pem", std::string_view{""});
  if (receivedCertPem.empty()) {
    return std::unexpected{std::format("No certificate in resposen.")};
  }

  crypto::X509Certificate receivedCert;
  if (auto res = crypto::X509Certificate::fromPem(receivedCertPem)) {
    receivedCert = std::move(*res);
  } else {
    return std::unexpected{
        std::format("Invalid certificate PEM. {}", res.error())};
  }

  if (auto res = ttpData.certificate.verify(receivedCert)) {
    if (!*res) {
      return std::unexpected{std::format("Certificate veirifaction failed")};
    }
  } else {
    return std::unexpected{
        std::format("Error when veirfyin gcertificate. {}", res.error())};
  }

  return std::expected<crypto::X509Certificate, std::string>{
      std::move(receivedCert)};
}

auto handleRegister(crypto::X509Certificate &ttpCertificate,
                    network::TcpSocket &client,
                    const crypto::RsaKeyPair &ttpKey)
    -> std::expected<ClientInfo, std::string> {

  nlohmann::json payload;
  if (auto packet = client.receive()) {
    if (packet->type != network::PacketType::CertificateRequest) {
      return std::unexpected(
          std::format("Invalid register packet type. {}", packet->type));
    }
    payload = std::move(packet->payload);
  } else {
    return std::unexpected(
        std::format("Couldn't receive from socket. {}", packet.error()));
  }

  logzy::trace("Received TradePublicKeysWithTtp packet from");

  auto publicKeyPem = payload.value("public_key_pem", std::string_view{""});
  std::string clientID = payload.value("id", "");

  if (clientID.empty()) {
    return std::unexpected(std::format("id is empty"));
  }

  if (auto res = crypto::decodeAndDecrypt(clientID, ttpKey)) {
    clientID = std::move(*res);
  } else {
    return std::unexpected(
        std::format("Couldn't decrypt user's id. {}", res.error()));
  }

  crypto::RsaKeyPair clientPublicKey;

  if (auto res = crypto::RsaKeyPair::fromPublicPem(publicKeyPem)) {
    clientPublicKey = std::move(*res);
  } else {
    return std::unexpected(
        std::format("Couldn't parse client's public key pem. {}", res.error()));
  }

  crypto::X509Certificate userCert;
  if (auto certRes = ttpCertificate.issue(clientPublicKey, clientID, ttpKey)) {
    userCert = std::move(*certRes);
  } else {
    return std::unexpected(
        std::format("Couldn't create user's certificate.{}", certRes.error()));
  }
  logzy::trace("Created user certificate for CN '{}'",
               userCert.getCommonNameSafe());

  logzy::trace("Sending client it's certificate");

  std::string userCertPem;

  if (auto res = userCert.toPem()) {
    userCertPem = std::move(*res);
  } else {
    return std::unexpected(
        std::format("Couldn't convert usercertificate to PEM"));
  }

  nlohmann::json responsePayload = {
      {"certificate_pem", std::move(userCertPem)},
  };

  auto userCertCn = userCert.getCommonName();
  if (!userCertCn) {
    return std::unexpected(
        std::format("Couldn't get common name from user's certificate. {}",
                    userCertCn.error()));
  }

  // RESPONSE
  if (auto err = client.send(
          network::Packet{.type = network::PacketType::CertificateResponse,
                          .payload = std::move(responsePayload)})) {
    return std::unexpected(std::format("error while sending. {}", *err));
  }

  logzy::info("sent certificate.");

  auto userPublicKey = userCert.getPublicKey();
  if (!userPublicKey) {
    return std::unexpected(std::format("couldn't get user's public key. {}",
                                       userPublicKey.error()));
  }

  return std::expected<ClientInfo, std::string>{
      ClientInfo{.commonName = std::move(*userCertCn),
                 .publicCertificate = std::move(userCert),
                 .publicKey = std::move(*userPublicKey)}};
}

auto finalizeHandshake(network::TcpSocket &clientSocket,
                       network::TcpSocket &serverSocket,
                       crypto::RsaKeyPair &clientPublicKey,
                       crypto::RsaKeyPair &serverPublicKey) -> bool {

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

  if (auto encSessKey = crypto::encryptAndEncode(sessionKey, clientPublicKey)) {
    encryptedClientSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt clients's session key. {}",
                 encSessKey.error());
    return false;
  }

  if (auto encSessKey = crypto::encryptAndEncode(sessionKey, serverPublicKey)) {
    encryptedServerSessionKey = std::move(*encSessKey);
  } else {
    logzy::error("Couldn't encrypt server's session key. {}",
                 encSessKey.error());
    return false;
  }

  if (auto err = serverSocket.send(network::Packet{
          .type = network::PacketType::UserAuthOk,
          .payload = {
              {"server_session_key", std::move(encryptedServerSessionKey)},
          }})) {
    logzy::error("Couldn't notify the server that user has "
                 "authenticated with TTP. {}",
                 *err);
    return false;
  }

  if (auto err = clientSocket.send(network::Packet{
          .type = network::PacketType::UserAuthOk,
          .payload = {
              {"client_session_key", std::move(encryptedClientSessionKey)},
          }})) {
    logzy::error("Couldn't notify the server that user has "
                 "authenticated with TTP. {}",
                 *err);
    return false;
  }
  return true;
}

auto handleClientHandshake(crypto::X509Certificate &ttpCertificate,
                           network::TcpSocket &clientSocket) -> bool {

  nlohmann::json payload;
  if (auto packet = clientSocket.receive()) {
    if (packet->type != network::PacketType::UserAuthDataSubmit) {
      logzy::error("Invalid register packet type. {}", packet->type);
      return false;
    }
    payload = std::move(packet->payload);
  } else {
    logzy::error("Couldn't receive from socket. {}", packet.error());
    return false;
  }

  std::string userCertPem = payload.value("user_cert_pem", "");
  if (userCertPem.empty()) {
    logzy::error("User didn't include crt pem.");
    return false;
  }

  crypto::X509Certificate userCert;
  if (auto res = crypto::X509Certificate::fromPem(userCertPem)) {
    userCert = std::move(*res);
  } else {
    logzy::error("Couldn't read user's certificate from PEM", userCertPem,
                 res.error());
    return false;
  }

  crypto::RsaKeyPair userPublicKey;
  if (auto res = userCert.getPublicKey()) {
    userPublicKey = std::move(*res);
  } else {
    logzy::error("Coulnd't etarctpuiblic key. {}", res.error());
    return false;
  }

  if (auto res = ttpCertificate.verify(userCert)) {
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

  return true;
}

} // namespace protocol
