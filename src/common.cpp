#include "common.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <expected>
#include <optional>

auto SessionTicket::toJson() -> nlohmann::json {
  return nlohmann::json{{"session_id", sessionId},
                        {"client_cn", clientCn},
                        {"server_cn", serverCn}};
}

auto SessionTicket::fromJson(const nlohmann::json &json)
    -> std::expected<SessionTicket, std::string> {
  std::expected<SessionTicket, std::string> ticket{SessionTicket{}};
  logzy::debug("loading session ticket from json.");

  const auto sessionId = json.value("session_in", std ::string_view{""});
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

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool {

  logzy::info("Connecting to {} at {}:{}", targetName, host, port);

  auto socketRes = network::TcpSocket::connect(host, port);
  if (!socketRes) {

    logzy::error("Couldn't connect to {}. Reason: {}", targetName,
                 socketRes.error());
    // As of now failure in connection is just ommited, and is not considered
    // and error
    return true;
  }

  logzy::info("successfully connected to: {}", targetName);
  socket = std::move(*socketRes);
  return true;
}

[[nodiscard]] auto
registerWithTtp(network::TcpSocket &socket, const crypto::Hash32 &id,
                const crypto::RsaKeyPair &rsaKey, const TtpData &ttpData,
                crypto::X509Certificate &outClientCertificate) -> bool {

  std::string publicKeyPem;
  if (auto res = rsaKey.publicKeyPem()) {
    publicKeyPem = std::move(*res);
  } else {
    logzy::error("Couldnt' create public key pem. {}", res.error());
    return false;
  }

  std::string encryptedId;
  if (auto res =
          crypto::encryptAndEncode(crypto::hashToHex(id), ttpData.publicKey)) {
    encryptedId = std::move(*res);
  } else {
    logzy::error("Couldn't encrypte id. {}", res.error());
    return false;
  }

  nlohmann::json payload = {
      {"id", encryptedId},
      {"public_key_pem", std::move(publicKeyPem)},
  };

  logzy::info("Registering with TTP");
  logzy::trace("Requesting TTP's certificate.");
  if (auto err = socket.send({.type = network::PacketType::CertificateRequest,
                              .payload = std::move(payload)})) {
    logzy::error("Couldn't send packet to TTP: {}", *err);
    return false;
  }

  logzy::trace("Requested. Waiting for response");
  auto received = socket.receive();
  if (!received) {
    logzy::error("There was an error when received packet from TTP. {}",
                 received.error());
    return false;
  }

  if (received->type != network::PacketType::CertificateResponse) {
    logzy::error("TTP Sent wrong packet when registering. {}", *received);
    return false;
  }

  auto receivedCertPem =
      received->payload.value("certificate_pem", std::string_view{""});
  if (receivedCertPem.empty()) {
    logzy::error("No certificate in resposen.");
    return false;
  }

  crypto::X509Certificate receivedCert;
  if (auto res = crypto::X509Certificate::fromPem(receivedCertPem)) {
    receivedCert = std::move(*res);
  } else {
    logzy::error("Invalid certificate PEM. {}", res.error());
    return false;
  }

  if (auto res = ttpData.certificate.verify(receivedCert)) {
    if (!*res) {
      logzy::critical("Certificate veirifaction failed");
      return false;
    }
  } else {
    logzy::error("Error when veirfyin gcertificate. {}", res.error());
    return false;
  }

  outClientCertificate = std::move(receivedCert);
  return true;
}
