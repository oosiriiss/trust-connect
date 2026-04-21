#include "common.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <expected>
#include <optional>

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

[[nodiscard]] static auto createRegisterPacket(const std::string &publicKeyPem)
    -> network::Packet {
  nlohmann::json payload;

  // Hash to hex just for human readability.
  payload["public_key_pem"] = publicKeyPem;
  return network::Packet{.type = network::PacketType::CertificateRequest,
                         .payload = std::move(payload)};
}

[[nodiscard]] auto
registerWithTtp(network::TcpSocket &socket, std::string_view name,
                const crypto::Hash32 &id, const crypto::RsaKeyPair &rsaKey,
                crypto::X509Certificate &outClientCertificate,
                crypto::X509Certificate &outCaCertificate,
                crypto::RsaKeyPair &ttpPublicKey) -> bool {

  std::string publicKeyPem;
  if (auto res = rsaKey.publicKeyPem()) {
    publicKeyPem = std::move(*res);
  } else {
    logzy::error("Couldnt' create public key pem. {}", res.error());
    return false;
  }

  nlohmann::json payload = {
      {"common_name", name},
      {"public_key_pem", std::move(publicKeyPem)},
  };

  logzy::debug("Siginig the request payload.");
  std::string signature;
  if (auto res = rsaKey.sign(payload.dump())) {

      if(auto encode = 
    signature = std::move(*res);
  } else {
    logzy::error("Couldn't sign the payload. {}", res.error());
    return false;
  }

   

  payload["signature"] = std::move(signature);

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

  if (received->type != network::PacketType::TradePublicKeysWithTtpResponse) {
    logzy::error("TTP Sent wrong packet when registering. {}", *received);
    return false;
  }

  std::string cert = received->payload.value("certificate_pem", "");
  std::string caCert = received->payload.value("ttp_ca_certificate_pem", "");
  signature = received->payload.value("signature", "");
  received->payload.erase("signature");

  if (cert.empty() || caCert.empty() || signature.empty()) {
    logzy::error("insufficient data");
  }

  crypto::X509Certificate ttpCert;
  if (auto res = crypto::X509Certificate::fromPem(caCert)) {
    ttpCert = std::move(*res);
  } else {
    logzy::error("couldn't load ca cert");
    return false;
  }

  crypto::X509Certificate ownCert;

  if (auto res = crypto::X509Certificate::fromPem(cert)) {
    ownCert = std::move(*res);
  } else {
    logzy::error("couldn't load own cert");
    return false;
  }

  std::string_view ttpPublicKeyPemString =
      received->payload.value("public_key_pem", std::string_view{""});

  if (ttpPublicKeyPemString.empty()) {
    logzy::error(
        "TTP's response payload doesn't include 'public_key_pem' json key");
    return false;
  }

  auto keyResult = crypto::RsaKeyPair::fromPublicPem(ttpPublicKeyPemString);
  if (!keyResult) {
    logzy::error("Couldn't create RSA key pair from TTP's public key PEM. {}",
                 keyResult.error());
    return false;
  }

  ttpPublicKey = std::move(*keyResult);

  std::string encryptedId;

  if (auto encryptResult =
          crypto::encryptAndEncode(crypto::hashToHex(id), ttpPublicKey)) {
    encryptedId = std::move(*encryptResult);
  } else {
    logzy::error("Error occurred. {}", encryptResult.error());
    return false;
  }

  logzy::trace("Obatining certificates");

  if (auto err = socket.send(network::Packet{
          .type = network::PacketType::RegisterRequest,
          .payload = {{"name", name}, {"id", encryptedId}},
      })) {
    logzy::error("Couldn't send {} to TTP. {}",
                 network::PacketType::RegisterRequest, *err);
    return false;
  }

  if (auto certPacket = socket.receive()) {
    if (certPacket->type != network::PacketType::RegisterResponse) {
      logzy::error("TTP sent wrong packet as register response. {}",
                   certPacket->type);
      return false;
    }
    std::string_view ttpCaCertificate = certPacket->payload.value(
        "ttp_ca_certificate_pem", std::string_view{""});
    std::string_view currentCertificate =
        certPacket->payload.value("certificate_pem", std::string_view{""});

    if (ttpCaCertificate.empty()) {
      logzy::error("TTP sent empty CA certificate.");
      return false;
    }

    if (currentCertificate.empty()) {
      logzy::error("TTP sent empty client's certificate.");
      return false;
    }

    if (auto certRes = crypto::X509Certificate::fromPem(ttpCaCertificate)) {
      logzy::trace("Received CA certificate.");
      outCaCertificate = std::move(*certRes);
    } else {
      logzy::error("CA Certificate was malformed. {}", certRes.error());
      return false;
    }

    if (auto certRes = crypto::X509Certificate::fromPem(currentCertificate)) {
      logzy::trace("Received Client certificate.");
      outClientCertificate = std::move(*certRes);
    } else {
      logzy::error("Client Certificate was malformed. {}", certRes.error());
      return false;
    }

    return true;
  }
  return false;
}
