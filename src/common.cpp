#include "common.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
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
  return network::Packet{.type =
                             network::PacketType::TradePublicKeysWithTtpRequest,
                         .payload = std::move(payload)};
}

[[nodiscard]] auto registerWithTtp(network::TcpSocket &socket,
                                   const crypto::Hash32 &id,
                                   const std::string &publicKeyPem)
    -> std::optional<crypto::RsaKeyPair> {

  logzy::info("Registering with TTP");

  logzy::trace("Sending own public key and requesting TTP's public key");
  if (auto err = socket.send(createRegisterPacket(publicKeyPem))) {
    logzy::error("Couldn't send packet to TTP: {}", *err);
    return std::nullopt;
  }
  logzy::trace("Own public key sent. Waiting for response");
  auto received = socket.receive();
  if (!received) {
    logzy::error("There was an error when received packet from TTP. {}",
                 received.error());
    return std::nullopt;
  }

  if (received->type != network::PacketType::TradePublicKeysWithTtpResponse) {
    logzy::error("TTP Sent wrong packet when registering. {}", *received);
    return std::nullopt;
  }

  std::string_view ttpPublicKeyPemString =
      received->payload.value("public_key_pem", std::string_view{""});

  if (ttpPublicKeyPemString.empty()) {
    logzy::error(
        "TTP's response payload doesn't include 'public_key_pem' json key");
    return std::nullopt;
  }

  auto keyResult = crypto::RsaKeyPair::fromPublicPem(ttpPublicKeyPemString);
  if (!keyResult) {
    logzy::error("Couldn't create RSA key pair from TTP's public key PEM. {}",
                 keyResult.error());
    return std::nullopt;
  }

  std::optional<crypto::RsaKeyPair> ttpPublicKey{std::move(*keyResult)};

  std::string encryptedId;

  if (auto encryptResult =
          crypto::encryptAndEncode(crypto::hashToHex(id), *ttpPublicKey)) {
    encryptedId = std::move(*encryptResult);
  } else {
    logzy::error("Error occurred. {}", encryptResult.error());
    return std::nullopt;
  }

  if (auto err = socket.send(network::Packet{
          .type = network::PacketType::RegisterRequest,
          .payload = {{"id", encryptedId}},
      })) {
    logzy::error("Couldn't send {} to TTP. {}",
                 network::PacketType::RegisterRequest, *err);
    return std::nullopt;
  }

  return ttpPublicKey;
}
