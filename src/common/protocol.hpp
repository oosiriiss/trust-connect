#pragma once

#include "crypto/aes.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/socket.hpp"
#include "utility.hpp"
#include <string>

namespace protocol {

struct TtpData {
  crypto::X509Certificate certificate;
  crypto::RsaKeyPair publicKey;

  //[[nodiscard]] auto fromFile(std::string_view path)
  //    -> std::expected<TtpData, std::string>;
};

struct SessionTicket {
  std::string sessionId;
  std::string clientCn;
  std::string serverCn;
  // TODO :: nonce
  // std::uint64_t clientNonce;

  [[nodiscard]] auto toJson() -> nlohmann::json;
  [[nodiscard]] static auto fromJson(const nlohmann::json &json)
      -> std::expected<SessionTicket, std::string>;
};

enum class ClientRole : std::uint8_t { Requester = 0, Service = 1 };

auto verifyAndParseSessionTicket(nlohmann::json &payload,
                                 const crypto::RsaKeyPair &ttpKey)
    -> std::expected<SessionTicket, std::string>;

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool;

[[nodiscard]] auto registerWithTtp(network::TcpSocket &socket,
                                   const crypto::Hash32 &id,
                                   const crypto::RsaKeyPair &clientKey,
                                   const TtpData &ttpData, ClientRole role)
    -> std::expected<crypto::X509Certificate, std::string>;

[[nodiscard]] auto clientHandshake(network::TcpSocket &serverSocket,
                                   network::TcpSocket &ttpSocket,
                                   crypto::X509Certificate &clientCert,
                                   const crypto::RsaKeyPair &clientKey,
                                   const crypto::RsaKeyPair &ttpKey)
    -> std::expected<crypto::Aes256, std::string>;

[[nodiscard]] auto serverHandshake(
    network::TcpSocket &clientSocket, network::TcpSocket &ttpSocket,
    const nlohmann::json &requestPayload, const crypto::Hash32 &serverID,
    const crypto::RsaKeyPair &serverKey, const crypto::RsaKeyPair &ttpKey,
    const crypto::X509Certificate &serverCertificate)
    -> std::expected<crypto::Aes256, std::string>;

struct ClientInfo {
  std::string commonName;
  crypto::X509Certificate publicCertificate;
  crypto::RsaKeyPair publicKey;
  ClientRole role;
};

auto handleRegister(crypto::X509Certificate &ttpCertificate,
                    network::TcpSocket &client,
                    const crypto::RsaKeyPair &ttpKey)
    -> std::expected<ClientInfo, std::string>;

auto handleClientHandshake(crypto::X509Certificate &ttpCertificate,
                           network::TcpSocket &clientSocket) -> bool;

auto finalizeHandshake(network::TcpSocket &clientSocket,
                       network::TcpSocket &serverSocket,
                       crypto::RsaKeyPair &clientPublicKey,
                       crypto::RsaKeyPair &serverPublicKey) -> bool;
} // namespace protocol
