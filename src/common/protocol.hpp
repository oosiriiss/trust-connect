#pragma once

#include "crypto/aes.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/socket.hpp"
#include <string>

namespace protocol {

namespace keys {

constexpr std::string_view Id = "id";
constexpr std::string_view SessionId = "session_id";
constexpr std::string_view ClientCommonName = "client_cn";
constexpr std::string_view ServerCommonName = "server_cn";
constexpr std::string_view UserCertPem = "user_cert_pem";
constexpr std::string_view ServerCertPem = "server_cert_pem";
constexpr std::string_view CertificatePem = "server_cert_pem";
constexpr std::string_view PublicKeyPem = "public_key_pem";
constexpr std::string_view Role = "role";
constexpr std::string_view SessionKey = "session_key";

} // namespace keys

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
  ClientRole role;
};

struct SessionInfo {
  crypto::X509Certificate serviceCertificate;
  crypto::X509Certificate clientCertificate;
};

auto handleRegister(crypto::X509Certificate &ttpCertificate,
                    network::TcpSocket &client,
                    const crypto::RsaKeyPair &ttpKey)
    -> std::expected<ClientInfo, std::string>;

auto authenticateClient(crypto::X509Certificate &ttpCertificate,
                        network::TcpSocket &clientSocket)
    -> std::optional<std::string>;

auto finalizeHandshake(network::TcpSocket &clientSocket,
                       network::TcpSocket &serverSocket,
                       const crypto::RsaKeyPair &clientPublicKey,
                       const crypto::RsaKeyPair &serverPublicKey)
    -> std::optional<std::string>;

auto authenticateService(const crypto::X509Certificate &ttpCertificate,
                         network::TcpSocket &serverSocket)
    -> std::expected<SessionInfo, std::string>;

auto notifyClient(network::TcpSocket &clientSocket,
                  const crypto::RsaKeyPair &ttpPrivateKey,
                  std::string_view clientCommonName,
                  std::string_view serverCommonName)
    -> std::optional<std::string>;

} // namespace protocol
