#pragma once

#include "crypto/aes.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/socket.hpp"
#include <string>

namespace protocol {

static constexpr std::string_view TTP_CERT_PATH = "ttp.cert";

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

/**
 * holds TTP's certificate certificate and public or private key
 */
struct TtpData {
  /**
   * Public Certificate if used at client
   * Private Ca certificate if used at TTP
   */
  crypto::X509Certificate certificate;
  /**
   * Public key if used at client
   * Private key if used at TTP
   */
  crypto::RsaKeyPair key;
};

/**
 * Role of a connected client. Either Requester (i.e. user) or Service (i..e
 * Server)
 */
enum class ClientRole : std::uint8_t { Requester = 0, Service = 1 };

/**
 * @brief Loads the TTP certificate and extracts its public key from a file.
 *
 * @param path The filesystem path to the TTP public certificate file
 *
 * @return
 * - Success: A TtpData structure containing the public certificate and key
 * - Error: String error message
 */
[[nodiscard]] auto loadTtpData(std::string_view path = TTP_CERT_PATH)
    -> std::expected<TtpData, std::string>;

/**
 * @brief Performs a series of requests to obtain a dedicated certificate from
 * the TTP
 *
 * @param ttpSocket The connected socket to the TTP server
 * @param id The unique identifier for the client
 * @param clientKey The RSA key pair of the client
 * @param ttpData The TTP data used to encrypt the request
 *
 * @return
 * - Success: The X509Certificate issued by TTP as CA
 * - Error: String error message
 */
[[nodiscard]] auto
obtainCertificate(network::TcpSocket &ttpSocket, std::string_view id,
                  const crypto::RsaKeyPair &clientKey, const TtpData &ttpData)
    -> std::expected<crypto::X509Certificate, std::string>;

/**
 * @brief Initiates the authentication process with the TTP.
 *
 * Allows the TTP to mark the client as waiting for authentication
 *
 * @param ttpSocket The connected socket to the TTP server
 * @param clientCertificate The client's X509 certificate to send
 * @param role The role of the client (Requester or Service)
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto initiateAuthentication(network::TcpSocket &ttpSocket,
                            crypto::X509Certificate &clientCertificate,
                            ClientRole role) -> std::optional<std::string>;

/**
 * Session ticket returned by the TTP.
 * Currently not used
 */
struct SessionTicket {
  std::string sessionId;
  std::string clientCn;
  std::string serverCn;
  // TODO :: nonce
  // std::uint64_t clientNonce;

  /**
   * Converts it to JSON
   */
  [[nodiscard]] auto toJson() -> nlohmann::json;

  /**
   * Creates the SessionTicket struct from given payload
   *
   * @return
   * - Success: The parsed SessionTicket
   * - Error: String error message
   */
  [[nodiscard]] static auto fromJson(const nlohmann::json &json)
      -> std::expected<SessionTicket, std::string>;
};

/**
 * @brief Performs the handshake process from the requester client's side.
 *
 * Blocks until authentication is complete or error occurs
 *
 * @note initiateAuthentication() Must be called before this to ensure TTP is
 * waiting
 *
 * @param serverSocket The connected socket to the target service server
 * @param ttpSocket The connected socket to the TTP server
 * @param clientCert The requester's X509 certificate
 * @param clientKey The requester's RSA private key
 * @param ttpKey The TTP's public key
 *
 * @return
 * - Success: The AES-256 session key
 * - Error: String error message
 *
 * @ref initiateAuthentication()
 */
[[nodiscard]] auto clientHandshake(network::TcpSocket &serverSocket,
                                   network::TcpSocket &ttpSocket,
                                   crypto::X509Certificate &clientCert,
                                   const crypto::RsaKeyPair &clientKey,
                                   const crypto::RsaKeyPair &ttpKey)
    -> std::expected<crypto::Aes256, std::string>;

/**
 * @brief Performs the handshake process from the service server's side.
 *
 * @note initiateAuthentication() Must be called before this to ensure TTP is
 * waiting
 *
 * @param ttpSocket The connected socket to the TTP server
 * @param requestPayload The initial service request payload received from the
 * client
 * @param serverKey The server's RSA private key
 * @param serverCertificate The server's X509 certificate
 *
 * @return
 * - Success: The AES-256 session key
 * - Error: String error message
 *
 * @ref initiateAuthentication()
 */
[[nodiscard]] auto
serverHandshake(network::TcpSocket &ttpSocket,
                const nlohmann::json &requestPayload,
                const crypto::RsaKeyPair &serverKey,
                const crypto::X509Certificate &serverCertificate)
    -> std::expected<crypto::Aes256, std::string>;

/**
 * Holds information about an authenticated client.
 */
struct ClientInfo {
  std::string commonName;
  crypto::X509Certificate publicCertificate;
  ClientRole role;
};

/**
 * @brief Holds the public certificates of both parties in a session.
 */
struct SessionInfo {
  crypto::X509Certificate serviceCertificate;
  crypto::X509Certificate clientCertificate;
};

/**
 * @brief Handles a client's request to obtain a new certificate (TTP side).
 *
 * @note the connection may be terminated after this
 *
 * @param client The connected client socket
 * @param rawPayload The JSON payload containing the certificate request data
 * @param ttpData The TTP's data used to issue the certificate
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto handleObtainCertificate(network::TcpSocket &client,
                             nlohmann::json &rawPayload, TtpData &ttpData

                             ) -> std::optional<std::string>;

/**
 * @brief Handles the initial authentication request from a client (TTP side).
 *
 * @note After this connection with client could be presisted until
 * finalizeHandshake()
 *
 * @param clientSocket The connected client socket
 * @param rawPayload The JSON payload containing the authentication initiation
 * data
 * @param ttpData The TTP's data used to verify the client
 *
 * @return
 * - Success: A ClientInfo object containing the authenticated client's details
 * - Error: String error message
 */
auto handleInitiateAuthentication(network::TcpSocket &clientSocket,
                                  nlohmann::json &rawPayload, TtpData &ttpData)
    -> std::expected<ClientInfo, std::string>;

/**
 * @brief Authenticates a requester client after a session redirect (TTP side).
 *
 * @param ttpCertificate The TTP's certificate used to verify the client
 * @param clientSocket The connected client socket
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto authenticateClient(crypto::X509Certificate &ttpCertificate,
                        network::TcpSocket &clientSocket)
    -> std::optional<std::string>;

/**
 * @brief Finalizes the handshake by generating and distributing the AES-256
 * session key (TTP side).
 *
 * @param clientSocket The connected socket of the requester client
 * @param serverSocket The connected socket of the service server
 * @param clientPublicKey The requester's public key to encrypt their copy of
 * the session key
 * @param serverPublicKey The server's public key to encrypt their copy of the
 * session key
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto finalizeHandshake(network::TcpSocket &clientSocket,
                       network::TcpSocket &serverSocket,
                       const crypto::RsaKeyPair &clientPublicKey,
                       const crypto::RsaKeyPair &serverPublicKey)
    -> std::optional<std::string>;

/**
 * @brief Authenticates a service server requesting to validate a client (TTP
 * side).
 *
 * @param ttpCertificate The TTP's certificate used to verify the certificates
 * @param serverSocket The connected server socket
 *
 * @return
 * - Success: A SessionInfo object containing both certificates
 * - Error: String error message
 */
auto authenticateService(const crypto::X509Certificate &ttpCertificate,
                         network::TcpSocket &serverSocket)
    -> std::expected<SessionInfo, std::string>;

/**
 * @brief Notifies the requester client that the service has been authenticated,
 * sending a session ticket.
 *
 * @param clientSocket The connected socket of the requester client
 * @param ttpPrivateKey The TTP's private key used to sign the session ticket
 * @param clientCommonName The Common Name of the requester
 * @param serverCommonName The Common Name of the service
 *
 * @return
 * - Success: std::nullopt
 * - Error: String error message
 */
auto notifyClient(network::TcpSocket &clientSocket,
                  const crypto::RsaKeyPair &ttpPrivateKey,
                  std::string_view clientCommonName,
                  std::string_view serverCommonName)
    -> std::optional<std::string>;

} // namespace protocol
