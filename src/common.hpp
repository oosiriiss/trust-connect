#pragma once

#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/socket.hpp"
#include <string>

struct TtpData {
  crypto::X509Certificate certificate;
  crypto::RsaKeyPair publicKey;
};

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool;

[[nodiscard]] auto
registerWithTtp(network::TcpSocket &socket, const crypto::Hash32 &id,
                const crypto::RsaKeyPair &rsaKey, const TtpData &ttpData,
                crypto::X509Certificate &outClientCertificate) -> bool;
