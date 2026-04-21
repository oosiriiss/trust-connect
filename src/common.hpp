#pragma once

#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/socket.hpp"
#include <string>

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool;

[[nodiscard]] auto
registerWithTtp(network::TcpSocket &socket, std::string_view name,
                const crypto::Hash32 &id, const crypto::RsaKeyPair &rsaKey,
                crypto::X509Certificate &outClientCertificate,
                crypto::X509Certificate &outCaCertificate,
                crypto::RsaKeyPair &ttpPublicKey) -> bool;
