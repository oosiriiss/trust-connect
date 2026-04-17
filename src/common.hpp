#pragma once

#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "network/socket.hpp"
#include <string>

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool;

[[nodiscard]] auto registerWithTtp(network::TcpSocket &socket,
                                   const crypto::Hash32 &id,
                                   const std::string &publicKeyPem)
    -> std::optional<crypto::RsaKeyPair>;
