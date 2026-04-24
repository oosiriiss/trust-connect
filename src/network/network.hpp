#pragma once

#include "network/packet.hpp"
#include "network/socket.hpp"
#include "nlohmann/json_fwd.hpp"
#include <expected>
namespace network {

[[nodiscard]] auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string>;
} // namespace network
