#pragma once

#include "network/packet.hpp"
#include "network/socket.hpp"
#include "nlohmann/json_fwd.hpp"
#include <expected>
namespace network {

namespace keys {
constexpr std::string_view ErrorMessage = "error_message";
}

[[nodiscard]] auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string>;

void sendError(TcpSocket &socket, std::string_view errorMessage);

} // namespace network
