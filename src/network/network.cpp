#include "network.hpp"
#include "network/packet.hpp"

namespace network {
auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string> {

  return socket.receive().and_then(
      [expectedType](const network::Packet &packet)
          -> std::expected<nlohmann::json, std::string> {
        if (packet.type != expectedType) {
          return std::unexpected(
              std::format("Wrong packet type received '{}'. Expected {}",
                          packet.type, expectedType));
        }

        return packet.payload;
      });
}
} // namespace network
