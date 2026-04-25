#include "network.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"

namespace network {
auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string> {

  return socket.receive().and_then(
      [expectedType](const network::Packet &packet)
          -> std::expected<nlohmann::json, std::string> {
        if (packet.type != expectedType) {
          if (packet.type == network::PacketType::ErrorMessage &&
              packet.payload.contains(keys::ErrorMessage)) {
            return std::unexpected(
                packet.payload.value(keys::ErrorMessage, ""));
          }

          return std::unexpected(
              std::format("Wrong packet type received '{}'. Expected {}",
                          packet.type, expectedType));
        }

        return packet.payload;
      });
}

void sendError(TcpSocket &socket, std::string_view errorMessage) {

  auto packet =
      network::Packet{.type = network::PacketType::ErrorMessage,
                      .payload = {{keys::ErrorMessage, errorMessage}}};

  if (auto err = socket.send(packet)) {
    logzy::error("Couldn't send error. {}", *err);
    return;
  }
}

} // namespace network
