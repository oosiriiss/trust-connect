#include "network.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"

constexpr std::string_view ERROR_MESSAGE_KEY = "error_message";

namespace network {
auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string> {

  return socket.receive().and_then(
      [expectedType](const network::Packet &packet)
          -> std::expected<nlohmann::json, std::string> {
        if (packet.type != expectedType) {
          if (packet.type == network::PacketType::ErrorMessage &&
              packet.payload.contains(ERROR_MESSAGE_KEY)) {
            return std::unexpected(packet.payload.value(ERROR_MESSAGE_KEY, ""));
          }

          return std::unexpected(
              std::format("Wrong packet type received '{}'. Expected {}",
                          packet.type, expectedType));
        }

        return packet.payload;
      });
}

void sendError(TcpSocket &socket, std::string_view errorMessage) {

  auto packet = network::Packet{.type = network::PacketType::ErrorMessage,
                                .payload = {{ERROR_MESSAGE_KEY, errorMessage}}};

  if (auto err = socket.send(packet)) {
    logzy::error("Couldn't send error. {}", *err);
    return;
  }
}

} // namespace network
