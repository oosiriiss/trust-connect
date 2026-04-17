#include "common.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <optional>

[[nodiscard]] auto connectTo(network::TcpSocket &socket,
                             const std::string &host, std::uint16_t port,
                             std::string_view targetName) -> bool {

  logzy::info("Connecting to {} at {}:{}", targetName, host, port);

  if (auto socketRes = network::TcpSocket::connect(host, port)) {
    logzy::info("successfully connected to: {}", targetName);
    socket = std::move(*socketRes);
    return true;
  } else {
    logzy::error("Couldn't connect to {}. Reason: {}", targetName,socketRes.error());
    return false;
   }
}

[[nodiscard]] static auto createRegisterPacket(const crypto::Hash32 &id)
    -> network::Packet {
  nlohmann::json payload;

  // Hash to hex just for human readability.
  payload["id"] = crypto::hashToHex(id);
  return network::Packet{.type = network::PacketType::RegisterRequest,
                         .payload = std::move(payload)};
}

[[nodiscard]] auto registerWithTtp(network::TcpSocket &socket,
                                   const crypto::Hash32 &id) -> bool {

  logzy::info("Registering with TTP");

  if (auto err = socket.send(createRegisterPacket(id))) {
    logzy::error("Couldn't send packet to TTP: {}", *err);
    return false;
  }

  logzy::info("Registered successfully");
  return true;
}
