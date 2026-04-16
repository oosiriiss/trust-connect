#include "packet.hpp"
#include <type_traits>
#include <utility>

namespace network {
using PacketTypeUnderlying = std::underlying_type_t<PacketType>;

constexpr size_t TYPE_OFFSET = 0;
constexpr size_t TYPE_SIZE_BYTES = sizeof(network::PacketType);
constexpr size_t PAYLOAD_OFFSET = TYPE_OFFSET + TYPE_SIZE_BYTES;

[[nodiscard]] static constexpr auto
isValidType(PacketTypeUnderlying type) noexcept -> bool {
  return type >= 0 && type < std::to_underlying(PacketType::__SizeGuard);
}

[[nodiscard]] auto encode(const Packet &packet)
    -> std::expected<std::string, std::string> {

  std::expected<std::string, std::string> buffer;

  buffer->push_back(std::to_underlying(packet.type));
  buffer->append(packet.payload.dump());

  return buffer;
}

[[nodiscard]] auto decode(std::string_view data)
    -> std::expected<Packet, std::string> {

  if (data.empty()) {
    return std::unexpected(std::format("Couldn't decode packet: {}", data));
  }

  std::string_view typeSubstring = data.substr(TYPE_OFFSET, TYPE_SIZE_BYTES);

  auto packetType = static_cast<PacketTypeUnderlying>(typeSubstring[0]);

  if (!isValidType(packetType)) {
    return std::unexpected(
        std::format("Packet type={} is invalid", packetType));
  }
  auto type = static_cast<PacketType>(packetType);

  std::string_view payloadSubstring = data.substr(PAYLOAD_OFFSET);
  Payload payload;

  try {
    payload = nlohmann::json::parse(payloadSubstring);
  } catch (const nlohmann::json::exception &exc) {
    return std::unexpected(std::format("JSON parse error: {}", exc.what()));
  }

  return std::expected<Packet, std::string>{
      Packet{.type = type, .payload = std::move(payload)}};
}
}; // namespace network
