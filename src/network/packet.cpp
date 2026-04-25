#include "packet.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include <cstdint>
#include <type_traits>
#include <utility>

namespace network {
using PacketTypeUnderlying = std::underlying_type_t<PacketType>;
using LengthType = std::uint32_t;

[[nodiscard]] static constexpr auto
isValidType(PacketTypeUnderlying type) noexcept -> bool {
  return type >= 0 && type < std::to_underlying(PacketType::__SizeGuard);
}

[[nodiscard]] static constexpr auto spanToUint32(std::span<char> bytes)
    -> std::uint32_t {
  DEBUG_ASSERT(bytes.size() == 4);

  return *(reinterpret_cast<std::uint32_t *>(bytes.data()));
}

[[nodiscard]] auto encode(const Packet &packet)
    -> std::expected<std::string, std::string> {

  std::expected<std::string, std::string> buffer;

  buffer->push_back(std::to_underlying(packet.type));

  std::string data = packet.payload.dump();

  std::array<char, LENGTH_SIZE_BYTES> lengthBuffer{};
  auto length = static_cast<LengthType>(data.size());
  logzy::trace("Encoded length = {}", length);
  std::memcpy(lengthBuffer.data(), &length, sizeof(LengthType));
  buffer->append(lengthBuffer.data(), lengthBuffer.size());

  buffer->append(data);

  return buffer;
}

[[nodiscard]] auto decodeHeader(std::span<char> data) noexcept
    -> std::expected<PacketHeader, std::string> {

  if (data.empty()) {
    return std::unexpected("Packet's header is empty");
  }

  std::span typeBytes = data.subspan(TYPE_OFFSET, TYPE_SIZE_BYTES);
  std::span lengthBytes = data.subspan(LENGTH_OFFSET, LENGTH_SIZE_BYTES);

  static_assert(TYPE_SIZE_BYTES == 1);
  auto packetType = static_cast<PacketTypeUnderlying>(typeBytes[0]);

  if (!isValidType(packetType)) {
    return std::unexpected(
        std::format("Packet type={} is invalid", packetType));
  }

  logzy::trace("Decoded packet header is (int={})", packetType);

  std::expected<PacketHeader, std::string> header{PacketHeader{}};
  header->type = static_cast<PacketType>(packetType);
  header->length = spanToUint32(lengthBytes);

  logzy::trace("Decoded payload length is: {}", header->length);

  return header;
}

[[nodiscard]] auto decodePayload(std::span<char> data) noexcept
    -> std::expected<Payload, std::string> {

  Payload payload;

  try {
    payload = nlohmann::json::parse(data);
  } catch (const nlohmann::json::exception &exc) {
    return std::unexpected(std::format("JSON parse error: {}", exc.what()));
  }

  return std::expected<Payload, std::string>{std::move(payload)};
}
} // namespace network
