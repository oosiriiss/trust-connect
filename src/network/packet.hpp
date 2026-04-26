#pragma once
#include <cstdint>
#include <expected>
#include <format>
#include <nlohmann/json.hpp>
#include <utility>

namespace network {

/**
 * Allowed packet types
 */
enum class PacketType : std::int8_t {
  CertificateRequest,
  CertificateResponse,
  InitiateAuth,
  InitiateAuthOk,
  ServiceRequest,
  ServerAuthRequest,
  ServerAuthOk,
  UserAuthDataSubmit,
  UserAuthOk,
  UserAuthRedirect,
  DataRequest,
  DataResponse,
  ErrorMessage,
  CloseConnection,
  TimedOut,
  __SizeGuard, // NOLINT
};

using PacketTypeUnderlying = std::underlying_type_t<PacketType>;
using LengthType = std::uint32_t;
constexpr size_t TYPE_OFFSET = 0;
constexpr size_t TYPE_SIZE_BYTES = sizeof(network::PacketType);
constexpr size_t LENGTH_OFFSET = TYPE_OFFSET + TYPE_SIZE_BYTES;
constexpr size_t LENGTH_SIZE_BYTES = sizeof(LengthType);
constexpr size_t PAYLOAD_OFFSET = LENGTH_OFFSET + LENGTH_SIZE_BYTES;
constexpr size_t HEADER_SIZE_BYTES = PAYLOAD_OFFSET;

/**
 * Packet header that should be present at the beginning of each packets
 */
struct PacketHeader {
  PacketType type;
  LengthType length;
};

/**
 * Packet using which the data can be transferred with TcpSocket or TcpServer
 */
struct Packet {
  PacketType type;
  /**
   * JSON payload
   */
  nlohmann::json payload;
};

using Payload = nlohmann::json;

/**
 * @brief encodes packet to bytes that can  be transferred over network
 *
 * Writes PacketHeader and payload
 *
 * @param packet The packet to encode
 *
 * @return
 * - Success: String containing the encoded packet's bytes
 * - Error: String error message
 */
[[nodiscard]] auto encode(const Packet &packet)
    -> std::expected<std::string, std::string>;

/**
 * @brief decodes PacketHeader from bytes
 *
 * @param data Span to the bytes that should contain encoded
 * PacketHeader
 *
 * @return
 * - Success: Encoded PacketHeader struct
 * - Error: String error message
 *
 * @ref encode(const Packet&)
 */
[[nodiscard]] auto decodeHeader(std::span<char> data) noexcept
    -> std::expected<PacketHeader, std::string>;

/**
 * @brief Decodes the bytes into Payload
 *
 * @param data Span to the raw payload bytes
 *
 * @return
 * - Success: JSON decoded payload
 * - Error: String error message
 *
 * @ref Payload
 */
[[nodiscard]] auto decodePayload(std::span<char> data) noexcept
    -> std::expected<Payload, std::string>;
} // namespace network

template <> struct std::formatter<network::PacketType> {
  static constexpr auto parse(std::format_parse_context &ctx) {
    return ctx.begin();
  }

  static auto format(const network::PacketType t, std::format_context &ctx) {
    using Type = network::PacketType;
    static std::unordered_map<Type, const char *> mappings{
        {Type::CertificateRequest, "CertificateRequest"},
        {Type::CertificateResponse, "CertificateResponse"},
        {Type::InitiateAuth, "InitiateAuth"},
        {Type::InitiateAuthOk, "InitiateAuthOk"},
        {Type::ServiceRequest, "ServiceRequest"},
        {Type::ServerAuthRequest, "ServerAuthRequest"},
        {Type::ServerAuthOk, "ServerAuthOk"},
        {Type::UserAuthDataSubmit, "UserAuthDataSubmit"},
        {Type::UserAuthOk, "UserAuthOk"},
        {Type::UserAuthRedirect, "UserAuthRedirect"},
        {Type::DataRequest, "DataRequest"},
        {Type::DataResponse, "DataResponse"},
        {Type::CloseConnection, "CloseConnection"},
        {Type::TimedOut, "TimedOut"},
        {Type::ErrorMessage, "ErrorMessage"},
        {Type::__SizeGuard, "__SizeGuard"},
    };

    std::string name = "PacketType::NOFORMATTERMAPPING(int=" +
                       std::to_string(std::to_underlying(t)) + ")";
    auto iter = mappings.find(t);
    if (iter != mappings.end()) {
      name = iter->second;
    }

    return std::format_to(ctx.out(), "{}", name);
  }
};

template <> struct std::formatter<network::Packet> {
  static constexpr auto parse(std::format_parse_context &ctx) {
    return ctx.begin();
  }
  static auto format(const network::Packet &p, std::format_context &ctx) {
    return std::format_to(ctx.out(), "Packet(type={}, payload={})", p.type,
                          p.payload.dump());
  }
};
