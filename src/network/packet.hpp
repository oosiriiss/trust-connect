#pragma once
#include <cstdint>
#include <expected>
#include <format>
#include <nlohmann/json.hpp>

namespace network {

enum class PacketType : std::int8_t {
  TradePublicKeysWithTtpRequest,
  TradePublicKeysWithTtpResponse,
  RegisterRequest,
  RegisterResponse,
  CloseConnection,
  __SizeGuard, // NOLINT
};

struct Packet {
  PacketType type;
  nlohmann::json payload;
};

using Payload = nlohmann::json;

[[nodiscard]] auto encode(const Packet &packet)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto decode(std::string_view data)
    -> std::expected<Packet, std::string>;
} // namespace network

template <> struct std::formatter<network::PacketType> {
  static constexpr auto parse(std::format_parse_context &ctx) {
    return ctx.begin();
  }

  static auto format(const network::PacketType t, std::format_context &ctx) {
    using Type = network::PacketType;
    static std::unordered_map<Type, const char *> mappings{
        {Type::TradePublicKeysWithTtpRequest, "TradePublicKeysWithTtpRequest"},
        {Type::TradePublicKeysWithTtpResponse,
         "TradePublicKeysWithTtpResponse"},
        {Type::RegisterRequest, "RegisterRequest"},
        {Type::RegisterResponse, "RegisterResponse"},
        {Type::CloseConnection, "CloseConnection"},
        {Type::__SizeGuard, "__SizeGuard"},
    };

    return std::format_to(ctx.out(), "{}", mappings[t]);
  }
};

template <> struct std::formatter<network::Packet> {
  static constexpr auto parse(std::format_parse_context &ctx) {
    return ctx.begin();
  }
  static auto format(const network::Packet &p, std::format_context &ctx) {
    return std::format_to(ctx.out(), "Packet(type={}, payload={}", p.type,
                          p.payload.dump());
  }
};
