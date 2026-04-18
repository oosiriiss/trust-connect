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
  ServiceRequest,
  ServerAuthRequest,
  ServerAuthOk,
  UserAuthRedirect,
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

        {Type::TradePublicKeysWithTtpRequest,
         "Type::TradePublicKeysWithTtpRequest"},
        {Type::TradePublicKeysWithTtpResponse,
         "Type::TradePublicKeysWithTtpResponse"},
        {Type::RegisterRequest, "Type::RegisterRequest"},
        {Type::RegisterResponse, "Type::RegisterResponse"},
        {Type::ServiceRequest, "Type::ServiceRequest"},
        {Type::ServerAuthRequest, "Type::ServerAuthRequest"},
        {Type::ServerAuthOk, "Type::ServerAuthOk"},
        {Type::UserAuthRedirect, "Type::UserAuthRedirect"},
        {Type::CloseConnection, "Type::CloseConnection"},
        {Type::__SizeGuard, "Type::__SizeGuard"},
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
