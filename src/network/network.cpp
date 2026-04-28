#include "network.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>

namespace network {

auto ipFromHost(const std::string &host)
    -> std::expected<std::string, std::string> {
  logzy::debug("Resolving hostname: {}", host);
  struct addrinfo hints{.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  struct addrinfo *result = nullptr;

  if (int status = getaddrinfo(host.c_str(), nullptr, &hints, &result);
      status != 0) {
    return std::unexpected(std::format("{}", host, gai_strerror(status)));
  }

  if (result == nullptr) {
    return std::unexpected(std::format("Result was null", host));
  }

  if (result->ai_next != nullptr) {
    return std::unexpected(std::format("Multiple addresses found", host));
  }

  DEBUG_ASSERT(result->ai_family == AF_INET, "Found address should be IPv4");

  auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(result->ai_addr);
  auto *rawIpv4Address = &ipv4->sin_addr;

  std::array<char, INET_ADDRSTRLEN> buffer{};
  if (inet_ntop(result->ai_family, rawIpv4Address, buffer.data(),
                buffer.size()) == nullptr) {
    return std::unexpected(std::format("Conversion to human format failed. {}",
                                       std::system_category().message(errno)));
  }

  std::expected<std::string, std::string> humanReadableIp{
      std::string{buffer.data(), buffer.size()}};

  return humanReadableIp;
}

auto connectTo(const std::string &host, std::uint16_t port,
               std::string_view targetName)
    -> std::expected<TcpSocket, std::string> {
  logzy::debug("Connecting to {} at {}:{}", targetName, host, port);

  auto socketRes = network::TcpSocket::connect(host, port);
  if (!socketRes) {
    return std::unexpected(std::format("Couldn't connect to {}. Reason: {}",
                                       targetName, socketRes.error()));
  }

  logzy::debug("successfully connected to: {}", targetName);
  return socketRes;
}

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
