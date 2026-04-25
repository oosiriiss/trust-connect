#pragma once

#include "constants.hpp"
#include "packet.hpp"
#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace network {

static constexpr auto INVALID_SOCKET = -1;

struct TcpSocket {

public:
  TcpSocket() = default;
  TcpSocket(const TcpSocket &) = delete;
  TcpSocket(TcpSocket &&) noexcept;
  TcpSocket &operator=(const TcpSocket &) = delete; // NOLINT
  TcpSocket &operator=(TcpSocket &&) noexcept;      // NOLINT
  ~TcpSocket() noexcept;

  [[nodiscard]] static auto connect(const std::string &host,
                                    std::uint16_t port) noexcept
      -> std::expected<TcpSocket, std::string>;

  [[nodiscard]] auto send(const Packet &packet) const noexcept
      -> std::optional<std::string>;

  [[nodiscard]] auto receive() const noexcept
      -> std::expected<Packet, std::string>;

  [[nodiscard]] auto setTimeout(std::uint32_t millis) noexcept
      -> std::optional<std::string>;
  auto disableTimeout() noexcept -> std::optional<std::string>;

  [[nodiscard]] auto isHealthy() const noexcept -> bool;

  void close() noexcept;

  friend class TcpServer;

  [[nodiscard]] constexpr auto getFd() const noexcept -> int { return fd_; }

private:
  int fd_{INVALID_SOCKET};
};

struct TcpServer {
  static constexpr int MAX_CONNECTIONS = 4;

public:
  TcpServer() = default;
  ~TcpServer() noexcept;
  TcpServer(const TcpServer &) = delete;
  TcpServer(TcpServer &&) noexcept;
  TcpServer &operator=(const TcpServer &) = delete; // NOLINT
  TcpServer &operator=(TcpServer &&) = delete;      // NOLINT

  [[nodiscard]] auto listen(std::uint16_t port = DEFAULT_SERVER_PORT)
      -> std::optional<std::string>;
  [[nodiscard]] auto accept() const -> std::expected<TcpSocket, std::string>;

  void close() noexcept;

private:
  int fd_{INVALID_SOCKET};
};

} // namespace network
