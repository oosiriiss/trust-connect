#pragma once

#include "constants.hpp"
#include "packet.hpp"
#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace network {

static constexpr auto INVALID_SOCKET = -1;

/**
 * Unix socket wrapper
 */
struct TcpSocket {

public:
  TcpSocket() = default;
  TcpSocket(const TcpSocket &) = delete;
  TcpSocket(TcpSocket &&) noexcept;
  TcpSocket &operator=(const TcpSocket &) = delete; // NOLINT
  TcpSocket &operator=(TcpSocket &&) noexcept;      // NOLINT
  ~TcpSocket() noexcept;

  /**
   * @brief creates a TCP connection to @p host @p:@p port @p
   *
   * @param host IP address of the target
   * @param port Port  of the target
   *
   * @return
   * - Success: TcpSocket connected to given <host>:<port>.
   * - Error: string error message on why the connection failed.
   */
  [[nodiscard]] static auto connect(const std::string &host,
                                    std::uint16_t port) noexcept
      -> std::expected<TcpSocket, std::string>;

  /**
   * @brief sends a packet to client associated with this socket
   *
   * @param packet Packet to send
   *
   * @return
   * - Success: std::nullopt
   * - Error: String error message
   */
  [[nodiscard]] auto send(const Packet &packet) const noexcept
      -> std::optional<std::string>;

  /**
   * @brief Reads a packet from the socket
   *
   * This function blocks until a packet is received or after timeout (set with
   * TcpSocket::setTimeout()) expires.
   *
   * @return
   * - Success: Received Packet
   * - Error: String error message
   */
  [[nodiscard]] auto receive() const noexcept
      -> std::expected<Packet, std::string>;

  /**
   * @brief Sets a receive timeout
   *
   * This timer works with TcpSocket::receive() to allow unblocking after a
   * specified time passes
   *
   * @param millis Number of milliseconds to set the timeout.
   *
   * @return
   * - Success: std::nullopt
   * - Error: String error message
   */
  [[nodiscard]] auto setTimeout(std::uint32_t millis) noexcept
      -> std::optional<std::string>;

  /**
   * @brief Sets the timeout timer to 0 milliseconds
   *
   * This function is same as calling Packet::setTimeout(0)
   *
   * @return
   * - Success: std::nullopt
   * - Error: String error message
   */
  auto disableTimeout() noexcept -> std::optional<std::string>;

  /**
   * @brief Check if a socket is valid and allows data transfer
   *
   * Checks for errors with socket and tries to peek a single bytes to see if it
   * is 'readable'
   *
   * @retval true Socket is open and not errors were found
   * @retval false Socket is invalid. It either got closed or some other error
   * happened like Broken Pipe.
   *
   */
  [[nodiscard]] auto isHealthy() const noexcept -> bool;

  /**
   * @brief closes the socket and makes it invalid.
   *
   * @note After that any further calls will not be valid.
   */
  void close() noexcept;

  /**
   * @brief returns underyling file descriptor
   *
   * @return System file descriptor representing the socket
   */
  [[nodiscard]] constexpr auto getFd() const noexcept -> int { return fd_; }

  friend class TcpServer;

private:
  /**
   * Socket file descriptor
   */
  int fd_{INVALID_SOCKET};
};

struct TcpServer {

public:
  TcpServer() = default;
  ~TcpServer() noexcept;
  TcpServer(const TcpServer &) = delete;
  TcpServer(TcpServer &&) noexcept;
  TcpServer &operator=(const TcpServer &) = delete; // NOLINT
  TcpServer &operator=(TcpServer &&) = delete;      // NOLINT

  /**
   * @brief Binds the server to given port
   *
   * @param port Port to bind to
   *
   * @return
   * - Success: std::nullopt
   * - Error: String error message
   */
  [[nodiscard]] auto listen(std::uint16_t port = DEFAULT_SERVER_PORT)
      -> std::optional<std::string>;

  /**
   * @brief Blocks and waits until a client tries to connect.
   *
   * @return
   * - Success: TcpSocket that that is connected to the connected client.
   * - Error: String error message.
   */
  [[nodiscard]] auto accept() const -> std::expected<TcpSocket, std::string>;

  /**
   * @brief closes the socket and makes it invalid.
   *
   * @note After that any further calls will not be valid.
   */
  void close() noexcept;

private:
  /**
   * Socket file descriptor
   */
  int fd_{INVALID_SOCKET};
};

} // namespace network
