
#include "network/socket.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include "network/packet.hpp"
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <expected>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <sys/socket.h>
#include <system_error>

namespace network {

static void closeSocket(int &fd) {
  if (fd == INVALID_SOCKET) {
    return;
  }

  if (shutdown(fd, SHUT_RDWR) != 0) {
    logzy::warn("Closing socket {} failed", fd);
  }
  fd = INVALID_SOCKET;
}

TcpSocket::~TcpSocket() noexcept { close(); }
TcpSocket::TcpSocket(TcpSocket &&other) noexcept : fd_{other.fd_} {
  other.fd_ = INVALID_SOCKET;
}

TcpSocket &TcpSocket::operator=(TcpSocket &&other) noexcept { // NNOLINT
  fd_ = other.fd_;
  other.fd_ = INVALID_SOCKET;
  return *this;
}

void TcpSocket::close() noexcept { closeSocket(fd_); }

auto TcpSocket::connect(const std::string &host, std::uint16_t port) noexcept
    -> std::expected<TcpSocket, std::string> {
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(addr.sin_family, host.c_str(), &addr.sin_addr);

  std::expected<TcpSocket, std::string> socket{TcpSocket{}};

  socket->fd_ = ::socket(addr.sin_family, SOCK_STREAM, 0);

  if (socket->fd_ < 0) {
    return std::unexpected(
        std::format("Couldnt' create a socket for {}:{}", host, port));
  }

  if (::connect(socket->fd_,
                reinterpret_cast<struct sockaddr *>(&addr), // NOLINT
                sizeof(addr)) != 0) {
    return std::unexpected(
        std::format("Couldn't connect to {}:{}", host, port));
  }

  logzy::trace("Client connected to {}:{}", host, port);
  return socket;
}

[[nodiscard]] auto TcpSocket::send(const Packet &packet) const noexcept
    -> std::optional<std::string> {

  logzy::trace("Sending: {}", packet);

  std::string dataToSend;

  if (auto serialized = encode(packet)) {
    dataToSend = std::move(*serialized);
  } else {
    return std::optional<std::string>(std::move(serialized.error()));
  }

  size_t packetBytesLeft = dataToSend.size();
  const auto *dataPtr =
      reinterpret_cast<const std::uint8_t *>(dataToSend.data()); // NOLINT

  while (packetBytesLeft > 0) {

    const ssize_t sentNow = ::send(fd_, dataPtr, packetBytesLeft, MSG_NOSIGNAL);

    if (sentNow <= 0) {
      return std::optional(std::format("Couldn't send packet: '{}'. Error: {}",
                                       packet,
                                       std::system_category().message(errno)));
    }

    DEBUG_ASSERT(sentNow <= packetBytesLeft);
    dataPtr += sentNow; // NOLINT
    packetBytesLeft -= sentNow;
  }

  logzy::trace("Packet successfully sent");
  return std::nullopt;
}

[[nodiscard]] auto TcpSocket::receive() const noexcept
    -> std::expected<Packet, std::string> {
  logzy::trace("Receiving...");

  std::expected<Packet, std::string> packet{Packet{}};
  size_t received = 0;

  std::string receivedData;

  std::array<char, 256> buffer{};

  while (true) {
    ssize_t read = ::recv(fd_, buffer.data(), buffer.size(), 0);

    if (read > 0) {

      receivedData.append(std::string_view{
          reinterpret_cast<const char *>(buffer.data()), // NOLINT
          static_cast<size_t>(read)});

      if (static_cast<size_t>(read) < buffer.size()) {
        break;
      }

    } else if (read == 0) { // Graceful closed connection
      return std::expected<Packet, std::string>{
          Packet{.type = PacketType::CloseConnection}};
    } else {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      return std::unexpected(std::format(
          "Receive failed. error: {}", std::system_category().message(errno)));
    }
  }

  return decode(receivedData);
}

//
// Server
//

TcpServer::~TcpServer() noexcept { close(); }
TcpServer::TcpServer(TcpServer &&other) noexcept : fd_{other.fd_} {
  other.close();
}
void TcpServer::close() noexcept { closeSocket(fd_); }

[[nodiscard]] auto TcpServer::listen(std::uint16_t port)
    -> std::optional<std::string> {

  fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0) {
    return std::optional(std::format("Couldn't create socket for server.err:{}",
                                     std::system_category().message(errno)));
  }
  const int opt = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  logzy::trace("Serve socket created");

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htons(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != // NOLINT
      0) {
    close();
    return std::optional(
        std::format("Couldn't create bind server to port: {}. error: {}", port,
                    std::system_category().message(errno)));
  }

  logzy::trace("Server socket bound");

  if (::listen(fd_, MAX_CONNECTIONS) != 0) {
    return std::optional(std::format("Listen failed. err: {}",
                                     std::system_category().message(errno)));
  }

  logzy::trace("Server listening at port: {}", port);
  return std::nullopt;
}
[[nodiscard]] auto TcpServer::accept() const
    -> std::expected<TcpSocket, std::string> {
  sockaddr_in clientAddr{};
  socklen_t clientLen = sizeof(clientAddr);

  logzy::trace("Waiting for connections");

  const int clientFd =
      ::accept(fd_, reinterpret_cast<sockaddr *>(&clientAddr), // NOLINT
               &clientLen);

  if (clientFd < 0) {
    return std::unexpected(std::format("Accept failed. {}",
                                       std::system_category().message(errno)));
  }

  std::expected<TcpSocket, std::string> socket{TcpSocket{}};
  socket->fd_ = clientFd;

  logzy::trace("New client accepted");
  return socket;
}
} // namespace network
