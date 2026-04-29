
#include "network/socket.hpp"
#include "debug_utils.hpp"
#include "logzy/logzy.hpp"
#include "network/network.hpp"
#include "network/packet.hpp"
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <cerrno>
#include <expected>
#include <filesystem>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <pthread.h>
#include <sys/socket.h>
#include <system_error>

namespace network {

namespace {
enum class ReadResult : std::uint8_t { Ok, WouldBlock, ConnectionClosed };

auto readExact(int fd, const size_t toRead, std::string &out)
    -> std::expected<ReadResult, std::string> {

  out.clear();

  size_t totalRead = 0;

  std::array<char, 1024> buff{};

  while (totalRead < toRead) {

    size_t currentReadMaxBytes = std::min(toRead - totalRead, buff.size());

    ssize_t read = recv(fd, buff.data(), currentReadMaxBytes, 0);

    if (read > 0) {
      totalRead += read;
      out.append(std::string_view{buff.data(), static_cast<size_t>(read)});
    }

    if (read == 0) {
      return ReadResult::ConnectionClosed;
    }

    if (read < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return ReadResult::WouldBlock;
      }
      return std::unexpected(std::format(
          "Receive failed. error: {}", std::system_category().message(errno)));
    }
  }

  return ReadResult::Ok;
}

void closeSocket(int &fd) {
  if (fd == INVALID_SOCKET) {
    return;
  }

  if (shutdown(fd, SHUT_RDWR) != 0) {
    logzy::warn("Closing socket {} failed", fd);
  }
  fd = INVALID_SOCKET;
}
} // namespace

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

  auto hostResolved = ipFromHost(host);
  if (!hostResolved) {
    return std::unexpected(
        std::format("Couldn't resolve host name. {}", hostResolved.error()));
  }

  inet_pton(addr.sin_family, hostResolved->c_str(), &addr.sin_addr);

  std::expected<TcpSocket, std::string> socket{TcpSocket{}};

  socket->fd_ = ::socket(addr.sin_family, SOCK_STREAM, 0);

  if (socket->fd_ < 0) {
    return std::unexpected(
        std::format("Couldnt' create a socket for host {} IP='{}:{}'", host,
                    *hostResolved, port));
  }

  if (::connect(socket->fd_,
                reinterpret_cast<struct sockaddr *>(&addr), // NOLINT
                sizeof(addr)) != 0) {
    return std::unexpected(std::format("Couldn't connect to host {} IP='{}:{}'",
                                       host, *hostResolved, port));
  }

  logzy::trace("Client connected to host {} IP='{}:{}'", host, *hostResolved,
               port);
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
  logzy::debug("Receiving...");

  std::string buffer;

  auto headerBytesResult = readExact(fd_, HEADER_SIZE_BYTES, buffer);
  if (!headerBytesResult) {
    return std::unexpected(std::move(headerBytesResult).error());
  }

  if (*headerBytesResult == ReadResult::ConnectionClosed) {
    return Packet{.type = PacketType::CloseConnection};
  }
  if (*headerBytesResult == ReadResult::WouldBlock) {
    return Packet{.type = PacketType::TimedOut};
  }

  logzy::trace("Read header");

  auto header = decodeHeader(std::span{buffer.data(), HEADER_SIZE_BYTES});
  if (!header) {
    return std::unexpected(std::move(header).error());
  }

  logzy::trace("Decoded header");
  auto payloadBytesResult = readExact(fd_, header->length, buffer);
  if (!payloadBytesResult) {
    return std::unexpected(std::move(payloadBytesResult).error());
  }

  if (*payloadBytesResult == ReadResult::ConnectionClosed) {
    return Packet{.type = PacketType::CloseConnection};
  }
  if (*payloadBytesResult == ReadResult::WouldBlock) {
    return Packet{.type = PacketType::TimedOut};
  }

  logzy::trace("Read payload");
  auto payload = decodePayload(buffer);
  if (!payload) {
    return std::unexpected(std::move(payload).error());
  }

  logzy::debug("Received whole packet");

  return std::expected<Packet, std::string>{
      Packet{
          .type = header->type,
          .payload = std::move(payload).value(),
      },
  };
}

auto TcpSocket::setTimeout(std::uint32_t millis) noexcept
    -> std::optional<std::string> {

  const std::uint32_t seconds = millis / 1000;
  const std::uint32_t micros = (millis % 1000) * 1000;

  struct timeval t{.tv_sec = seconds, .tv_usec = micros};

  if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO_NEW, &t, sizeof(t)) < 0) {
    return std::optional{
        std::format("Couldnt' set socket's receive timeout. {}",
                    std::system_category().message(errno))};
  }
  return std::nullopt;
}
auto TcpSocket::disableTimeout() noexcept -> std::optional<std::string> {
  return setTimeout(0);
}

auto TcpSocket::isHealthy() const noexcept -> bool {

  if (fd_ < 0) {
    return false;
  }

  int err = 0;
  socklen_t errLen = sizeof(err);

  int res = getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &errLen);

  const bool sockOptErr = res != 0;
  const bool hasError = err != 0;
  if (sockOptErr || hasError) {
    return false;
  }

  char buf = 0;
  ssize_t peekRes = recv(fd_, &buf, 1, MSG_PEEK | MSG_DONTWAIT);

  const bool gracefullyClosed = peekRes == 0;

  if (gracefullyClosed) {
    return false;
  }

  if (peekRes < 0) {
    // EAGAIN AND EWOULDBLOCK are ok
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      return false;
    }
  }
  return true;
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

  if (::listen(fd_, SOMAXCONN) != 0) {
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
