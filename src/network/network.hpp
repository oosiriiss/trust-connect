#pragma once

#include "network/packet.hpp"
#include "network/socket.hpp"
#include "nlohmann/json_fwd.hpp"
#include <expected>
namespace network {

namespace keys {
constexpr std::string_view ErrorMessage = "error_message";
} // namespace keys

auto ipFromHost(const std::string &host)
    -> std::expected<std::string, std::string>;

/**
 * @brief Creates a TCP connection to the @p host @p:@p port @p
 *
 * This function is the same as TcpSocket::connect(), but it logs progress to
 * stdout
 *
 * @param host IP address of the target
 * @param port Port of the target
 * @param targetName Friendly name used for logging
 *
 * @return
 * - Success: TcpSocket connected to the given @p host @p:@p port @p
 * - Error: String error message
 */
[[nodiscard]] auto connectTo(const std::string &host, std::uint16_t port,
                             std::string_view targetName)
    -> std::expected<TcpSocket, std::string>;

/**
 * @brief receives a Packet from @p socket @p of @p expectedType @p and returns
 * its payload
 *
 * If received packet is PacketType::ErrorMessage (and it was not passed
 * as @p expectedType @p) then it also unwraps it's error value and returns it
 * as error string
 *
 * @param socket Socket to receive from
 * @param expectedType Expected packet type
 *
 * @return
 * - Success: Returns received packet's payload
 * - Error: String error message.
 *
 *  @ref PacketType
 */
[[nodiscard]] auto expectPacket(TcpSocket &socket, PacketType expectedType)
    -> std::expected<nlohmann::json, std::string>;

/**
 * @brief Sends error message @p errorMessage @p to @p socket @p
 *
 * Automatically wraps the @p errorMessage @p in Packet with
 * PacketType::ErrorMessage This functions handles the possible send error and
 * logs it as an error.
 *
 * @param socket Socket to send message to
 * @param errorMessage error message to send
 *
 * @ref TcpSocket::send()
 * @ref PacketType
 */
void sendError(TcpSocket &socket, std::string_view errorMessage);

} // namespace network
