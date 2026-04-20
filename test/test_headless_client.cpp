#include "common.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include <cstdlib>
#include <logzy/formatters.hpp>
#include <logzy/logzy.hpp>
#include <print>

#include <cppli/cppli.hpp>

namespace {

namespace {
enum class OptionKey : std::uint_fast8_t {
  ServerIp,
  ServerPort,
  TtpIp,
  TtpPort,
  Help
};

struct AppContext {
  std::string serverIp{network::DEFAULT_SERVER_IP};
  std::string ttpIp{network::DEFAULT_TTP_IP};
  std::uint16_t serverPort{network::DEFAULT_SERVER_PORT};
  std::uint16_t ttpPort{network::DEFAULT_TTP_PORT};
  crypto::RsaKeyPair rsaKey{};
};

auto getOptions() {
  cppli::OptionContainer<OptionKey> options;

  options.addOption(
      OptionKey::ServerIp,
      cppli::Option{.firstName = "-s",
                    .secondName = "--server-ip",
                    .description =
                        "Specifies ip at which the server is located",
                    .needsValue = true});
  options.addOption(
      OptionKey::ServerPort,
      cppli::Option{.firstName = "-p",
                    .secondName = "--server-port",
                    .description = "Specifies port at which the TTP is located",
                    .needsValue = true});
  options.addOption(
      OptionKey::TtpIp,
      cppli::Option{.firstName = "-S",
                    .secondName = "--ttp-ip",
                    .description = "Specifies ip at which the TTP is located",
                    .needsValue = true});
  options.addOption(
      OptionKey::TtpPort,
      cppli::Option{.firstName = "-P",
                    .secondName = "--ttp-port",
                    .description = "Specifies port at which the TTP is located",
                    .needsValue = true});
  options.addOption(OptionKey::Help,
                    cppli::Option{.firstName = "-h",
                                  .secondName = "--help",
                                  .description = "Displays the help message",
                                  .needsValue = false});

  return options;
}

auto parseCommandlineArgs(AppContext &ctx, int argc,
                          char const *const *const argv) -> bool {

  cppli::OptionContainer<OptionKey> options = getOptions();
  cppli::ParseResult<OptionKey> result;
  try {
    result = cppli::parseArguments(argc, argv, options);
  } catch (const std::exception &exc) {
    std::println("Couldn't parse arguments: {}", exc.what());
    return true;
  }

  // Help terminates
  if (result.options.contains(OptionKey::Help)) {
    std::println("{}", cppli::createHelp(options, "ttp-client"));
    return true;
  }

  if (auto serverIp = result.options.find(OptionKey::ServerIp);
      serverIp != result.options.end()) {
    ctx.serverIp = serverIp->second.value.value();
  }
  if (auto serverPort = result.options.find(OptionKey::ServerPort);
      serverPort != result.options.end()) {
    ctx.serverPort = std::stoi(std::string(serverPort->second.value.value()));
  }

  if (auto ttpIp = result.options.find(OptionKey::TtpIp);
      ttpIp != result.options.end()) {
    ctx.ttpIp = ttpIp->second.value.value();
  }
  if (auto ttpPort = result.options.find(OptionKey::TtpPort);
      ttpPort != result.options.end()) {
    ctx.ttpPort = std::stoi(std::string(ttpPort->second.value.value()));
  }

  return false;
}

[[nodiscard]] auto initialize(int argc, char const *const *const argv,
                              bool &outTerminate) noexcept
    -> std::optional<AppContext> {
  std::optional<AppContext> ctx{AppContext{}};

  outTerminate = parseCommandlineArgs(*ctx, argc, argv);

  if (outTerminate) {
    return std::nullopt;
  }

  if (auto keyRes = crypto::RsaKeyPair::generate()) {
    ctx->rsaKey = std::move(*keyRes);
  } else {
    logzy::critical("Couldn't create RSA key pair: {}", keyRes.error());
    return std::nullopt;
  }

  return ctx;
}

} // namespace

enum class AppStage {
  GeneratingID,
  Registering,
  Registered,
  Authenticated,

};

struct AppState {
  static_string<32> clientName;
  crypto::Hash32 id{};
  std::string errorMessage;
  AppStage stage{AppStage::GeneratingID};
  crypto::Aes256 sessionKey{};
  std::vector<std::string> sentMessages;
  std::vector<std::string> serverResponses;
  crypto::X509Certificate clientCertificate;
  crypto::X509Certificate ttpCertificate;
};

void estabilishSession(network::TcpSocket &serverSocket,
                       network::TcpSocket &ttpSocket, AppState &state,
                       const crypto::RsaKeyPair &clientKey,
                       const crypto::RsaKeyPair &ttpPublicKey) {

  logzy::debug("Requesting service from server");
  logzy::trace("Encrypting user id with ttp's public key");

  std::string userCertPem;
  if (auto certResult = state.clientCertificate.toPem()) {
    userCertPem = std::move(*certResult);
  } else {
    logzy::error("Couldn't encrypt user's id. {}", certResult.error());
    return;
  }

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::ServiceRequest,
                          .payload = {
                              {"user_cert_pem", userCertPem},
                          }})) {

    logzy::error("ServiceRequest failed. {}", *err);
    return;
  }

  logzy::debug("Waiting for TTP response forwarded by server.");

  // TODO :: Add certificates

  if (auto packet = serverSocket.receive()) {
    if (packet->type != network::PacketType::ServerAuthOk) {
      logzy::error(
          "Received wrong type of packet. {} and expected ServerAuthResponse",
          packet->type);
      return;
    }
    logzy::trace("Recevied ServerAuthOk");

  } else {
    logzy::error("Receiving failed. {}", packet.error());
    return;
  }

  // User  auth redirect happens here

  if (auto packet = ttpSocket.receive()) {
    if (packet->type != network::PacketType::UserAuthRedirect) {
      logzy::error(
          "Received wrong type of packet. {} and expected UserAuthRedirect",
          packet->type);
      return;
    }

  } else {
    logzy::error("Receving failed. {}", packet.error());
    return;
  }

  logzy::trace("Sending user auth data to TTP");

  if (auto err = ttpSocket.send(
          network::Packet{.type = network::PacketType::UserAuthDataSubmit,
                          .payload = {
                              {"user_cert_pem", userCertPem},

                          }})) {
    logzy::error("Couldn't send user auth data to TTP. {}", *err);
    return;
  }

  // Server should notify the client that its ok and pass the sssion key

  if (auto authResult = serverSocket.receive()) {
    if (authResult->type != network::PacketType::UserAuthOk) {
      logzy::error("User auth failed. expected UserAuthOk packet but got {}",
                   authResult->type);
      return;
    }

    const auto clientSessionKey =
        authResult->payload.value("client_session_key", std::string_view{""});

    if (clientSessionKey.empty()) {
      logzy::error(
          "Server didn't send AES 256 GCM session key with UserAuthOk packet.");
      return;
    }

    if (auto keyString =
            crypto::decodeAndDecrypt(clientSessionKey, clientKey)) {

      if (auto aes = crypto::Aes256::fromKey(*keyString)) {
        state.sessionKey = std::move(*aes);
        state.stage = AppStage::Authenticated;
      } else {
        logzy::error("Couldnt create AES 256 GCM form key '{}'. {}", *keyString,
                     aes.error());
        return;
      }
    } else {
      logzy::error("Couldn't decode and decrypt aes key. {}",
                   keyString.error());
      return;
    }

    logzy::info("Session key: {}", state.sessionKey.getRawKey());

  } else {
    logzy::error("Receiving from clietn failed. {}", authResult.error());
  }
}

auto sendData(std::string_view data, network::TcpSocket &serverSocket,
              AppState &state) -> std::string {
  logzy::debug("Encrytping data with session key.");

  std::string encryptedData;
  if (auto encrypted = crypto::encryptAndEncode(data, state.sessionKey)) {
    encryptedData = std::move(*encrypted);
  } else {
    logzy::error("Couldn't encrypt data with session key. {}",
                 encrypted.error());
    return "1";
  }

  logzy::debug("Sending encrtypted data to server.");

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::DataRequest,
                          .payload = {{"data", encryptedData}}})) {
    logzy::error("Couldn't send data. {}", *err);
    return "2";
  }

  logzy::debug("Waiting for response");

  if (auto resp = serverSocket.receive()) {

    if (resp->type != network::PacketType::DataResponse) {
      logzy::error("Wrong resposne packet received '{}. Expected DataResponse",
                   resp->type);
      return "3";
    }

    const auto data = resp->payload.value("data", std::string_view{""});
    if (data.empty()) {
      logzy::error("Server returned no data.");
      return "4";
    }
    if (auto decodedResult = crypto::decodeAndDecrypt(data, state.sessionKey)) {
      logzy::info("Decoded data = {}. Size=  {}", *decodedResult,
                  decodedResult->size());
      std::ranges::replace(*decodedResult, '\0', ' ');
      return *decodedResult;
    } else {
      logzy::error("Couldn't decode data. {}", decodedResult.error());
    }

  } else {
    logzy::error("Couldn't receive response from server. {}", resp.error());
  }

  return "5";
}

} // namespace

auto main(int argc, char const *const *const argv) -> int {
  AppContext ctx;

  bool terminate = false;

  if (auto ctxOpt = initialize(argc, argv, terminate)) {
    ctx = std::move(*ctxOpt);
  } else {
    if (terminate) {
      return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
  }

  if (auto publicKey = ctx.rsaKey.publicKeyPem()) {
    logzy::info("Public key PEM:\n{}", *publicKey);
  } else {
    logzy::warn("Couldnt generate PEM for public key. {}", publicKey.error());
  }

  if (auto privateKey = ctx.rsaKey.privateKeyPem()) {
    logzy::info("Private key PEM:\n{}", *privateKey);
  } else {
    logzy::warn("Couldnt generate PEM for privateKey key. {}",
                privateKey.error());
  }

  network::TcpSocket serverSocket;
  if (!connectTo(serverSocket, ctx.serverIp, ctx.serverPort, "Server")) {
    return EXIT_FAILURE;
  }

  network::TcpSocket ttpSocket;
  if (!connectTo(ttpSocket, ctx.ttpIp, ctx.ttpPort, "Trusted third party")) {
    return EXIT_FAILURE;
  }

  crypto::RsaKeyPair ttpPublicKey;

  AppState state{};

  if (auto idExp = crypto::generateRandomId("UserSeed")) {
    state.id = *idExp;
    logzy::info("Created user id: {}", crypto::hashToHex(state.id));
    state.stage = AppStage::Registering;
  } else {
    idExp.error();
    state.errorMessage =
        std::format("Couldn't generate user id: {}", idExp.error());
  }

  logzy::trace("Beggining registering with TTP");

  std::string publicKeyPem;
  logzy::trace("Generating public key PEM to send to TTP");

  if (auto keyPemResult = ctx.rsaKey.publicKeyPem()) {
    publicKeyPem = std::move(*keyPemResult);
  } else {
    logzy::error("couldn't generate public key PEM from key");
    return EXIT_FAILURE;
  }

  if (!registerWithTtp(
          ttpSocket,
          std::format("Test clietn with id {}", crypto::hashToHex(state.id)),
          state.id, publicKeyPem, state.clientCertificate, state.ttpCertificate,
          ttpPublicKey)) {
    return EXIT_FAILURE;
  }
  logzy::info("Successfully registerd with TTP");
  state.stage = AppStage::Registered;

  estabilishSession(serverSocket, ttpSocket, state, ctx.rsaKey, ttpPublicKey);

  std::string dataToSend("Hello from test client");

  std::string returned =
      sendData(std::string_view{dataToSend.data(), // To not send the whole
                                                   // 256 byte string buffer.
                                strlen(dataToSend.c_str())},
               serverSocket, state);

  const char *expected = "Hello from test client Hello, bonus from server";
  if (returned != "Hello from test client Hello, bonus from server") {
    logzy::error("Received '{}' and expected '{}'", returned, expected);
  }
  logzy::info("Returned data matches.");

  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");
  logzy::info("SUCCESS !!!");

  return 0;
}
