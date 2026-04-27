
#include "client/application.hpp"
#include "client/cli.hpp"
#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "crypto/aes.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "imgui.h"
#include "network/network.hpp"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "ui/window.hpp"
#include <GLFW/glfw3.h>
#include <cstdlib>
#include <logzy/formatters.hpp>
#include <logzy/logzy.hpp>

#include <cppli/cppli.hpp>

namespace {

enum class AppStage : std::uint8_t {
  GeneratingID,
  ObtainCertificate,
  Registered,
  Authenticated,
};

constexpr auto toString(AppStage stage) noexcept -> const char * {

  switch (stage) {
  case AppStage::GeneratingID:
    return "Generating ID";
  case AppStage::ObtainCertificate:
    return "Obtaining Certificate";
  case AppStage::Registered:
    return "Registered";
  case AppStage::Authenticated:
    return "Authenticated";
    break;
  }

  return "unreachable";
}

struct AppState {
  static_string<32> clientName;
  crypto::Hash32 id{};
  bool idGenerated{false};
  std::vector<std::string> errors;
  AppStage stage{AppStage::GeneratingID};
  crypto::Aes256 sessionKey{};
  crypto::X509Certificate clientCertificate;
  std::vector<std::string> sentMessages;
  std::vector<std::string> serverResponses;
  network::TcpSocket serverSocket;
  bool useFakeCertificate{false};
};

void sendData(std::string_view data, network::TcpSocket &serverSocket,
              AppState &state) {
  logzy::debug("Encrytping data with session key.");
  logzy::info("Sending message: {}", data);

  std::string encryptedData;
  if (auto encrypted = crypto::encryptAndEncode(data, state.sessionKey)) {
    encryptedData = std::move(*encrypted);
  } else {
    logzy::error("Couldn't encrypt data with session key. {}",
                 encrypted.error());
    return;
  }
  logzy::info("Encrypted and encoded data: {}", encryptedData);
  logzy::info("Sending encrtypted data to server.");
  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::DataRequest,
                          .payload = {{"data", encryptedData}}})) {
    logzy::error("Couldn't send data. {}", *err);
    return;
  }

  state.sentMessages.emplace_back(data);
  logzy::info("Waiting for response from server");

  auto response =
      network::expectPacket(serverSocket, network::PacketType::DataResponse);

  const auto receivedData = response->value("data", std::string_view{""});

  if (data.empty()) {
    logzy::error("Server returned no data.");
    return;
  }

  logzy::info("Server replied with encoded: {}", receivedData);

  if (auto decodedResult =
          crypto::decodeAndDecrypt(receivedData, state.sessionKey)) {
    logzy::info("Decoded data = {}. Size=  {}", *decodedResult,
                decodedResult->size());
    std::ranges::replace(*decodedResult, '\0', ' ');
    state.serverResponses.emplace_back(std::move(*decodedResult));
  }
}

void connectToServer(AppState &state, const std::string &host,
                     std::uint16_t port) {
  auto serverSocket = network::connectTo(host, port, "Server");
  if (!serverSocket) {
    logzy::error("Couldn't conneect to server. {}", serverSocket.error());
    state.errors.emplace_back(
        std::format("Couldn't conneect to server. {}", serverSocket.error()));
  }
  state.serverSocket = std::move(*serverSocket);
}

void baseUi(AppState &state, cli::client::ClientArguments &args) {
  ImGui::Text("Server Address: %s:%hd", args.serverIp.c_str(), args.serverPort);
  ImGui::Text("TTP Address: %s:%hd", args.ttpIp.c_str(), args.ttpPort);
  ImGui::Text("Connected to server: %s",
              state.serverSocket.isHealthy() ? "yes" : "no");
  if (!state.serverSocket.isHealthy()) {
    ImGui::SameLine();
    if (ImGui::Button("Connect")) {
      connectToServer(state, args.serverIp, args.serverPort);
    }
  }
  ImGui::Text("User ID: %s", (state.idGenerated)
                                 ? crypto::hashToHex(state.id).c_str()
                                 : "Not generated");
  ImGui::Separator();
  ImGui::Text("Current application stage: %s", toString(state.stage));
}

void generateIdUi(AppState &state) {
  if (!ImGui::Button("Generate ID")) {
    return;
  }

  logzy::info("Generating user ID");

  auto id = crypto::generateRandomId("UserSeed");
  if (!id) {
    state.errors.emplace_back(
        std::format("Couldn't generate user id: {}", id.error()));
  }

  logzy::info("User id: {}", crypto::hashToHex(state.id));
  state.id = *id;
  state.stage = AppStage::ObtainCertificate;
  state.idGenerated = true;
}

void obtainCertificateUi(AppState &state,
                         const cli::client::ClientArguments &args,
                         crypto::RsaKeyPair &clientKey,
                         protocol::TtpData &ttpData) {

  if (!ImGui::Button("Obtain certificate from TTP")) {
    return;
  }

  logzy::info("Connecting to TTP");

  auto ttpSocket =
      network::connectTo(args.ttpIp, args.ttpPort, "Trusted third party");
  if (!ttpSocket) {
    logzy::error("Connecting to TTP failed. {}", ttpSocket.error());
    state.errors.emplace_back("Couldn't connect to TTP");
    return;
  }

  logzy::info("Connected");

  auto cert = protocol::obtainCertificate(
      *ttpSocket, crypto::hashToHex(state.id), clientKey, ttpData);

  if (!cert) {
    logzy::error("Couldn't obiatin certificate. {}", cert.error());
    state.errors.emplace_back("Couldn't obtain certificate.");
    return;
  }

  logzy::info("Obtained certificate");

  state.clientCertificate = std::move(*cert);
  state.stage = AppStage::Registered;
}

void authenticateUi(AppState &state, const cli::client::ClientArguments &args,
                    crypto::RsaKeyPair &clientKey, protocol::TtpData &ttpData,
                    crypto::X509Certificate &fakeCertificate) {
  ImGui::Checkbox("Use false certificate", &state.useFakeCertificate);

  if (!state.serverSocket.isHealthy()) {
    ImGui::Text("Please connect to the server first");
    return;
  }

  if (!ImGui::Button("Request service")) {
    return;
  }

  auto ttpSocket =
      network::connectTo(args.ttpIp, args.ttpPort, "Trusted third party");
  if (!ttpSocket) {
    logzy::error("Connecting to TTP failed. {}", ttpSocket.error());
    state.errors.emplace_back("Couldn't connect to TTP");
    return;
  }

  logzy::info("Initiating authentication with TTP");
  if (auto err =
          protocol::initiateAuthentication(*ttpSocket, state.clientCertificate,
                                           protocol::ClientRole::Requester)) {
    logzy::error("Couldn't initiate atuhentication with TTP. {}", *err);
    state.errors.emplace_back("Couldn't initiate authentication with TTP");
    return;
  }
  logzy::info("Initiated");

  crypto::X509Certificate *activeCertificate =
      (state.useFakeCertificate) ? &fakeCertificate : &state.clientCertificate;

  logzy::info("performing handshake");

  auto sessionKey =
      protocol::clientHandshake(state.serverSocket, *ttpSocket,
                                *activeCertificate, clientKey, ttpData.key);

  if (!sessionKey) {
    logzy::error("{}", sessionKey.error());
    state.errors.emplace_back(
        std::format("Couldn't perform handshake. {}", sessionKey.error()));
    return;
  }

  state.sessionKey = std::move(*sessionKey);
  state.stage = AppStage::Authenticated;
  logzy::info("Session key obtained.");
}

void authenticatedUi(AppState &state) {
  static std::string inputFieldText(256, '\0');
  ImGui::Text("Authenticated.");
  ImGui::InputText("Data to send", inputFieldText.data(),
                   inputFieldText.size());

  if (ImGui::Button("Send")) {
    sendData(std::string_view{inputFieldText.data(), // To not send the whole
                                                     // 256 byte string buffer.
                              strlen(inputFieldText.c_str())},
             state.serverSocket, state);
  }

  {
    ImGui::BeginChild("Messages that server responded to", ImVec2(0, 300),
                      ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_HorizontalScrollbar);

    size_t msgResponsePairs =
        std::min(state.sentMessages.size(), state.serverResponses.size());
    for (size_t i = 0; i < msgResponsePairs; ++i) {
      ImGui::TextColored({0.0f, 0.0f, 1.0f, 1.0f}, "%s",
                         state.sentMessages.at(i).c_str());
      ImGui::TextColored({0.0f, 1.0f, 0.0f, 1.0f}, "%s",
                         state.serverResponses.at(i).c_str());
    }
    ImGui::EndChild();
  }
}

void errorsUi(AppState &state) {
  if (ImGui::Button("Clear errors")) {
    state.errors.clear();
  }
  ImGui::Text("Errors:");
  ImGui::BeginChild("Errors", ImVec2(0, 100), ImGuiChildFlags_None,
                    ImGuiWindowFlags_HorizontalScrollbar);

  size_t msgResponsePairs =
      std::min(state.sentMessages.size(), state.serverResponses.size());
  for (const auto &error : state.errors) {
    ImGui::TextColored({1.0f, 0.0f, 0.0f, 1.0f}, "%s", error.c_str());
  }
  ImGui::EndChild();
}

} // namespace

auto main(int argc, char const *const *const argv) -> int {

  auto args =
      cli::parseCommandlineArgs<cli::client::ClientArguments>(argc, argv);
  if (!args) {
    return args.error();
  }

  AppContext ctx;
  AppState state{};

  if (auto ctxOpt = initialize()) {
    ctx = std::move(*ctxOpt);
  }

  auto ttpData = protocol::loadTtpData();
  if (!ttpData) {
    logzy::critical("Couldn't load TTP data. {}", ttpData.error());
    return EXIT_FAILURE;
  }

  logzy::info("Loaded ttp key");

  auto falseCertificate = crypto::X509Certificate::createSelfSignedCA(
      "False certificate", ctx.rsaKey);
  if (!falseCertificate) {
    logzy::critical("Couldnt generate false certificate");
    return EXIT_FAILURE;
  }

  bool useFakeCertificate = false;
  crypto::X509Certificate *activeCertificate = &state.clientCertificate;

  while (glfwWindowShouldClose(ctx.window) == 0) {
    if (!beginFrame(ctx)) {
      continue;
    }

    {
      auto fsWindow = FullScreenWindow("Window");

      baseUi(state, *args);

      switch (state.stage) {
      case AppStage::GeneratingID:
        generateIdUi(state);
        break;
      case AppStage::ObtainCertificate:
        obtainCertificateUi(state, *args, ctx.rsaKey, *ttpData);
        break;
      case AppStage::Registered:
        authenticateUi(state, *args, ctx.rsaKey, *ttpData, *falseCertificate);
        break;
      case AppStage::Authenticated:
        authenticatedUi(state);
        break;
      }

      ImGui::Separator();
      errorsUi(state);
    }

    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
