
#include "client/application.hpp"
#include "client/cli.hpp"
#include "common/cli.hpp"
#include "common/protocol.hpp"
#include "crypto/aes.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
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

enum class AppStage {
  GeneratingID,
  ObtainCertificate,
  Registered,
  Authenticated,

};

struct AppState {
  static_string<32> clientName;
  crypto::Hash32 id{};
  std::string errorMessage;
  AppStage stage{AppStage::GeneratingID};
  crypto::Aes256 sessionKey{};
  crypto::X509Certificate clientCertificate;
  std::vector<std::string> sentMessages;
  std::vector<std::string> serverResponses;
};

void sendData(std::string_view data, network::TcpSocket &serverSocket,
              AppState &state) {
  logzy::debug("Encrytping data with session key.");

  std::string encryptedData;
  if (auto encrypted = crypto::encryptAndEncode(data, state.sessionKey)) {
    encryptedData = std::move(*encrypted);
  } else {
    logzy::error("Couldn't encrypt data with session key. {}",
                 encrypted.error());
    return;
  }

  logzy::debug("Sending encrtypted data to server.");

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::DataRequest,
                          .payload = {{"data", encryptedData}}})) {
    logzy::error("Couldn't send data. {}", *err);
    return;
  }

  state.sentMessages.emplace_back(data);

  logzy::debug("Waiting for response");

  if (auto resp = serverSocket.receive()) {

    if (resp->type != network::PacketType::DataResponse) {
      logzy::error("Wrong resposne packet received '{}. Expected DataResponse",
                   resp->type);
      return;
    }

    const auto data = resp->payload.value("data", std::string_view{""});
    if (data.empty()) {
      logzy::error("Server returned no data.");
      return;
    }
    if (auto decodedResult = crypto::decodeAndDecrypt(data, state.sessionKey)) {
      logzy::info("Decoded data = {}. Size=  {}", *decodedResult,
                  decodedResult->size());
      std::ranges::replace(*decodedResult, '\0', ' ');
      state.serverResponses.emplace_back(std::move(*decodedResult));
    } else {
      logzy::error("Couldn't decode data. {}", decodedResult.error());
    }

  } else {
    logzy::error("Couldn't receive response from server. {}", resp.error());
  }
}

} // namespace

auto main(int argc, char const *const *const argv) -> int {

  auto args =
      cli::parseCommandlineArgs<cli::client::ClientArguments>(argc, argv);
  if (!args) {
    return args.error();
  }

  AppContext ctx;

  if (auto ctxOpt = initialize()) {
    ctx = std::move(*ctxOpt);
  }

  auto serverSocket =
      network::connectTo(args->serverIp, args->serverPort, "Server");

  if (!serverSocket) {
    logzy::critical("Couldn't conneect to server. {}", serverSocket.error());
    return EXIT_FAILURE;
  }

  auto ttpSocket =
      network::connectTo(args->ttpIp, args->ttpPort, "Trusted third party");

  if (!ttpSocket) {
    logzy::critical("Couldn't conneect to ttp. {}", ttpSocket.error());
    return EXIT_FAILURE;
  }

  AppState state{};
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

      switch (state.stage) {
      case AppStage::GeneratingID: {
        if (ImGui::Button("Generate ID")) {
          if (auto idExp = crypto::generateRandomId("UserSeed")) {
            state.id = *idExp;
            logzy::info("Created user id: {}", crypto::hashToHex(state.id));
            state.stage = AppStage::ObtainCertificate;
          } else {
            idExp.error();
            state.errorMessage =
                std::format("Couldn't generate user id: {}", idExp.error());
          }
        }
      } break;

      case AppStage::ObtainCertificate: {
        ImGui::Text("User ID: %s", crypto::hashToHex(state.id).c_str());

        if (!ImGui::Button("Obtain certificate from TTP")) {
          break;
        }

        if (auto cert = protocol::obtainCertificate(*ttpSocket,
                                                    crypto::hashToHex(state.id),
                                                    ctx.rsaKey, *ttpData)) {
          state.clientCertificate = std::move(*cert);
          state.stage = AppStage::Registered;
        } else {
          logzy::error("Couldnt register. {}", cert.error());
        }
        logzy::info("Successfully registerd with TTP");
        state.stage = AppStage::Registered;

      } break;

      case AppStage::Registered: {
        ImGui::Checkbox("Use false certificate", &useFakeCertificate);

        if (!ImGui::Button("Request service")) {
          break;
        }

        ttpSocket = network::connectTo(args->ttpIp, args->ttpPort,
                                       "Trusted third party");
        if (!ttpSocket) {
          logzy::error("Connecting to TTP failed. {}", ttpSocket.error());
          break;
        }

        if (auto err = protocol::initiateAuthentication(
                *ttpSocket, state.clientCertificate,
                protocol::ClientRole::Requester)) {
          logzy::error("Couldn't initiate atuhentication with TTP. {}", *err);
          break;
        }

        crypto::X509Certificate *activeCertificate =
            (useFakeCertificate) ? &falseCertificate.value()
                                 : &state.clientCertificate;

        if (auto sessionKey = protocol::clientHandshake(
                *serverSocket, *ttpSocket, *activeCertificate, ctx.rsaKey,
                ttpData->key)) {
          state.sessionKey = std::move(*sessionKey);
          state.stage = AppStage::Authenticated;
          logzy::info("Session key obtained.");
        } else {
          logzy::error("{}", sessionKey.error());
          state.errorMessage =
              std::format("Authentication failed. {}", sessionKey.error());
        }

      } break;
      case AppStage::Authenticated: {
        static std::string inputFieldText(256, '\0');
        ImGui::Text("Authenticated.");
        ImGui::InputText("Data to send", inputFieldText.data(),
                         inputFieldText.size());

        if (ImGui::Button("Send")) {
          sendData(
              std::string_view{inputFieldText.data(), // To not send the whole
                                                      // 256 byte string buffer.
                               strlen(inputFieldText.c_str())},
              *serverSocket, state);
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
      } break;
      }

      // Error message is visible in all screens
      ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s",
                         state.errorMessage.c_str());
    }
    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
