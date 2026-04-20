
#include "client/application.hpp"
#include "common.hpp"
#include "crypto/aes.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/rsa.hpp"
#include "crypto/x509.hpp"
#include "imgui.h"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "ui/window.hpp"
#include <GLFW/glfw3.h>
#include <cstdlib>
#include <ios>
#include <logzy/formatters.hpp>
#include <logzy/logzy.hpp>

#include <cppli/cppli.hpp>

namespace {

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
  crypto::X509Certificate clientCertificate;
  crypto::X509Certificate ttpCertificate;
  std::vector<std::string> sentMessages;
  std::vector<std::string> serverResponses;
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
            state.stage = AppStage::Registering;
          } else {
            idExp.error();
            state.errorMessage =
                std::format("Couldn't generate user id: {}", idExp.error());
          }
        }
      } break;

      case AppStage::Registering: {
        ImGui::Text("User ID: %s", crypto::hashToHex(state.id).c_str());

        if (!ImGui::Button("Register with TTP")) {
          break;
        }
        logzy::trace("Beggining registering with TTP");

        std::string publicKeyPem;
        logzy::trace("Generating public key PEM to send to TTP");

        if (auto keyPemResult = ctx.rsaKey.publicKeyPem()) {
          publicKeyPem = std::move(*keyPemResult);
        } else {
          logzy::error("couldn't generate public key PEM from key");
          break;
        }

        if (!registerWithTtp(
                ttpSocket,
                std::format("Client with id {}", crypto::hashToHex(state.id)),
                state.id, publicKeyPem, state.clientCertificate,
                state.ttpCertificate, ttpPublicKey)) {
          break;
        }
        logzy::info("Successfully registerd with TTP");
        state.stage = AppStage::Registered;

      } break;

      case AppStage::Registered: {

        if (ImGui::Button("Request service")) {
          estabilishSession(serverSocket, ttpSocket, state, ctx.rsaKey,
                            ttpPublicKey);
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
              serverSocket, state);
        }

        {
          ImGui::BeginChild("Messages that server responded to", ImVec2(0, 300),
                            true, ImGuiWindowFlags_HorizontalScrollbar);

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
    }
    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
