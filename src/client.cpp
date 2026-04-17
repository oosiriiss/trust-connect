
#include "client/application.hpp"
#include "common.hpp"
#include "crypto/crypto.hpp"
#include "crypto/rsa.hpp"
#include "imgui.h"
#include "network/packet.hpp"
#include "network/socket.hpp"
#include "ui/window.hpp"
#include <GLFW/glfw3.h>
#include <cstdlib>
#include <logzy/logzy.hpp>

#include <cppli/cppli.hpp>

namespace {

enum class AppStage {
  GeneratingID,
  Registering,
  Registered,

};

struct AppState {
  crypto::Hash32 id{};
  AppStage stage{AppStage::GeneratingID};
  std::string errorMessage;
};
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

        if (auto keyOpt = registerWithTtp(ttpSocket, state.id, publicKeyPem)) {
          ttpPublicKey = std::move(*keyOpt);
        } else {
          break;
        }
        logzy::info("Successfully registerd with TTP");
        state.stage = AppStage::Registered;

      } break;

      case AppStage::Registered: {

        if (!state.errorMessage.empty()) {
          ImGui::Text("Error: %s", state.errorMessage.c_str());
        }

        if (ImGui::Button("Send data")) {
          nlohmann::json payload;
          payload["value"] = "Hello";
          if (auto err = serverSocket.send(
                  network::Packet{.type = network::PacketType::RegisterRequest,
                                  .payload = std::move(payload)})) {
            logzy::error("Couldn't send data: {}", *err);
          }
        }

        if (ImGui::Button("Receive data")) {
          if (auto received = serverSocket.receive()) {
            logzy::info("Received: {}", *received);

            switch (received->type) {
            case network::PacketType::RegisterResponse:
              break;
            case network::PacketType::CloseConnection:
              logzy::info("Client disconnected");
              glfwSetWindowShouldClose(ctx.window, 1);
              break;
            default:
              logzy::error("Invalid packet received: {}", received->type);
              break;
            }

          } else {
            logzy::error("Couldn't receive message from server: {}",
                         received.error());
          }
        }
      } break;
      }
    }
    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
