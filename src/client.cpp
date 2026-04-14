
#include "client/application.hpp"
#include "crypto.hpp"
#include "imgui.h"
#include "network.hpp"
#include "ui/window.hpp"
#include <GLFW/glfw3.h>
#include <cstdlib>
#include <logzy/logzy.hpp>

#include <cppli/cppli.hpp>

namespace {

enum class AppStage {
  GeneratingID,
  Registering,

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
    ctx = *ctxOpt;
  } else {
    if (terminate) {
      return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
  }

  logzy::trace("Connecting to server: {}:{}", ctx.serverIp, ctx.serverPort);
  network::TcpSocket clientSocket;
  if (auto socketExp =
          network::TcpSocket::connect(ctx.serverIp, ctx.serverPort)) {

    clientSocket = std::move(*socketExp);

  } else {
    logzy::critical("Couldn't create client socket. Reason: {}",
                    socketExp.error());
    return EXIT_FAILURE;
  }

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
        std::string userIdString = crypto::hashToHex(state.id);
        ImGui::Text("User ID: %s", userIdString.c_str());
      } break;
      }

      if (!state.errorMessage.empty()) {
        ImGui::Text("Error: %s", state.errorMessage.c_str());
      }

      if (ImGui::Button("Send data")) {
        if (auto err = clientSocket.send("Hello")) {
          logzy::error("Couldn't send data: {}", *err);
        }
      }

      if (ImGui::Button("Receive data")) {
        if (auto received = clientSocket.receive()) {
          logzy::info("Received: {}", *received);

          if (received->empty()) {
            logzy::info("Client disconnected");
            break;
          }
        } else {
          logzy::error("Couldn't receive message from server: {}",
                       received.error());
        }
      }
    }

    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
