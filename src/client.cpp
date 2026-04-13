
#include "client/application.hpp"
#include "crypto.hpp"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "ui/window.hpp"
#include <GLFW/glfw3.h>
#include <cstdlib>
#include <logzy/logzy.hpp>

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

auto main() -> int {

  AppContext ctx;

  if (auto ctxOpt = initialize()) {
    ctx = *ctxOpt;
  } else {
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
    }

    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
