#include "crypto/rsa.hpp"
#define GLFW_INCLUDE_NONE
#include "GLFW/glfw3.h"
#include "application.hpp"
#include "glad.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "logzy/logzy.hpp"
#include <optional>

constexpr const char *GLSL_VERSION = "#version 330 core";
constexpr int WINDOW_WIDTH = 800;
constexpr int WINDOW_HEIGHT = 800;

static void glfwErrorCallback(int /*error*/, const char *description) {
  logzy::error("GLFW error: {}", description);
}

static void glfwKeyCallback(GLFWwindow *window, int key, int /*scancode*/,
                            int action, int /*mods*/) {
  if (key == GLFW_KEY_ESCAPE && action == GLFW_PRESS) {
    glfwSetWindowShouldClose(window, GLFW_TRUE);
  }
}

namespace {} // namespace

[[nodiscard]] auto initialize() noexcept -> std::optional<AppContext> {
  std::optional<AppContext> ctx{AppContext{}};

  glfwSetErrorCallback(glfwErrorCallback);
  if (glfwInit() == 0) {
    logzy::critical("Couldnt' initialize glfw");
    return std::nullopt;
  }

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+
  float mainScale = ImGui_ImplGlfw_GetContentScaleForMonitor(
      glfwGetPrimaryMonitor()); // Valid on GLFW 3.3+ only
  ctx->window = glfwCreateWindow(static_cast<int>(WINDOW_WIDTH * mainScale),
                                 static_cast<int>(WINDOW_HEIGHT * mainScale),
                                 "TTP Client", nullptr, nullptr);
  if (ctx->window == nullptr) {
    logzy::critical("Couldn't create window");
    return std::nullopt;
  }

  glfwMakeContextCurrent(ctx->window);
  glfwSwapInterval(1);
  glfwSetKeyCallback(ctx->window, glfwKeyCallback);
  gladLoadGL(glfwGetProcAddress);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

  ImGui::StyleColorsDark();
  // Setup scaling
  ImGuiStyle &style = ImGui::GetStyle();
  style.ScaleAllSizes(mainScale);
  style.FontScaleDpi = mainScale;
  ImGui_ImplGlfw_InitForOpenGL(ctx->window, /*install_callbacks=*/true);
  ImGui_ImplOpenGL3_Init(GLSL_VERSION);

  if (auto keyRes = crypto::RsaKeyPair::generate()) {
    ctx->rsaKey = std::move(*keyRes);
  } else {
    logzy::critical("Couldn't create RSA key pair: {}", keyRes.error());
    return std::nullopt;
  }

  return ctx;
}

void shutdown(AppContext &ctx) noexcept {

  // Cleanup
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();

  glfwDestroyWindow(ctx.window);
  glfwTerminate();
}

auto beginFrame(AppContext &ctx) noexcept -> bool {

  glfwPollEvents();
  if (glfwGetWindowAttrib(ctx.window, GLFW_ICONIFIED) != 0) {
    ImGui_ImplGlfw_Sleep(10);
    return false;
  }
  ImGui_ImplOpenGL3_NewFrame();
  ImGui_ImplGlfw_NewFrame();
  ImGui::NewFrame();
  return true;
}
void endFrame(AppContext &ctx) noexcept {

  constexpr ImVec4 clearColor = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

  // Rendering
  ImGui::Render();
  int displayWidth = 0;
  int displayHeight = 0;
  glfwGetFramebufferSize(ctx.window, &displayWidth, &displayHeight);

  glViewport(0, 0, displayWidth, displayHeight);
  glClearColor(clearColor.x * clearColor.w, clearColor.y * clearColor.w,
               clearColor.z * clearColor.w, clearColor.w);
  glClear(GL_COLOR_BUFFER_BIT);
  ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

  glfwSwapBuffers(ctx.window);
}
