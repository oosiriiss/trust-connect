#include "cppli/cppli.hpp"
#include "cppli/help.hpp"
#include "cppli/option.hpp"
#include <cstdint>
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

namespace {
enum class OptionKey : std::uint_fast8_t {
  ServerIp,
  ServerPort,
  TtpIp,
  TtpPort,
  Help
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
} // namespace

[[nodiscard]] auto initialize(int argc, char const *const *const argv,
                              bool &outTerminate) noexcept
    -> std::optional<AppContext> {
  std::optional<AppContext> ctx{AppContext{}};

  outTerminate = parseCommandlineArgs(*ctx, argc, argv);

  if (outTerminate) {
    return std::nullopt;
  }

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
