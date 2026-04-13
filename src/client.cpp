
#include "crypto.hpp"
#include "ui/window.hpp"
#include <cstdlib>
#include <print>
#define GLFW_INCLUDE_NONE
#include "glad.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <logzy/logzy.hpp>

static void glfwErrorCallback(int /*error*/, const char *description) {
  std::println(stderr, "Error: {}", description);
}

constexpr const char *GLSL_VERSION = "#version 330 core";
constexpr int WINDOW_WIDTH = 800;
constexpr int WINDOW_HEIGHT = 800;

auto main() -> int {
  glfwSetErrorCallback(glfwErrorCallback);
  if (glfwInit() == 0) {
    return EXIT_FAILURE;
  }

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+

  // Create window with graphics context
  float mainScale = ImGui_ImplGlfw_GetContentScaleForMonitor(
      glfwGetPrimaryMonitor()); // Valid on GLFW 3.3+ only
  GLFWwindow *window =
      glfwCreateWindow(static_cast<int>(WINDOW_WIDTH * mainScale),
                       static_cast<int>(WINDOW_HEIGHT * mainScale),
                       "TTP Client", nullptr, nullptr);
  if (window == nullptr) {
    return EXIT_FAILURE;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);
  gladLoadGL(glfwGetProcAddress);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  io.ConfigFlags |=
      ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls

  ImGui::StyleColorsDark();

  // Setup scaling
  ImGuiStyle &style = ImGui::GetStyle();
  style.ScaleAllSizes(mainScale);
  style.FontScaleDpi = mainScale;
  ImGui_ImplGlfw_InitForOpenGL(window, /*install_callbacks=*/true);

  ImGui_ImplOpenGL3_Init(GLSL_VERSION);

  ImVec4 clearColor = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

  auto id = crypto::generateRandomId("User");

  if (!id) {
    logzy::critical("Couldn't generate ID for client. Reason: {}", id.error());
  }
  logzy::info("Generated Client ID: {}", crypto::hashToHex(*id));

  while (glfwWindowShouldClose(window) == 0) {
    glfwPollEvents();
    if (glfwGetWindowAttrib(window, GLFW_ICONIFIED) != 0) {
      ImGui_ImplGlfw_Sleep(10);
      continue;
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    {
      auto fsWindow = FullScreenWindow("Hello!");
      ImGui::Text("Hello");
    }

    // Rendering
    ImGui::Render();
    int displayWidth = 0;
    int displayHeight = 0;
    glfwGetFramebufferSize(window, &displayWidth, &displayHeight);

    glViewport(0, 0, displayWidth, displayHeight);
    glClearColor(clearColor.x * clearColor.w, clearColor.y * clearColor.w,
                 clearColor.z * clearColor.w, clearColor.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window);
  }

  // Cleanup
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();

  glfwDestroyWindow(window);
  glfwTerminate();

  return 0;
}
