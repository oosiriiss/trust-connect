#pragma once

#include "GLFW/glfw3.h"
#include <optional>

struct AppContext {

  GLFWwindow *window{nullptr};
};

[[nodiscard]] auto initialize() noexcept -> std::optional<AppContext>;
void shutdown(AppContext &ctx) noexcept;

auto beginFrame(AppContext &ctx) noexcept -> bool;
void endFrame(AppContext &ctx) noexcept;
