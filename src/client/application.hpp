#pragma once

#include "GLFW/glfw3.h"
#include "constants.hpp"
#include <cstdint>
#include <optional>
#include <string>

struct AppContext {
  GLFWwindow *window{nullptr};
  std::string serverIp{network::DEFAULT_SERVER_IP};
  std::string ttpIp{network::DEFAULT_TTP_IP};
  std::uint16_t serverPort{network::DEFAULT_SERVER_PORT};
  std::uint16_t ttpPort{network::DEFAULT_TTP_PORT};
};

[[nodiscard]] auto initialize(int argc, char const *const *argv,
                              bool &outTerminate) noexcept
    -> std::optional<AppContext>;
void shutdown(AppContext &ctx) noexcept;

auto beginFrame(AppContext &ctx) noexcept -> bool;
void endFrame(AppContext &ctx) noexcept;
