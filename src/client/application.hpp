#pragma once

#include "GLFW/glfw3.h"
#include "constants.hpp"
#include "crypto/rsa.hpp"
#include "network/socket.hpp"
#include <cstdint>
#include <optional>
#include <string>

struct AppContext {
  GLFWwindow *window{nullptr};
  crypto::RsaKeyPair rsaKey{};
};

[[nodiscard]] auto initialize() noexcept -> std::optional<AppContext>;
void shutdown(AppContext &ctx) noexcept;

auto beginFrame(AppContext &ctx) noexcept -> bool;
void endFrame(AppContext &ctx) noexcept;
