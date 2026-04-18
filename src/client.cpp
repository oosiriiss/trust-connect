
#include "client/application.hpp"
#include "common.hpp"
#include "crypto/base64.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
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
  static_string<32> clientName;
  crypto::Hash32 id{};
  std::string errorMessage;
  AppStage stage{AppStage::GeneratingID};
};

void estabilishSession(network::TcpSocket &serverSocket,
                       network::TcpSocket &ttpSocket,
                       const crypto::RsaKeyPair &ttpPublicKey,
                       const crypto::Hash32 &id) {

  logzy::debug("Requesting service from server");
  logzy::trace("Encrypting user id with ttp's public key");
  logzy::trace("User id: {}", crypto::hashToHex(id));
  std::string userId;
  if (auto idResult =
          crypto::encryptAndEncode(crypto::hashToHex(id), ttpPublicKey)) {
    userId = std::move(*idResult);
  } else {
    logzy::error("Couldn't encrypt user's id. {}", idResult.error());
    return;
  }

  if (auto err = serverSocket.send(
          network::Packet{.type = network::PacketType::ServiceRequest,
                          .payload = {
                              {"id", userId},
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

    // Veriying
    const auto message = packet->payload.value("message", std::string_view{""});
    std::string signature = packet->payload.value("signature", "");

    if (message.empty()) {
      logzy::error("Server empty message during authentication");
      return;
    }

    if (signature.empty()) {
      logzy::error("Server empty signature during authentication");
      return;
    }

    if (auto decodeResult = crypto::base64Decode(signature)) {
      signature = std::move(*decodeResult);
    } else {
      logzy::error("Couldn't base64 decode the signature. {}",
                   decodeResult.error());
    }

    if (auto result = ttpPublicKey.verify(message, signature); !result) {

      logzy::error("Couldn't validate message and signature. {}",
                   result.error());
      return;
    }

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

        if (auto keyOpt = registerWithTtp(ttpSocket, state.id, publicKeyPem)) {
          ttpPublicKey = std::move(*keyOpt);
        } else {
          break;
        }
        logzy::info("Successfully registerd with TTP");
        state.stage = AppStage::Registered;

      } break;

      case AppStage::Registered: {

        if (ImGui::Button("Request service")) {
          estabilishSession(serverSocket, ttpSocket, ttpPublicKey, state.id);
        }

      } break;
      }
    }
    endFrame(ctx);
  }

  shutdown(ctx);

  return 0;
}
