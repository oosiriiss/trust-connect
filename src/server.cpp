#include "crypto.hpp"
#include "logzy/logzy.hpp"
#include "network.hpp"
#include <cstdlib>
#include <unistd.h>

auto main(int /*argc*/, const char *const *const /*argv*/) -> int {

  crypto::Hash32 id{};

  logzy::info("Generating server id");
  if (auto idExp = crypto::generateRandomId("Server")) {
    id = *idExp;
  } else {
    logzy::critical("Couldn't generate ID for client. Reason: {}",
                    idExp.error());
    return EXIT_FAILURE;
  }
  logzy::info("ID generated: {}", crypto::hashToHex(id));

  logzy::info("Binding to port");
  network::TcpServer server;
  if (auto err = server.listen()) {
    logzy::critical("Server listen failed. Reason: {}", *err);
    return EXIT_FAILURE;
  }

  logzy::info("Bound");

  logzy::info("Waiting for 1 client to connect");
  auto client = server.accept();
  logzy::info("Client connected");

  while (true) {

    if (!client) {
      logzy::error("Accepting client failed: {}", client.error());
      continue;
    }
    logzy::info("Client connected!");

    if (auto received = client->receive()) {
      logzy::info("Received: {}", *received);

      if (received->empty()) {
        logzy::info("Client disconnected");
        break;
      }

      // Echo
      if (auto err = client->send(*received)) {
        logzy::error("Couldn't send send echo messge to client. {}", *err);
      }
    } else {
      logzy::error("Couldn't receive message from client: {}",
                   received.error());
    }
  }

  return EXIT_SUCCESS;
}
