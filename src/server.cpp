#include "crypto.hpp"
#include "logzy/logzy.hpp"
#include "network.hpp"
#include <print>

int main(int argc, const char *const *const argv) {

  auto id = crypto::generateRandomId("User");

  if (!id) {
    logzy::critical("Couldn't generate ID for client. Reason: {}", id.error());
  }

  logzy::info("Generated Server ID: {}", crypto::hashToHex(*id));

  return 0;
}
