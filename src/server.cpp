#include "crypto.hpp"
#include "logzy/logzy.hpp"
#include <cstdlib>
#include <unistd.h>

auto main(int  /*argc*/, const char *const *const  /*argv*/) -> int {

  crypto::Hash32 id{};

  if (auto idExp = crypto::generateRandomId("Server")) {
    id = *idExp;
  } else {
    logzy::critical("Couldn't generate ID for client. Reason: {}",
                    idExp.error());
    return EXIT_FAILURE;
  }

  logzy::info("Generated Server ID: {}", crypto::hashToHex(id));

  return EXIT_SUCCESS;
}
