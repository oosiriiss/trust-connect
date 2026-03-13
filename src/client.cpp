#include "network.hpp"
#include <print>

int main() {

#if defined(ENABLE_DEBUG_UTILS)
  std::println("Debug utils enabledin consumers");
#endif

  std::println("Client app, lib fun: {}", testLibFun());
  return 0;
}
