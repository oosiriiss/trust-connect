#include "network.hpp"
#include <tasty/tasty.hpp>

int main() {

#if defined(ENABLE_DEBUG_UTILS)
  tasty::expectEqual(testLibFun(), 1)
#else
  tasty::expectEqual(testLibFun(), 2);
#endif
}
