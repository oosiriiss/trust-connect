#include "network.hpp"

int testLibFun() {

#if defined(ENABLE_DEBUG_UTILS)
  return 1;
#else
  return 2;
#endif
}
