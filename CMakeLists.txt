cmake_minimum_required(VERSION 3.13)

project(
   TTP-showcase
   LANGUAGES CXX
)

option(ENABLE_DEBUG_UTILS "Enable debug_utils.hpp" ON)
option(COMPILE_TESTS "Whether tests will be compiled" ON)
option(BUILD_DOCS "Whether doxygen documentation will be created" ON)
option(BUILD_CLIENT "Whether GLFW client will be built" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include(FetchContent)

FetchContent_Declare(
   cppli
   GIT_REPOSITORY https://github.com/oosiriiss/cppli
   GIT_TAG 44b96701812803d2b5171bafa56120fb20852c08 # 0.2.1
)
FetchContent_MakeAvailable(cppli)


FetchContent_Declare(
   logzy
   GIT_REPOSITORY https://github.com/oosiriiss/logzy
   GIT_TAG 075928d08bc97f05d10e1d4def802e2bf0792fc4
)
FetchContent_MakeAvailable(logzy)

FetchContent_Declare(
   nlohmann_json
   GIT_REPOSITORY https://github.com/nlohmann/json
   GIT_TAG 55f93686c01528224f448c19128836e7df245f72 # 3.12.0
)
FetchContent_MakeAvailable(nlohmann_json)


find_package(OpenSSL REQUIRED)


add_library(
   shared-lib

   src/network/socket.hpp
   src/network/socket.cpp

   src/network/packet.hpp
   src/network/packet.cpp

   src/crypto/crypto.hpp
   src/crypto/crypto.cpp
   src/crypto/openssl.hpp
   src/crypto/openssl.cpp
   src/crypto/hash.hpp
   src/crypto/hash.cpp
   src/crypto/rsa.hpp
   src/crypto/rsa.cpp
   src/crypto/aes.hpp
   src/crypto/aes.cpp
   src/crypto/base64.hpp
   src/crypto/base64.cpp

   src/common.hpp
   src/common.cpp
)

add_executable(
   ttp-app
   src/ttp.cpp
)


add_executable(
   server-app
   src/server.cpp
)


target_compile_features(shared-lib PUBLIC cxx_std_23)
target_compile_features(ttp-app PUBLIC cxx_std_23)
target_compile_features(server-app PUBLIC cxx_std_23)

target_include_directories(shared-lib PUBLIC src vendor/debug_utils vendor/otl)


if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL GNU) 
      # print, println
   target_link_libraries(shared-lib PUBLIC stdc++exp)
endif()

if(ENABLE_DEBUG_UTILS)
    target_compile_definitions(shared-lib PUBLIC ENABLE_DEBUG_UTILS)
    target_compile_definitions(ttp-app PUBLIC ENABLE_DEBUG_UTILS)
    target_compile_definitions(server-app PUBLIC ENABLE_DEBUG_UTILS)
endif()


message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libs: ${OPENSSL_LIBRARIES}")

target_link_libraries(shared-lib PUBLIC OpenSSL::SSL OpenSSL::Crypto logzy::logzy cppli::cppli nlohmann_json::nlohmann_json)
target_link_libraries(ttp-app PRIVATE shared-lib )
target_link_libraries(server-app PRIVATE shared-lib )



# Client GUI related.
if(BUILD_CLIENT)
   FetchContent_Declare(
      glfw
      GIT_REPOSITORY https://github.com/glfw/glfw
      GIT_TAG 7b6aead9fb88b3623e3b3725ebb42670cbe4c579a #3.4
   )
   FetchContent_MakeAvailable(glfw)
   add_subdirectory(vendor/imgui)
   add_subdirectory(vendor/glad)
   find_package(OpenGL REQUIRED)

   add_executable(
      client-app
      src/client.cpp
      ./src/ui/window.hpp
      src/client/application.hpp
      src/client/application.cpp
   )
   target_compile_features(client-app PUBLIC cxx_std_23)
   target_compile_definitions(client-app PUBLIC ENABLE_DEBUG_UTILS)

   target_link_libraries(client-app PRIVATE shared-lib imgui glfw OpenGL::GL glad)
endif()


if(COMPILE_TESTS) 
   include(CTest)
   add_subdirectory(test)
endif()

if(BUILD_DOCS) 
   include(cmake/docs.cmake)
endif()





