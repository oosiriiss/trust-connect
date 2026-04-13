cmake_minimum_required(VERSION 3.13)

project(
   TTP-showcase
   LANGUAGES CXX
)

option(ENABLE_DEBUG_UTILS "Enable debug_utils.hpp" ON)
option(COMPILE_TESTS "Whether tests will be compiled" ON)
option(BUILD_DOCS "Whether doxygen documentation will be created" ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
FetchContent_Declare(
   glfw
   GIT_REPOSITORY https://github.com/glfw/glfw
   GIT_TAG 7b6aead9fb88b3623e3b3725ebb42670cbe4c579a #3.4
)
FetchContent_Declare(
   logzy
   GIT_REPOSITORY https://github.com/oosiriiss/logzy
   GIT_TAG 075928d08bc97f05d10e1d4def802e2bf0792fc4
)
FetchContent_MakeAvailable(glfw logzy)

add_subdirectory(vendor/imgui)
add_subdirectory(vendor/glad)

find_package(OpenGL REQUIRED)
find_package(OpenSSL REQUIRED)


add_library(
   shared-lib

   src/network.cpp
   src/network.hpp
   src/crypto.hpp
   src/crypto.cpp
)

add_executable(
   ttp-app
   src/ttp.cpp
)

add_executable(
   client-app
   src/client.cpp
   ./src/ui/window.hpp
   src/client/application.hpp
   src/client/application.cpp
)

add_executable(
   server-app
   src/server.cpp
)
target_compile_features(shared-lib PUBLIC cxx_std_23)
target_compile_features(ttp-app PUBLIC cxx_std_23)
target_compile_features(client-app PUBLIC cxx_std_23)
target_compile_features(server-app PUBLIC cxx_std_23)

target_include_directories(shared-lib PUBLIC src vendor/debug_utils vendor/otl)


if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL GNU) 
      # print, println
   target_link_libraries(shared-lib PUBLIC stdc++exp)
endif()

if(ENABLE_DEBUG_UTILS)
    target_compile_definitions(shared-lib PUBLIC ENABLE_DEBUG_UTILS)
endif()


message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libs: ${OPENSSL_LIBRARIES}")

target_link_libraries(shared-lib PUBLIC OpenSSL::SSL OpenSSL::Crypto logzy::logzy)
target_link_libraries(ttp-app PRIVATE shared-lib)
target_link_libraries(client-app PRIVATE shared-lib imgui glfw OpenGL::GL glad)
target_link_libraries(server-app PRIVATE shared-lib)


if(COMPILE_TESTS) 
   include(CTest)
   add_subdirectory(test)
endif()

if(BUILD_DOCS) 
   include(cmake/docs.cmake)
endif()





