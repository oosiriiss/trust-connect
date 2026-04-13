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
FetchContent_MakeAvailable(glfw)

add_subdirectory(vendor/imgui)
add_subdirectory(vendor/glad)
find_package(OpenGL REQUIRED)


add_library(
   shared-lib

   src/network.cpp
   src/network.hpp
)

add_executable(
   ttp-app
   src/ttp.cpp
)

add_executable(
   client-app
   src/client.cpp
)

add_executable(
   server-app
   src/server.cpp
)
target_compile_features(shared-lib PUBLIC cxx_std_23)

target_include_directories(shared-lib PUBLIC src)


if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL GNU) 
      # print, println
   target_link_libraries(shared-lib PUBLIC stdc++exp)
endif()

if(ENABLE_DEBUG_UTILS)
    target_compile_definitions(shared-lib PUBLIC ENABLE_DEBUG_UTILS)
endif()

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





