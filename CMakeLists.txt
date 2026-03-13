cmake_minimum_required(VERSION 3.13)

option(ENABLE_DEBUG_UTILS "Enable debug_utils.hpp" ON)
option(COMPILE_TESTS "Whether tests will be compiled" ON)
option(BUILD_DOCS "Whether doxygen documentation will be created" ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


project(
   TTP-showcase
   LANGUAGES CXX
)

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

if(ENABLE_DEBUG_UTILS)
    target_compile_definitions(shared-lib PUBLIC ENABLE_DEBUG_UTILS)
endif()

target_link_libraries(ttp-app PRIVATE shared-lib)
target_link_libraries(client-app PRIVATE shared-lib)
target_link_libraries(server-app PRIVATE shared-lib)

if(COMPILE_TESTS) 
   include(CTest)
   add_subdirectory(test)
endif()

if(BUILD_DOCS) 
   include(cmake/docs.cmake)
endif()





