cmake_minimum_required(VERSION 3.14)


project(TTP-tests)

enable_testing()
include(FetchContent)
FetchContent_Declare(
   tasty
   GIT_REPOSITORY https://github.com/oosiriiss/tasty
   GIT_TAG 0.2.11
)
FetchContent_MakeAvailable(tasty)

function(Register_Test name)
   add_executable(${name} ${name}.cpp)
   target_link_libraries(${name} PRIVATE shared-lib PRIVATE tasty::tasty)
   target_compile_features(${name} PRIVATE cxx_std_23)
   add_test(NAME ${name} COMMAND ${name})
   message("Test ${name} registered")
endfunction()


Register_Test(test_headless_client)
