
project(glad LANGUAGES C)



add_library(
   glad
   "${CMAKE_CURRENT_LIST_DIR}/glad.c"
   "${CMAKE_CURRENT_LIST_DIR}/glad.h"
   "${CMAKE_CURRENT_LIST_DIR}/khrplatform.h"
)
target_include_directories(glad PUBLIC ${CMAKE_CURRENT_LIST_DIR})
