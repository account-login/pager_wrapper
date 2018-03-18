cmake_minimum_required(VERSION 3.6)
project(pager_wrapper C)

set(CMAKE_C_STANDARD 99)

add_definitions(-Wall -Wextra -g)
add_definitions(-Os)

add_executable(pager_wrapper pager_wrapper.c)
install(TARGETS pager_wrapper DESTINATION bin)
