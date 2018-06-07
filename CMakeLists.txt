cmake_minimum_required(VERSION 3.1)
project(haxm-test)

set(CMAKE_C_STANDARD 11)

include_directories(SYSTEM depends/haxm/include)

add_executable(haxm-test main.c)
