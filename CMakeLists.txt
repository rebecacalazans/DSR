cmake_minimum_required(VERSION 2.8)
project("DSR")

add_definitions(-std=c++11)
include_directories(include)

set(SRC
  main.cpp
  utils.cpp
  routediscovery.cpp)

add_executable(dsr.out ${SRC})
add_executable(teste.out teste.cpp utils.cpp routediscovery.cpp)
target_link_libraries(dsr.out -pthread)
