cmake_minimum_required(VERSION 2.8)
project("DSR")

add_definitions(-std=c++11)
include_directories(include)

set(SRC
  utils.cpp
  routediscovery.cpp)

add_executable(dsr.out main.cpp ${SRC})
add_executable(routerequest.out routerequest.cpp ${SRC})
target_link_libraries(dsr.out -pthread)
