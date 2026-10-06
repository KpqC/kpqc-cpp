cmake_minimum_required(VERSION 3.20)
project(kpqc_consumer LANGUAGES CXX)

find_package(kpqc CONFIG REQUIRED)

add_executable(kpqc_consumer main.cpp)
target_link_libraries(kpqc_consumer PRIVATE kpqc::kpqc)

enable_testing()
add_test(NAME installed-package COMMAND kpqc_consumer)
