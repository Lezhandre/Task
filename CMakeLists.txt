cmake_minimum_required(VERSION 3.23)
project(task)

set(CMAKE_CXX_STANDARD 20)

add_executable(task main.cpp tests.cpp catch.hpp PCAP.h PCAP.cpp)

add_custom_command(
    TARGET task POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        ${CMAKE_BINARY_DIR}/examples
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/examples/nlmon-big.pcap
        ${CMAKE_SOURCE_DIR}/examples/PPP-config.pcap
        ${CMAKE_SOURCE_DIR}/examples/PPPHandshake.pcap
        ${CMAKE_SOURCE_DIR}/examples/rtp-norm-transfer.pcap
        ${CMAKE_BINARY_DIR}/examples/
)