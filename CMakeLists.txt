cmake_minimum_required(VERSION 3.5)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file (STRINGS "capstone.version" vCapstone)
file (STRINGS "keystone.version" vKeystone)

add_subdirectory(capstone)
add_subdirectory(keystone)

project (PEDetour)
include_directories(capstone/include)
include_directories(keystone/include)
include_directories(src)

add_subdirectory(src)

