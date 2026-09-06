# SPDX-License-Identifier: GPL-2.0-or-later
cmake_minimum_required(VERSION 3.24)
project(installed_consumer LANGUAGES C)
find_package(tiny-crypto-c CONFIG REQUIRED)
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE tiny-crypto-c::tiny-crypto-c)
enable_testing()
add_test(NAME consumer COMMAND consumer)
