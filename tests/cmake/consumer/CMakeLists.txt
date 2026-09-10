# SPDX-License-Identifier: GPL-2.0-or-later
cmake_minimum_required(VERSION 3.24)
project(installed_consumer LANGUAGES C CXX)
find_package(tiny-crypto-c CONFIG REQUIRED)
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE tiny-crypto-c::tiny-crypto-c)
enable_testing()
add_test(NAME consumer COMMAND consumer)
add_executable(consumer_cpp main.cpp)
target_link_libraries(consumer_cpp PRIVATE tiny-crypto-c::tiny-crypto-c)
add_test(NAME consumer_cpp COMMAND consumer_cpp)

add_library(consumer_example_impl STATIC example/x509_client.c example/cms_reader.c
  example/cms_validate.c example/credential_object.c
  example/rsa_encrypt.c example/twic_ccl_storage.c example/twic_ccl_import.c
  example/card_key_policy.c example/credential_auth.c example/credential_validate.c
  example/credential_io.c example/pki_input.c)
target_sources(consumer_example_impl PRIVATE example/credential_workflow.c)
set_target_properties(consumer_example_impl PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(consumer_example_impl PUBLIC example)
target_link_libraries(consumer_example_impl PUBLIC tiny-crypto-c::tiny-crypto-c)
add_executable(consumer_example example.c)
target_link_libraries(consumer_example PRIVATE consumer_example_impl)
add_test(NAME consumer_example COMMAND consumer_example)
add_executable(cms_check example/cms_check.c)
target_link_libraries(cms_check PRIVATE consumer_example_impl)
set_target_properties(cms_check PROPERTIES C_STANDARD 99
  C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

# Exercise the same caller through the example header's C++ linkage.
configure_file(example.c "${CMAKE_CURRENT_BINARY_DIR}/example.cpp" COPYONLY)
add_executable(consumer_example_cpp "${CMAKE_CURRENT_BINARY_DIR}/example.cpp")
target_link_libraries(consumer_example_cpp PRIVATE consumer_example_impl)
add_test(NAME consumer_example_cpp COMMAND consumer_example_cpp)
foreach(target consumer_cpp consumer_example_cpp)
  set_target_properties(${target} PROPERTIES CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -fno-exceptions -fno-rtti)
  endif()
endforeach()
