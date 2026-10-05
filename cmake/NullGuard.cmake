# SPDX-License-Identifier: GPL-2.0-or-later

# Null-guard instrumentation for the C tests. Every public call made by a C
# test first repeats with each pointer argument NULL and each span argument
# {NULL, length}. Combined with TINY_CRYPTO_SANITIZE=address,undefined, a
# missing argument check is reported where the library dereferences it.
# tests/null_guard/generate.py writes the wrappers from Clang's AST of the
# public headers. test_null_guard_coverage lists the cases no test reached.
option(TINY_CRYPTO_TEST_NULL_GUARD "Repeat C test calls with NULL arguments" OFF)

set(tc_null_guard_dir ${CMAKE_CURRENT_BINARY_DIR}/null-guard)
set(tc_null_guard_wrappers ${tc_null_guard_dir}/null_guard_wrappers.h)
set(tc_null_guard_inventory ${tc_null_guard_dir}/inventory.txt)
set(tc_null_guard_report ${tc_null_guard_dir}/report.txt)

if(TINY_CRYPTO_TEST_NULL_GUARD)
  if(MSVC)
    message(FATAL_ERROR "TINY_CRYPTO_TEST_NULL_GUARD requires GCC or Clang")
  endif()
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(tc_null_guard_clang ${CMAKE_C_COMPILER})
  else()
    find_program(tc_null_guard_clang NAMES clang REQUIRED)
  endif()
  file(GLOB tc_null_guard_headers CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tiny_crypto/*.h)
  add_custom_command(
    OUTPUT ${tc_null_guard_wrappers} ${tc_null_guard_inventory}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard/generate.py
      --clang ${tc_null_guard_clang} --output ${tc_null_guard_wrappers}
      --inventory ${tc_null_guard_inventory}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard/generate.py
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard/nullable.txt
      ${CMAKE_CURRENT_SOURCE_DIR}/cmake/features.json ${tc_null_guard_headers}
    COMMENT "Generating null-guard wrappers"
    VERBATIM)
  add_custom_target(tc_null_guard_wrappers DEPENDS ${tc_null_guard_wrappers})
  # Some test executables compile library sources directly. Those keep the
  # real calls between library functions.
  file(GLOB tc_null_guard_library_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
  set_property(SOURCE ${tc_null_guard_library_sources} APPEND PROPERTY
    COMPILE_DEFINITIONS TC_NULL_GUARD_LIBRARY_SOURCE)
  add_library(tc_null_guard_runtime STATIC tests/null_guard/null_guard.c)
  tc_warnings(tc_null_guard_runtime)
  if(tc_sanitize_flags)
    target_compile_options(tc_null_guard_runtime PRIVATE ${tc_sanitize_flags})
  endif()
endif()

# Force-include the wrappers into the C sources of one test executable.
function(tc_use_null_guard target)
  if(NOT TINY_CRYPTO_TEST_NULL_GUARD)
    return()
  endif()
  add_dependencies(${target} tc_null_guard_wrappers)
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard ${tc_null_guard_dir})
  target_compile_options(${target} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:SHELL:-include ${tc_null_guard_wrappers}>")
  target_link_libraries(${target} PRIVATE tc_null_guard_runtime)
  set_property(GLOBAL APPEND PROPERTY TC_NULL_GUARD_TARGETS ${target})
endfunction()

# The force-included header reaches <stdint.h>, which fixes the feature-test
# macros of the C library (glibc <features.h>). A source that defines one, such
# as _POSIX_C_SOURCE, before its first include gets the same definition on the
# command line, so its system headers see it. A source that defines one macro
# with two values selects it by condition and is compiled without wrappers.
function(tc_null_guard_feature_macros)
  get_property(targets GLOBAL PROPERTY TC_NULL_GUARD_TARGETS)
  set(done)
  foreach(target IN LISTS targets)
    get_target_property(sources ${target} SOURCES)
    get_target_property(source_dir ${target} SOURCE_DIR)
    foreach(source IN LISTS sources)
      if(NOT source MATCHES "\\.c$")
        continue()
      endif()
      if(IS_ABSOLUTE "${source}")
        set(path "${source}")
      else()
        set(path "${source_dir}/${source}")
      endif()
      if(NOT EXISTS "${path}" OR path IN_LIST done)
        continue()
      endif()
      list(APPEND done "${path}")
      file(STRINGS "${path}" lines
        REGEX "^#[ \t]*define[ \t]+_[A-Z0-9_]*_SOURCE([ \t].*)?$")
      set(names)
      set(definitions)
      set(ambiguous 0)
      foreach(line IN LISTS lines)
        string(REGEX REPLACE "^#[ \t]*define[ \t]+([A-Z0-9_]+)[ \t]*(.*)$" "\\1" name "${line}")
        string(REGEX REPLACE "^#[ \t]*define[ \t]+([A-Z0-9_]+)[ \t]*(.*)$" "\\2" value "${line}")
        string(STRIP "${value}" value)
        if(name IN_LIST names)
          set(ambiguous 1)
        endif()
        list(APPEND names ${name})
        list(APPEND definitions "${name}=${value}")
      endforeach()
      if(ambiguous)
        set_property(SOURCE "${path}" APPEND PROPERTY COMPILE_DEFINITIONS TC_NULL_GUARD_DISABLE)
      elseif(definitions)
        set_property(SOURCE "${path}" APPEND PROPERTY COMPILE_DEFINITIONS ${definitions})
      endif()
    endforeach()
  endforeach()
endfunction()

# Keep one executable on direct calls. Use this only for a test whose
# library state, such as a fault-injection counter, the repeated calls would
# change.
function(tc_skip_null_guard target)
  if(TINY_CRYPTO_TEST_NULL_GUARD)
    target_compile_definitions(${target} PRIVATE TC_NULL_GUARD_DISABLE)
  endif()
endfunction()

# Point every test at one report, cleared before the run, and add the
# coverage check that reads it after every other test.
function(tc_null_guard_tests)
  if(NOT TINY_CRYPTO_TEST_NULL_GUARD)
    return()
  endif()
  tc_null_guard_feature_macros()
  get_property(tests DIRECTORY PROPERTY TESTS)
  add_test(NAME test_null_guard_reset
    COMMAND ${CMAKE_COMMAND} -E rm -f ${tc_null_guard_report})
  set_tests_properties(test_null_guard_reset PROPERTIES FIXTURES_SETUP null_guard)
  add_test(NAME test_null_guard_coverage
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard/coverage.py
      --inventory ${tc_null_guard_inventory} --report ${tc_null_guard_report}
      --uncovered ${CMAKE_CURRENT_SOURCE_DIR}/tests/null_guard/uncovered.txt)
  set_tests_properties(test_null_guard_coverage PROPERTIES FIXTURES_CLEANUP null_guard)
  foreach(test IN LISTS tests)
    set_property(TEST ${test} APPEND PROPERTY ENVIRONMENT
      "TC_NULL_GUARD_REPORT=${tc_null_guard_report}")
    set_property(TEST ${test} APPEND PROPERTY FIXTURES_REQUIRED null_guard)
  endforeach()
endfunction()
