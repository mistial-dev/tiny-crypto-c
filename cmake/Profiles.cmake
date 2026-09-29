# SPDX-License-Identifier: GPL-2.0-or-later
include(${CMAKE_CURRENT_LIST_DIR}/Targets.cmake)

# Every public configuration macro is registered once, as MACRO=value, in the
# TINY_CRYPTO_PUBLIC_DEFINITIONS global property. CMakeLists.txt passes the list
# to the library target, to ConfigCheck.cmake and to the installed
# build_config.h, so headers and objects always see the same values.
set_property(GLOBAL PROPERTY TINY_CRYPTO_PUBLIC_DEFINITIONS "")
set_property(GLOBAL PROPERTY TINY_CRYPTO_PUBLIC_MACROS "")

function(tc_register_definition macro value)
  get_property(macros GLOBAL PROPERTY TINY_CRYPTO_PUBLIC_MACROS)
  if(macro IN_LIST macros)
    message(FATAL_ERROR "${macro} is registered twice")
  endif()
  set_property(GLOBAL APPEND PROPERTY TINY_CRYPTO_PUBLIC_MACROS ${macro})
  set_property(GLOBAL APPEND PROPERTY TINY_CRYPTO_PUBLIC_DEFINITIONS "${macro}=${value}")
endfunction()

set(TINY_CRYPTO_RESOURCE_PROFILE "" CACHE STRING "Resource profile: micro, mini, desktop, or empty for existing defaults")
set_property(CACHE TINY_CRYPTO_RESOURCE_PROFILE PROPERTY STRINGS "" micro mini desktop)
set(tc_profile_names default micro mini desktop)
if(TINY_CRYPTO_RESOURCE_PROFILE STREQUAL "")
  set(tc_profile_index 0)
else()
  list(FIND tc_profile_names "${TINY_CRYPTO_RESOURCE_PROFILE}" tc_profile_index)
  if(tc_profile_index LESS 1)
    message(FATAL_ERROR "Unknown TINY_CRYPTO_RESOURCE_PROFILE")
  endif()
endif()
tc_register_definition(TC_RESOURCE_PROFILE ${tc_profile_index})

# Read numeric defaults without running a target executable when cross-compiling.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../src/tiny_crypto/config.h" tc_profile_entries
  REGEX "^#define TC_[A-Z0-9_]+ TC_PROFILE_VALUE")
foreach(entry IN LISTS tc_profile_entries)
  if(NOT entry MATCHES "^#define (TC_[A-Z0-9_]+) TC_PROFILE_VALUE\\(([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\\)$")
    message(FATAL_ERROR "Malformed resource default: ${entry}")
  endif()
  set(values ${CMAKE_MATCH_2} ${CMAKE_MATCH_3} ${CMAKE_MATCH_4} ${CMAKE_MATCH_5})
  list(GET values ${tc_profile_index} tc_profile_default_${CMAKE_MATCH_1})
endforeach()

# Convert an ON/OFF choice to 0 or 1. AUTO is resolved by the caller.
function(tc_choice_value name choice output)
  if(choice MATCHES "^(ON|TRUE|YES|1)$")
    set(${output} 1 PARENT_SCOPE)
  elseif(choice MATCHES "^(OFF|FALSE|NO|0)$")
    set(${output} 0 PARENT_SCOPE)
  else()
    message(FATAL_ERROR "${name} must be AUTO, ON, or OFF")
  endif()
endfunction()

# Declare a feature option, resolve it to 0 or 1 and register macro.
# AUTO follows the application target, then the resource profile. Macros in
# tc_platform_features, set by a platform port, have a floor of 1.
function(tc_profile_option name macro description)
  set(${name} AUTO CACHE STRING "${description} (AUTO follows the resource profile)")
  set_property(CACHE ${name} PROPERTY STRINGS AUTO ON OFF)
  string(TOUPPER "${${name}}" choice)
  tc_target_default(${macro} role_default)
  set(platform_floor OFF)
  if(macro IN_LIST tc_platform_features)
    set(platform_floor ON)
  endif()
  if(choice STREQUAL "AUTO")
    if(NOT DEFINED tc_profile_default_${macro})
      message(FATAL_ERROR "Missing resource default for ${macro}")
    endif()
    set(value ${tc_profile_default_${macro}})
    if(NOT role_default STREQUAL "")
      set(value ${role_default})
    endif()
    if(platform_floor)
      set(value 1)
    endif()
  else()
    tc_choice_value(${name} "${choice}" value)
  endif()
  if(NOT role_default STREQUAL "" AND NOT value EQUAL role_default)
    message(FATAL_ERROR "${name} conflicts with ${TINY_CRYPTO_TARGET}; use AUTO or an unscoped target")
  endif()
  if(platform_floor AND value EQUAL 0)
    message(FATAL_ERROR "${name} is required by the platform port; use AUTO or ON")
  endif()
  tc_register_definition(${macro} ${value})
  # Keep AUTO in the cache so switching profiles recomputes the default.
  set(${name} ${value} PARENT_SCOPE)
endfunction()

# Declare an RFC 5914 trust-anchor choice. AUTO follows
# TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT, so it must be declared first.
function(tc_taf_choice_option name macro description)
  set(${name} AUTO CACHE STRING "${description} (AUTO follows trust-anchor format)")
  set_property(CACHE ${name} PROPERTY STRINGS AUTO ON OFF)
  string(TOUPPER "${${name}}" choice)
  if(choice STREQUAL "AUTO")
    set(value ${TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT})
  else()
    tc_choice_value(${name} "${choice}" value)
  endif()
  tc_register_definition(${macro} ${value})
  set(${name} ${value} PARENT_SCOPE)
endfunction()
