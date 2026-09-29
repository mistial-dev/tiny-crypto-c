# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks configuration rules that config.h owns for the hash, SSKDF and DRBG
# headers. Each probe includes one header with a -D profile and expects the
# build to pass, or to fail with the named config.h message.

file(MAKE_DIRECTORY "${BINARY_DIR}")

# Compile a one-line translation unit that includes header under definitions.
function(tc_header_probe name header definitions expected)
  set(probe "${BINARY_DIR}/${name}.c")
  file(WRITE "${probe}" "#include <tiny_crypto/${header}>\nint tc_header_probe_${name};\n")
  set(flags)
  foreach(definition IN LISTS definitions)
    list(APPEND flags "-D${definition}")
  endforeach()
  execute_process(
    COMMAND "${C_COMPILER}" -I "${SOURCE_DIR}/src" ${flags} -c "${probe}"
      -o "${BINARY_DIR}/${name}.o"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  if(expected STREQUAL "")
    if(NOT result EQUAL 0)
      message(FATAL_ERROR "${name}: ${definitions} was rejected:\n${output}${error}")
    endif()
  elseif(result EQUAL 0)
    message(FATAL_ERROR "${name}: ${definitions} was accepted")
  elseif(NOT "${output}${error}" MATCHES "${expected}")
    message(FATAL_ERROR "${name}: failed for the wrong reason:\n${output}${error}")
  endif()
endfunction()

set(no_sha TC_ENABLE_SHA1=0 TC_ENABLE_SHA224=0 TC_ENABLE_SHA256=0 TC_ENABLE_SHA384=0
  TC_ENABLE_SHA512=0 TC_ENABLE_HMAC=0)

# hash.h declares nothing in a profile without SHA and stays includable.
tc_header_probe(hash_without_sha hash.h "${no_sha}" "")

# SSKDF accepts any Table 1 hash and needs at least one.
tc_header_probe(sskdf_sha1_only sskdf.h
  "TC_ENABLE_SSKDF=1;TC_ENABLE_SHA256=0;TC_ENABLE_SHA1=1" "")
tc_header_probe(sskdf_sha512_only sskdf.h
  "TC_ENABLE_SSKDF=1;TC_ENABLE_SHA256=0;TC_ENABLE_SHA512=1" "")
tc_header_probe(sskdf_without_sha sskdf.h "TC_ENABLE_SSKDF=1;${no_sha}"
  "Single-step KDF requires an enabled SHA algorithm")

# config.h checks the DRBG entropy bound for every header that includes it.
set(drbg TC_ENABLE_DRBG=1 TC_DRBG_ENABLE_HASH=1)
tc_header_probe(drbg_entropy_47 common.h "${drbg};TC_DRBG_MAX_ENTROPY_BYTES=47u"
  "TC_DRBG_MAX_ENTROPY_BYTES must hold a CTR_DRBG seed")
tc_header_probe(drbg_entropy_48 drbg.h "${drbg};TC_DRBG_MAX_ENTROPY_BYTES=48u" "")
