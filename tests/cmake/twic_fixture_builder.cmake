# SPDX-License-Identifier: GPL-2.0-or-later
# Runs the TWIC synthetic fixture builder into WORK_DIR and checks that every
# file it writes equals the checked-in vector of the same name.
# Inputs: SOURCE_DIR, BUILDER, WORK_DIR.
set(vectors "${SOURCE_DIR}/tests/vectors/twic/synthetic")
file(REMOVE_RECURSE "${WORK_DIR}")
# The builder reads the test face image from <output>/../common.
file(COPY "${vectors}/common" DESTINATION "${WORK_DIR}")
foreach(generation legacy nexgen)
  file(MAKE_DIRECTORY "${WORK_DIR}/${generation}")
  execute_process(
    COMMAND "${BUILDER}" ${generation} "${WORK_DIR}/${generation}" "${vectors}/${generation}/keys"
    RESULT_VARIABLE result OUTPUT_QUIET)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${generation}: builder exited with ${result}")
  endif()
  file(GLOB generated RELATIVE "${WORK_DIR}/${generation}" "${WORK_DIR}/${generation}/*")
  if(NOT generated)
    message(FATAL_ERROR "${generation}: builder wrote no files")
  endif()
  foreach(name ${generated})
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E compare_files "${WORK_DIR}/${generation}/${name}"
        "${vectors}/${generation}/${name}"
      RESULT_VARIABLE differs)
    if(NOT differs EQUAL 0)
      message(FATAL_ERROR "${generation}/${name} differs from the checked-in vector")
    endif()
  endforeach()
endforeach()
