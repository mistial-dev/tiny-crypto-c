# SPDX-License-Identifier: GPL-2.0-or-later

execute_process(COMMAND "${NM}" -u "${ARCHIVE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE symbols ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "Could not inspect library symbols: ${errors}")
endif()

# The shipped archive must not depend on an allocator. Test support may use one.
if(symbols MATCHES "(^|\n)[ \t]*(U[ \t]+)?_?(malloc|calloc|realloc|reallocf|free|aligned_alloc|posix_memalign|memalign|valloc|pvalloc|strdup|strndup|asprintf|vasprintf|Zn[wa]|Zd[al])([ \t]|\n|$)")
  message(FATAL_ERROR "Library references a heap allocator: ${CMAKE_MATCH_0}")
endif()
