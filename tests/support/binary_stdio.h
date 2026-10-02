/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_BINARY_STDIO_H
#define TC_TEST_BINARY_STDIO_H

#include <stdio.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

/* Put stdin and stdout in binary mode for the Python-driven adapters. The
 * Windows C runtime opens both in text mode, which rewrites 0x0A as 0x0D 0x0A
 * on output and drops 0x0D and 0x1A on input. Returns 1 on success. */
static inline int tc_test_binary_stdio(void)
{
#if defined(_WIN32)
  return _setmode(_fileno(stdin), _O_BINARY) != -1 && _setmode(_fileno(stdout), _O_BINARY) != -1;
#else
  return 1;
#endif
}

#endif
