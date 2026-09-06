/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Portable file opening for host-side tests.
 */

#ifndef TC_TEST_IO_H
#define TC_TEST_IO_H

#include <stdio.h>

static inline FILE* tc_test_fopen(const char* path, const char* mode)
{
#if defined(_MSC_VER)
  FILE* file = NULL;
  return fopen_s(&file, path, mode) == 0 ? file : NULL;
#else
  return fopen(path, mode);
#endif
}

#endif /* TC_TEST_IO_H */
