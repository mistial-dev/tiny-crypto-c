/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "null_guard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__SANITIZE_ADDRESS__)
#define TC_NULL_GUARD_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TC_NULL_GUARD_ASAN 1
#endif
#endif
#ifdef TC_NULL_GUARD_ASAN
/* The ASan runtime of GCC and Clang provides this function. Some toolchains
 * ship it without the interface header. */
#if defined(__has_include)
#if __has_include(<sanitizer/asan_interface.h>)
#include <sanitizer/asan_interface.h>
#define TC_NULL_GUARD_ASAN_HEADER 1
#endif
#endif
#ifndef TC_NULL_GUARD_ASAN_HEADER
void* __asan_region_is_poisoned(void* begin, size_t size);
#endif
#endif

/* Distinct cases seen by this process, keyed by "function parameter". */
#define TC_NULL_GUARD_SLOTS 8192u

static char* seen[TC_NULL_GUARD_SLOTS];
static int active;
static int registered;

static void report(void)
{
  const char* path = getenv("TC_NULL_GUARD_REPORT");
  FILE* file;
  size_t i;
  if (!path || !*path)
    return;
  file = fopen(path, "a");
  if (!file)
    return;
  for (i = 0; i < TC_NULL_GUARD_SLOTS; ++i)
    if (seen[i])
      fprintf(file, "%s\n", seen[i]);
  fclose(file);
}

int tc_null_guard_enter(void)
{
  if (active)
    return 0;
  if (!registered) {
    registered = 1;
    atexit(report);
  }
  active = 1;
  return 1;
}

void tc_null_guard_leave(tc_null_guard_snapshot* snapshot)
{
  size_t i;
  for (i = 0; i < snapshot->count; ++i)
    free(snapshot->entries[i].copy);
  snapshot->count = 0;
  active = 0;
}

void tc_null_guard_snapshot_init(tc_null_guard_snapshot* snapshot)
{
  snapshot->count = 0;
}

void tc_null_guard_save(tc_null_guard_snapshot* snapshot, const void* address, size_t length)
{
  void* copy;
  if (!address || !length)
    return;
#ifdef TC_NULL_GUARD_ASAN
  /* Overlap tests pass pointers cast from smaller objects. Save only an
   * addressable range. */
  if (__asan_region_is_poisoned((void*)(size_t)address, length))
    return;
#endif
  if (snapshot->count == TC_NULL_GUARD_SAVES) {
    fprintf(stderr, "null guard: more than %d writable arguments\n", TC_NULL_GUARD_SAVES);
    abort();
  }
  copy = malloc(length);
  if (!copy) {
    fprintf(stderr, "null guard: cannot save %zu bytes\n", length);
    abort();
  }
  memcpy(copy, address, length);
  snapshot->entries[snapshot->count].address = (void*)(size_t)address;
  snapshot->entries[snapshot->count].copy = copy;
  snapshot->entries[snapshot->count].length = length;
  ++snapshot->count;
}

void tc_null_guard_restore(const tc_null_guard_snapshot* snapshot)
{
  size_t i = snapshot->count;
  /* Write only ranges that changed, so read-only objects passed as writable
   * arguments in negative tests are never stored to. */
  while (i--)
    if (memcmp(snapshot->entries[i].address, snapshot->entries[i].copy,
               snapshot->entries[i].length) != 0)
      memcpy(snapshot->entries[i].address, snapshot->entries[i].copy, snapshot->entries[i].length);
}

void tc_null_guard_hit(const char* function, const char* parameter)
{
  /* FNV-1a over "function parameter", then linear probing. */
  char key[256];
  unsigned long hash = 2166136261u;
  size_t i, slot;
  int length = snprintf(key, sizeof key, "%s %s", function, parameter);
  if (length < 0 || (size_t)length >= sizeof key)
    return;
  for (i = 0; key[i]; ++i)
    hash = (hash ^ (unsigned char)key[i]) * 16777619u;
  for (i = 0; i < TC_NULL_GUARD_SLOTS; ++i) {
    slot = (hash + i) % TC_NULL_GUARD_SLOTS;
    if (!seen[slot]) {
      seen[slot] = malloc((size_t)length + 1);
      if (seen[slot])
        memcpy(seen[slot], key, (size_t)length + 1);
      return;
    }
    if (!strcmp(seen[slot], key))
      return;
  }
}

void tc_null_guard_accepted(const char* function, const char* parameter)
{
  fprintf(stderr, "null guard: %s accepted NULL %s and returned OK\n", function, parameter);
  abort();
}
