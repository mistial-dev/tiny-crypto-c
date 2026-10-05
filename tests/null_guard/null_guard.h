/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Runtime support for the generated null-guard wrappers. A wrapper repeats a
 * public call with one NULL pointer or NULL span before the real call. The
 * snapshot restores writable arguments between those calls. Repeated calls
 * do not nest: a public call made from a callback during a repeated call goes
 * straight to the library.
 *
 * TC_NULL_GUARD_REPORT names a file that receives one "function parameter"
 * line for each case exercised by the process. The report is appended at
 * exit. */
#ifndef TC_NULL_GUARD_H_
#define TC_NULL_GUARD_H_

#include <stddef.h>

#define TC_NULL_GUARD_SAVES 16

typedef struct {
  struct {
    void* address;
    void* copy;
    size_t length;
  } entries[TC_NULL_GUARD_SAVES];
  size_t count;
} tc_null_guard_snapshot;

/* Returns 1 when the caller should run its NULL cases, and then the caller
 * must call tc_null_guard_leave. Returns 0 inside another wrapper's cases. */
int tc_null_guard_enter(void);
void tc_null_guard_leave(tc_null_guard_snapshot* snapshot);

void tc_null_guard_snapshot_init(tc_null_guard_snapshot* snapshot);
/* Copy length bytes at address. NULL or empty ranges are ignored, and so is
 * a range AddressSanitizer reports unaddressable. */
void tc_null_guard_save(tc_null_guard_snapshot* snapshot, const void* address, size_t length);
/* Write back every saved range that changed, in reverse order. */
void tc_null_guard_restore(const tc_null_guard_snapshot* snapshot);

/* Record that a case ran. */
void tc_null_guard_hit(const char* function, const char* parameter);
/* A call with a NULL argument returned OK. Print the case and abort. */
void tc_null_guard_accepted(const char* function, const char* parameter);

#endif
