/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_X509_PATH_WORKSPACE_INTERNAL_H_
#define TC_X509_PATH_WORKSPACE_INTERNAL_H_
#include <tiny_crypto/x509_path.h>

/* Reserve the twelve path workspace arrays from *offset onward, each starting
 * at a multiple of alignment, and advance *offset past the last one. A NULL
 * arena sizes the layout and leaves the array pointers NULL. Arrays with a
 * zero count stay NULL. out receives the pointers and capacities. Composite
 * arenas call this with their own alignment, which must be a multiple of
 * TC_X509_path_workspace_alignment. Returns 0 when the size overflows size_t,
 * with *offset and out unspecified. The caller checks the capacity counts. */
int tc_x509_path_workspace_layout(const TC_X509_path_capacity* capacity, uint8_t* arena,
                                  size_t alignment, size_t* offset, TC_X509_path_workspace* out);
#endif
